"""iptables engine for the Firewall module — mirrors firewall_nft.py's shape
(pure render + host-specific validate/live-query/apply-script), dispatched to
by firewall.py based on a profile's `engine` column.

Integration point, confirmed live on the reference host: this host's `iptables`
is the iptables-nft compatibility layer (classic syntax, nf_tables kernel
backend), sharing the nf_tables subsystem with the nftables engine but through
a completely separate userspace grammar and in-kernel representation — the
two engines' artifacts never collide, but only one is ever meant to be
enforced at a time (see teardown_fragment() and firewall.py's apply()).

Real `INPUT`/`FORWARD`/`OUTPUT` base-chain policies are never touched (they
stay ACCEPT — host-owned, shared state this module doesn't own). Instead,
this engine's rules live in three dedicated custom chains —
`OPENSMART-INPUT`, `OPENSMART-FORWARD`, `OPENSMART-OUTPUT` — reached via
exactly one jump rule inserted into the real `INPUT` and `OUTPUT` chains, and
into Docker's own `DOCKER-USER` chain for `FORWARD` (Docker's documented,
permanent, safe-for-admins insertion point — confirmed present and empty on
the reference host; never inserted directly into the real `FORWARD` chain,
which would compete with Docker's own chain ordering there). A profile's
declared chain "policy" (accept/drop) is realised as an explicit terminal
rule at the end of our own custom chain, never a change to the real chain's
policy. The jump rules themselves are managed by the apply script (Phase 4),
never by the rendered iptables-restore text below — that text only ever
declares/populates our three custom chains, so it stays valid and
self-contained on its own (testable with `iptables-restore --test`) without
depending on INPUT/OUTPUT/DOCKER-USER's current state.

Deliberate v1 scope limits (see design notes B3):
IPv4 only (a rule with family='ip6' is rejected at render time — ip6tables is
a separate binary this engine doesn't drive); protocol='icmpv6' and the two
icmpv6 reject_with variants are rejected for the same reason. 'tcp+udp'
becomes two separate rules (iptables has no combined-protocol match). Rules
with multiple interfaces/addresses in one field (nft's set syntax) become
multiple rules with identical fields and the same target — the union of
"any of these" is expressed as multiple discrete rules, not a single
richer match, since plain iptables -s/-d/-i/-o take exactly one value each.
"""
import re

from pathlib import Path

from . import hostnet

STATE_EXT = "iptables"

CHAIN_MAP = {"input": "OPENSMART-INPUT", "forward": "OPENSMART-FORWARD", "output": "OPENSMART-OUTPUT"}
CUSTOM_CHAINS = tuple(CHAIN_MAP.values())

_STATE_UPPER = {"new": "NEW", "established": "ESTABLISHED", "related": "RELATED", "invalid": "INVALID", "untracked": "UNTRACKED"}
_REJECT_MAP = {
    "tcp reset": "tcp-reset",
    "icmp port-unreachable": "icmp-port-unreachable",
    "icmp admin-prohibited": "icmp-admin-prohibited",
}
_UNSUPPORTED_REJECT = {"icmpv6 port-unreachable", "icmpv6 admin-prohibited"}
_RATE_LIMIT_PARSE_RE = re.compile(r"^(\d+/(?:second|minute|hour|day))(?: burst (\d+) packets)?$")

# Apply support (APPLY_SCRIPT) lands in Phase 4 of the plan above. Until
# then, firewall.py's dispatch surfaces a clear "not yet supported" error
# for any attempt to apply an iptables-engine profile.
APPLY_SCRIPT = None


def _split(value: str) -> list[str]:
    return [p.strip() for p in (value or "").split(",") if p.strip()]


def _quote(token: str) -> str:
    # Our upstream field validators (firewall._validate_*) already forbid
    # quote characters in every field that reaches here, so this is a
    # display nicety (readable, restorable-by-hand output), not the primary
    # defense against a value breaking the line — that defense is the
    # validators rejecting the character in the first place.
    if any(c in token for c in (" ", '"', "'")):
        return '"' + token.replace('"', "") + '"'
    return token


def _port_tokens(field: str, value: str) -> list[str]:
    """field is 'sport' or 'dport'. A single value or single range uses the
    native --sport/--dport (accepts 'lo:hi'); a comma list (with or without
    ranges) uses the multiport extension, which iptables limits to 15
    ports/ranges per rule — already far more than this UI's service presets
    or a realistic hand-typed list would use."""
    parts = _split(value)
    if not parts:
        return []
    if len(parts) == 1 and "-" not in parts[0]:
        return [f"--{field}", parts[0]]
    if len(parts) == 1:
        lo, _, hi = parts[0].partition("-")
        return [f"--{field}", f"{lo}:{hi}"]
    converted = ",".join(p.replace("-", ":") for p in parts)
    plural = "sports" if field == "sport" else "dports"
    return ["-m", "multiport", f"--{plural}", converted]


def _match_tokens(rule: dict, proto: str | None, iif: str | None, oif: str | None, src: str | None, dst: str | None) -> list[str]:
    tokens: list[str] = []
    if iif:
        tokens += ["-i", iif]
    if oif:
        tokens += ["-o", oif]
    if proto:
        tokens += ["-p", proto]
    if src:
        if rule["src_negate"]:
            tokens.append("!")
        tokens += ["-s", src]
    if dst:
        if rule["dst_negate"]:
            tokens.append("!")
        tokens += ["-d", dst]
    if proto in ("tcp", "udp"):
        tokens += _port_tokens("sport", rule["sport"])
        tokens += _port_tokens("dport", rule["dport"])
    if proto == "icmp" and rule["icmp_type"]:
        tokens += ["--icmp-type", rule["icmp_type"]]
    if rule["ct_state"]:
        states = ",".join(_STATE_UPPER.get(s.strip().lower(), s.strip().upper()) for s in rule["ct_state"].split(",") if s.strip())
        tokens += ["-m", "conntrack", "--ctstate", states]
    if rule["rate_limit"]:
        match = _RATE_LIMIT_PARSE_RE.match(rule["rate_limit"])
        if match:
            tokens += ["-m", "limit", "--limit", match.group(1)]
            if match.group(2):
                tokens += ["--limit-burst", match.group(2)]
    tokens += ["-m", "comment", "--comment", f"osfw:{rule['id']}"]
    return tokens


def _target_tokens(rule: dict) -> list[str]:
    if rule["action"] == "reject":
        tokens = ["-j", "REJECT"]
        reject_with = _REJECT_MAP.get(rule.get("reject_with") or "")
        if reject_with:
            tokens += ["--reject-with", reject_with]
        return tokens
    return ["-j", rule["action"].upper()]


def _render_combo(rule: dict, chain_name: str, proto: str | None, iif: str | None, oif: str | None, src: str | None, dst: str | None) -> list[str]:
    match = _match_tokens(rule, proto, iif, oif, src, dst)
    lines = []
    if rule["log"]:
        # iptables' LOG is a non-terminating target (unlike nft's inline
        # `log` statement), so a logged rule renders as two lines sharing
        # the same match: LOG, then the real action. xt_LOG truncates
        # --log-prefix at 29 chars (a kernel constraint nft doesn't share,
        # which is why the shared log_prefix validator allows up to 60).
        prefix = f"osfw-{rule['id']}: {rule['log_prefix']}" if rule["log_prefix"] else f"osfw-{rule['id']}: "
        log_tokens = ["-A", chain_name, *match, "-j", "LOG", "--log-prefix", prefix[:29]]
        lines.append(" ".join(_quote(t) for t in log_tokens))
    action_tokens = ["-A", chain_name, *match, *_target_tokens(rule)]
    lines.append(" ".join(_quote(t) for t in action_tokens))
    return lines


def _render_rule(rule: dict, chain_name: str) -> list[str]:
    if rule["family"] == "ip6":
        raise ValueError(f"iptables engine does not support IPv6 rules yet (rule {rule['id']}, family=ip6).")
    protocol = rule["protocol"] or "any"
    if protocol == "icmpv6":
        raise ValueError(f"iptables engine does not support icmpv6 rules yet (rule {rule['id']}).")
    if (rule.get("reject_with") or "") in _UNSUPPORTED_REJECT:
        raise ValueError(f"iptables engine does not support reject_with='{rule['reject_with']}' (rule {rule['id']}).")

    protocols = ["tcp", "udp"] if protocol == "tcp+udp" else [protocol if protocol != "any" else None]
    iifs = _split(rule["iif"]) or [None]
    oifs = _split(rule["oif"]) or [None]
    srcs = _split(rule["src"]) or [None]
    dsts = _split(rule["dst"]) or [None]

    lines: list[str] = []
    for proto in protocols:
        for iif in iifs:
            for oif in oifs:
                for src in srcs:
                    for dst in dsts:
                        lines.extend(_render_combo(rule, chain_name, proto, iif, oif, src, dst))
    return lines


def render(rules: list[dict], policies: dict, custom_nft: str) -> str:
    """Pure — no side effects, no docker calls. rules -> iptables-restore
    text covering only the three OPENSMART-* custom chains (see module
    docstring for why INPUT/FORWARD/OUTPUT/DOCKER-USER themselves are never
    touched here). `custom_nft` is the nftables engine's raw-snippet escape
    hatch and has no iptables equivalent in v1 — silently unused here rather
    than mis-applied as if it were iptables syntax."""
    lines = ["*filter"]
    for chain_name in CUSTOM_CHAINS:
        lines.append(f":{chain_name} - [0:0]")
    for chain in ("input", "forward", "output"):
        chain_name = CHAIN_MAP[chain]
        for rule in [r for r in rules if r["chain"] == chain and r["enabled"]]:
            lines.extend(_render_rule(rule, chain_name))
        if policies.get(chain, "accept") == "drop":
            lines.append(f"-A {chain_name} -j DROP")
    lines.append("COMMIT")
    return "\n".join(lines) + "\n"


def validate(rendered: str, pending_path: Path) -> tuple[bool, str]:
    """`iptables-restore --test` against the rendered ruleset, inside a
    one-off host-networked container. `--noflush` matters even for a test
    run: without it, iptables-restore's default behavior is to flush every
    chain in the table first, which this dry-run must not depend on (or
    imply) touching Docker's own rules. Nothing is applied either way.

    `pending_path` must already contain `rendered` on disk (the caller
    writes it) — a real file, never a shell heredoc, for the same
    heredoc-injection reasons documented on firewall_nft.validate()."""
    return hostnet.run_host(
        'iptables-restore --test --noflush "$1"', [str(pending_path)],
        image="opensmart/netadmin", net_admin=True,
        mounts={str(pending_path.parent): str(pending_path.parent)},
    )


def live_query() -> tuple[bool, str]:
    return hostnet.run_host(
        f"iptables-save -t filter 2>/dev/null | grep -E '^(:({'|'.join(CUSTOM_CHAINS)})|-A ({'|'.join(CUSTOM_CHAINS)}))' || true",
        image="opensmart/netadmin", net_admin=True,
    )


def is_applied(raw_output: str) -> bool:
    return raw_output.strip() != ""


def teardown_fragment() -> str:
    """Bash, safe to embed inside another engine's apply script to
    defensively remove this engine's artifacts before that engine's own
    ruleset is applied. Idempotent; a no-op if nothing of ours is loaded.
    Defined ahead of this engine's own apply pipeline (Phase 4) so the
    nftables engine's "at most one engine enforced at a time" invariant is
    real starting now, not only once iptables can apply anything itself."""
    lines = [f'iptables -F "{chain}" 2>/dev/null || true' for chain in CUSTOM_CHAINS]
    lines += [
        'iptables -D INPUT -j OPENSMART-INPUT 2>/dev/null || true',
        'iptables -D OUTPUT -j OPENSMART-OUTPUT 2>/dev/null || true',
        'iptables -D DOCKER-USER -j OPENSMART-FORWARD 2>/dev/null || true',
    ]
    lines += [f'iptables -X "{chain}" 2>/dev/null || true' for chain in CUSTOM_CHAINS]
    return "\n".join(lines)

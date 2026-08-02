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


def _split(value: str) -> list[str]:
    return [p.strip() for p in (value or "").split(",") if p.strip()]


def _iface_token(value: str, rule_id) -> str:
    """nftables' wildcard character is '*' (fnmatch-style, anywhere in the
    name); iptables' is '+' (prefix-match, and ONLY as the final character —
    xtables treats a literal '*' as an ordinary, unmatchable character, so
    passing "br-*" through unchanged would silently match nothing). Translate
    a single trailing '*' to '+'; anything else involving '*' has no correct
    iptables translation, so it's rejected rather than silently mis-rendered
    — this includes the seeded safety rules' "docker0,br-*" value, which is
    exactly the kind of rule a silent mismatch would be most dangerous for."""
    if "*" in value[:-1] or (value.count("*") > 1):
        raise ValueError(f"iptables engine only supports a trailing '*' wildcard in interface names (rule {rule_id}): '{value}'.")
    if value.endswith("*"):
        return value[:-1] + "+"
    return value


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
    iifs = [_iface_token(v, rule["id"]) for v in _split(rule["iif"])] or [None]
    oifs = [_iface_token(v, rule["id"]) for v in _split(rule["oif"])] or [None]
    srcs = _split(rule["src"]) or [None]
    dsts = _split(rule["dst"]) or [None]

    # Expanding a multi-value field into a cross-product of discrete rules
    # (see module docstring) is only equivalent to nft's set match for a
    # POSITIVE match. Negated, it's the opposite: nft's "!= {A, B}" means
    # "not A AND not B" (De Morgan), but N separate "! A -> accept" / "! B ->
    # accept" rules mean "not A OR not B" — which every packet satisfies
    # (nothing is simultaneously equal to both A and B), silently accepting
    # everything regardless of source/destination. Reject rather than render
    # something that looks like a restriction but isn't one.
    if rule["src_negate"] and len(srcs) > 1:
        raise ValueError(f"iptables engine cannot render a negated multi-value src (rule {rule['id']}) — use a single value or split into separate rules.")
    if rule["dst_negate"] and len(dsts) > 1:
        raise ValueError(f"iptables engine cannot render a negated multi-value dst (rule {rule['id']}) — use a single value or split into separate rules.")

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
        'iptables-restore -w --test --noflush "$1"', [str(pending_path)],
        image="opensmart/netadmin", net_admin=True,
        mounts={str(pending_path.parent): str(pending_path.parent)},
    )


def live_query() -> tuple[bool, str]:
    """Captures both our custom chains' rule content AND the three jump
    lines that reach them — is_applied() needs both, since a chain that
    exists and has rules but isn't jumped to from anywhere filters nothing
    (see is_applied())."""
    chains = "|".join(CUSTOM_CHAINS)
    return hostnet.run_host(
        f"iptables-save -w -t filter 2>/dev/null | grep -E "
        f"'^(:({chains})|-A ({chains}) |-A INPUT -j OPENSMART-INPUT$|-A OUTPUT -j OPENSMART-OUTPUT$|-A DOCKER-USER -j OPENSMART-FORWARD$)' || true",
        image="opensmart/netadmin", net_admin=True,
    )


def is_applied(raw_output: str) -> bool:
    """True only if at least one real rule is loaded in one of our custom
    chains AND all three jump rules are in place — a chain with rules but no
    jump pointing at it (e.g. left behind by an orphaned watchdog racing a
    backend restart) filters nothing, and reporting it as "applied" would
    show a healthy status for a firewall that isn't in the packet path."""
    lines = raw_output.splitlines()
    has_content = any(any(line.startswith(f"-A {chain} ") for chain in CUSTOM_CHAINS) for line in lines)
    has_input_jump = "-A INPUT -j OPENSMART-INPUT" in lines
    has_output_jump = "-A OUTPUT -j OPENSMART-OUTPUT" in lines
    has_forward_jump = "-A DOCKER-USER -j OPENSMART-FORWARD" in lines
    return has_content and has_input_jump and has_output_jump and has_forward_jump


# Idempotent: creates the three custom chains if missing (swallows the
# "already exists" error rather than checking for it, since either outcome
# leaves the chain present, which is all that matters), always flushes them
# (iptables-restore --noflush does NOT do this itself — without it, a
# re-apply would silently APPEND to, not replace, whatever was already
# loaded), and ensures exactly one jump rule per chain via -C (check) before
# -I (insert) so re-running this never accumulates duplicate jumps. Used by
# both the apply watchdog (which additionally records which jumps IT added,
# for precise rollback) and the plain startup reapply (which doesn't need
# that, since it never rolls back — same relationship as
# firewall_nft.reapply() to its own apply script).
_ENSURE_CHAINS_AND_JUMPS = """
for chain in OPENSMART-INPUT OPENSMART-FORWARD OPENSMART-OUTPUT; do
  iptables -w -N "$chain" 2>/dev/null
  iptables -w -F "$chain"
done
if ! iptables -w -C INPUT -j OPENSMART-INPUT 2>/dev/null; then
  iptables -w -I INPUT 1 -j OPENSMART-INPUT || exit 1
fi
if ! iptables -w -C OUTPUT -j OPENSMART-OUTPUT 2>/dev/null; then
  iptables -w -I OUTPUT 1 -j OPENSMART-OUTPUT || exit 1
fi
if ! iptables -w -C DOCKER-USER -j OPENSMART-FORWARD 2>/dev/null; then
  iptables -w -I DOCKER-USER 1 -j OPENSMART-FORWARD || exit 1
fi
"""


def reapply(active_path: Path) -> tuple[bool, str]:
    """Startup hook: ensure the custom chains + jump rules exist, then load
    the last confirmed-good ruleset. No timer, no rollback path — same
    fail-open contract as firewall_nft.reapply(); if this fails, the caller
    just logs a warning (see firewall.reapply_active())."""
    script = _ENSURE_CHAINS_AND_JUMPS + '\niptables-restore -w --noflush "$1"\n'
    return hostnet.run_host(
        script, [str(active_path)],
        image="opensmart/netadmin", net_admin=True,
        mounts={str(active_path.parent): str(active_path.parent)},
    )


def teardown_fragment() -> str:
    """Bash, safe to embed inside another engine's apply script to remove
    this engine's artifacts once THAT engine's own ruleset is confirmed
    good — see the APPLY_SCRIPT comment below for why this only ever runs
    on confirm, never before or during the confirm window. Idempotent; a
    no-op if nothing of ours is loaded."""
    lines = [f'iptables -w -F "{chain}" 2>/dev/null || true' for chain in CUSTOM_CHAINS]
    lines += [
        'iptables -w -D INPUT -j OPENSMART-INPUT 2>/dev/null || true',
        'iptables -w -D OUTPUT -j OPENSMART-OUTPUT 2>/dev/null || true',
        'iptables -w -D DOCKER-USER -j OPENSMART-FORWARD 2>/dev/null || true',
    ]
    lines += [f'iptables -w -X "{chain}" 2>/dev/null || true' for chain in CUSTOM_CHAINS]
    return "\n".join(lines)


# Positional args: $1=token $2=confirm_seconds $3=state_dir — same contract
# as firewall_nft.APPLY_SCRIPT (see that module for why these are never
# string-interpolated: real argv elements only).
#
# __TEARDOWN_OTHER_ENGINES__ is replaced by firewall.apply() with the other
# registered engines' teardown_fragment() text — and, critically, it is
# spliced into the CONFIRM branch below, not run up front. Tearing down the
# other engine before this one's ruleset is even proven good would mean a
# cancel/timeout during the confirm window leaves NEITHER engine enforcing
# anything (this engine reverts to its own prior state, which for a
# fresh/never-applied engine is "nothing"; the other engine's ruleset is
# already gone and nothing restores it). Leaving both engines' artifacts
# loaded simultaneously during the confirm window is fail-safe, not
# fail-open: nf_tables evaluates every hook registered at a given priority,
# so a DROP verdict from either engine still drops the packet — the
# temporary overlap can only make the effective policy MORE restrictive,
# never less. The other engine is only actually torn down once this
# engine's ruleset is confirmed, i.e. once it's certain to be the new
# single source of truth.
#
# Every iptables/iptables-restore/iptables-save call takes `-w` (wait for
# the xtables lock) rather than failing immediately — Docker itself takes
# this lock on ordinary container start/stop/port-publish, which this very
# app triggers via provisioning, so a bare (non-`-w`) call can fail under
# completely routine concurrent activity, not just an attack.
#
# `revert()` is defined immediately after the rollback snapshot is
# captured, BEFORE the first mutation (the chain flush) — every failure
# path from that point on calls it before exiting, so a mid-setup failure
# (e.g. a jump insert failing after the chains were already flushed) still
# restores the prior rules instead of leaving the chains empty-and-live.
#
# Rollback here is more involved than nft's single atomic table-replace,
# because iptables has no equivalent "delete everything, redefine from
# scratch" idiom scoped to just our chains: the custom chains are flushed
# and reloaded from a snapshot instead of replaced wholesale, and the
# INPUT/OUTPUT/DOCKER-USER jump rules are only removed on rollback if THIS
# apply is the one that added them (recorded in $JUMPS_ADDED) — a jump
# already in place from a prior CONFIRMED apply must survive a cancel/
# timeout of a later one. A newly-created custom chain that had no rules
# before this apply is left in place, empty, on rollback rather than
# deleted (`-X`) — harmless litter cleaned up by any engine's next apply
# (see teardown_fragment()), not a functional or safety concern since
# nothing ever jumps to an empty chain.
APPLY_SCRIPT = """
set -uo pipefail
TOKEN="$1"; TIMEOUT="$2"; STATE_DIR="$3"
mkdir -p "$STATE_DIR/confirm" "$STATE_DIR/cancel" "$STATE_DIR/result"
PENDING="$STATE_DIR/pending-$TOKEN.iptables"
ROLLBACK="$STATE_DIR/rollback-$TOKEN.iptables"
JUMPS_ADDED="$STATE_DIR/rollback-$TOKEN.jumps"
if [ ! -f "$PENDING" ]; then
  echo "failed:pending ruleset file missing" > "$STATE_DIR/result/$TOKEN"
  exit 1
fi

{
  echo "*filter"
  echo ":OPENSMART-INPUT - [0:0]"
  echo ":OPENSMART-FORWARD - [0:0]"
  echo ":OPENSMART-OUTPUT - [0:0]"
  iptables-save -w -t filter 2>/dev/null | grep -E '^-A (OPENSMART-INPUT|OPENSMART-FORWARD|OPENSMART-OUTPUT) '
  echo "COMMIT"
} > "$ROLLBACK"
: > "$JUMPS_ADDED"

revert() {
  for chain in OPENSMART-INPUT OPENSMART-FORWARD OPENSMART-OUTPUT; do
    iptables -w -F "$chain" 2>/dev/null || true
  done
  iptables-restore -w --noflush "$ROLLBACK" 2>/dev/null || true
  if grep -qx "INPUT" "$JUMPS_ADDED" 2>/dev/null; then
    iptables -w -D INPUT -j OPENSMART-INPUT 2>/dev/null || true
  fi
  if grep -qx "OUTPUT" "$JUMPS_ADDED" 2>/dev/null; then
    iptables -w -D OUTPUT -j OPENSMART-OUTPUT 2>/dev/null || true
  fi
  if grep -qx "FORWARD" "$JUMPS_ADDED" 2>/dev/null; then
    iptables -w -D DOCKER-USER -j OPENSMART-FORWARD 2>/dev/null || true
  fi
}

for chain in OPENSMART-INPUT OPENSMART-FORWARD OPENSMART-OUTPUT; do
  iptables -w -N "$chain" 2>/dev/null
  if ! iptables -w -F "$chain"; then
    echo "failed:could not flush $chain" > "$STATE_DIR/result/$TOKEN"
    revert
    exit 1
  fi
done

if ! iptables -w -C INPUT -j OPENSMART-INPUT 2>/dev/null; then
  if ! iptables -w -I INPUT 1 -j OPENSMART-INPUT; then
    echo "failed:could not insert INPUT jump rule" > "$STATE_DIR/result/$TOKEN"
    revert
    exit 1
  fi
  echo "INPUT" >> "$JUMPS_ADDED"
fi
if ! iptables -w -C OUTPUT -j OPENSMART-OUTPUT 2>/dev/null; then
  if ! iptables -w -I OUTPUT 1 -j OPENSMART-OUTPUT; then
    echo "failed:could not insert OUTPUT jump rule" > "$STATE_DIR/result/$TOKEN"
    revert
    exit 1
  fi
  echo "OUTPUT" >> "$JUMPS_ADDED"
fi
if ! iptables -w -C DOCKER-USER -j OPENSMART-FORWARD 2>/dev/null; then
  if ! iptables -w -I DOCKER-USER 1 -j OPENSMART-FORWARD; then
    echo "failed:could not insert DOCKER-USER jump rule (is Docker running?)" > "$STATE_DIR/result/$TOKEN"
    revert
    exit 1
  fi
  echo "FORWARD" >> "$JUMPS_ADDED"
fi

if ! iptables-restore -w --noflush "$PENDING"; then
  echo "failed:iptables-restore apply failed" > "$STATE_DIR/result/$TOKEN"
  revert
  exit 1
fi

i=0
while [ "$i" -lt "$TIMEOUT" ]; do
  if [ -f "$STATE_DIR/confirm/$TOKEN" ]; then
    __TEARDOWN_OTHER_ENGINES__
    cp "$PENDING" "$STATE_DIR/active.iptables"
    echo "confirmed" > "$STATE_DIR/result/$TOKEN"
    exit 0
  fi
  if [ -f "$STATE_DIR/cancel/$TOKEN" ]; then
    revert
    echo "reverted" > "$STATE_DIR/result/$TOKEN"
    exit 0
  fi
  sleep 1
  i=$((i + 1))
done
revert
echo "reverted" > "$STATE_DIR/result/$TOKEN"
"""

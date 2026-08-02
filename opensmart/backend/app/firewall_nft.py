"""nftables engine for the Firewall module: pure rendering plus the
nft-specific host commands (validate/live-query/reapply/apply-script). All
DB access, profile/rule CRUD, and apply bookkeeping live in firewall.py,
which dispatches here based on a profile's `engine` column — this module
knows nothing about SQLite and receives already-fetched structured data.

Everything this engine generates lives in one nft table: `inet opensmart_fw`.
The renderer NEVER emits `flush ruleset` — the host runs Docker, which
programs its own tables via iptables-nft; a global flush would wipe Docker's
rules and break every container's networking, including the app's own
front-door proxy. Table replacement is always the atomic `table inet
opensmart_fw` / `delete table inet opensmart_fw` / `table inet opensmart_fw {
... }` idiom instead (see render()), and rollback (the apply script) uses the
exact same idiom around a captured snapshot of whatever was loaded before.
"""
import ipaddress
from pathlib import Path

from . import hostnet

TABLE_NAME = "opensmart_fw"
CHAINS = ("input", "forward", "output")

# The file extension firewall.py uses for this engine's pending/rollback/
# active state files (e.g. "active.nft") — keeps two engines' on-disk state
# from colliding in the shared state directory.
STATE_EXT = "nft"


def _quote(value: str) -> str:
    return '"' + value.replace('"', '') + '"'


def _iface_set(names: str, direction: str) -> str:
    parts = [n.strip() for n in names.split(",") if n.strip()]
    if not parts:
        return ""
    field = "iifname" if direction == "in" else "oifname"
    if len(parts) == 1:
        return f"{field} {_quote(parts[0])}"
    return f"{field} {{ {', '.join(_quote(p) for p in parts)} }}"


def _addr_family(value: str) -> str:
    """'ip' or 'ip6' depending on whether the first token looks like an IPv6
    literal/CIDR. Defaults to 'ip' (IPv4) for ranges like '10.0.0.1-10.0.0.9'
    where ipaddress can't parse the whole expression directly."""
    first = value.split(",")[0].split("-")[0].strip()
    try:
        return "ip6" if ipaddress.ip_network(first, strict=False).version == 6 else "ip"
    except ValueError:
        return "ip6" if ":" in first else "ip"


def _addr_expr(field: str, value: str, negate: bool) -> str:
    family = _addr_family(value)
    parts = [p.strip() for p in value.split(",") if p.strip()]
    expr = parts[0] if len(parts) == 1 else "{ " + ", ".join(parts) + " }"
    neg = "!= " if negate else ""
    return f"{family} {field} {neg}{expr}"


def _port_expr(protocol: str, field: str, value: str) -> str:
    parts = [p.strip() for p in value.split(",") if p.strip()]
    expr = parts[0] if len(parts) == 1 else "{ " + ", ".join(parts) + " }"
    # "tcp+udp" needs the protocol-agnostic transport-header field, since a
    # single nft statement can't match "tcp dport X or udp dport X" otherwise.
    prefix = "th" if protocol == "tcp+udp" else protocol
    return f"{prefix} {field} {expr}"


def _render_rule(rule: dict) -> str:
    if not rule["enabled"]:
        return ""
    tokens: list[str] = []
    if rule["iif"]:
        tokens.append(_iface_set(rule["iif"], "in"))
    if rule["oif"]:
        tokens.append(_iface_set(rule["oif"], "out"))
    protocol = rule["protocol"] or "any"
    has_port_match = protocol in ("tcp", "udp") and (rule["sport"] or rule["dport"])
    if protocol == "tcp+udp":
        # "th dport/sport" below matches either protocol's port field, but
        # doesn't by itself restrict to tcp/udp packets — needed regardless
        # of whether a port match follows.
        tokens.append("meta l4proto { tcp, udp }")
    elif protocol not in ("any",) and not has_port_match:
        # A dport/sport match on tcp/udp already implies the protocol (nft's
        # `tcp`/`udp` keyword carries its own dependency) — an explicit
        # `meta l4proto` alongside it would be redundant, not incorrect.
        tokens.append(f"meta l4proto {protocol}")
    if rule["src"]:
        tokens.append(_addr_expr("saddr", rule["src"], bool(rule["src_negate"])))
    if rule["dst"]:
        tokens.append(_addr_expr("daddr", rule["dst"], bool(rule["dst_negate"])))
    if rule["sport"] and protocol in ("tcp", "udp", "tcp+udp"):
        tokens.append(_port_expr(protocol, "sport", rule["sport"]))
    if rule["dport"] and protocol in ("tcp", "udp", "tcp+udp"):
        tokens.append(_port_expr(protocol, "dport", rule["dport"]))
    if rule["ct_state"]:
        states = ",".join(p.strip() for p in rule["ct_state"].split(",") if p.strip())
        tokens.append(f"ct state {states}")
    if rule["icmp_type"] and protocol in ("icmp", "icmpv6"):
        tokens.append(f"{protocol} type {rule['icmp_type']}")
    tokens.append("counter")
    if rule["log"]:
        # Always tag with "osfw" regardless of any custom prefix the admin
        # set — read_logs() greps kernel messages for exactly this tag, so a
        # custom prefix without it would make that rule's log lines
        # invisible to the Advanced tab's log viewer.
        prefix = f"osfw-{rule['id']}: {rule['log_prefix']}" if rule["log_prefix"] else f"osfw-{rule['id']}: "
        tokens.append(f'log prefix "{prefix}"')
    if rule["rate_limit"]:
        tokens.append(f"limit rate {rule['rate_limit']}")
    if rule["action"] == "reject":
        tokens.append(f"reject with {rule['reject_with']}" if rule["reject_with"] else "reject")
    else:
        tokens.append(rule["action"])
    tokens.append(f'comment "osfw:{rule["id"]}"')
    return "    " + " ".join(t for t in tokens if t) + ";"


def render(rules: list[dict], policies: dict, custom_nft: str) -> str:
    """Pure — no side effects, no docker calls. rules -> nft text. Never
    emits `flush ruleset`; always the atomic per-table replace idiom so
    Docker's own iptables-nft tables are left untouched."""
    lines = [
        f"table inet {TABLE_NAME}",
        f"delete table inet {TABLE_NAME}",
        f"table inet {TABLE_NAME} {{",
    ]
    for chain in CHAINS:
        policy = policies.get(chain, "accept")
        lines.append(f"  chain {chain} {{")
        lines.append(f"    type filter hook {chain} priority filter; policy {policy};")
        for rule in [r for r in rules if r["chain"] == chain]:
            rendered = _render_rule(rule)
            if rendered:
                lines.append(rendered)
        lines.append("  }")
    lines.append("}")
    if custom_nft.strip():
        lines.append(custom_nft)
    return "\n".join(lines) + "\n"


def validate(rendered: str, pending_path: Path) -> tuple[bool, str]:
    """`nft -c` (check mode) against the rendered ruleset, inside a one-off
    host-networked container so interface names and any already-loaded
    tables resolve exactly as they will at apply time. Nothing is applied.

    `pending_path` must already contain `rendered` on disk (the caller writes
    it) — a real file, not a shell heredoc, since rule fields like custom_nft
    or a crafted log_prefix could otherwise contain a line matching a heredoc
    delimiter and break out into arbitrary shell commands inside a
    NET_ADMIN, host-networked container. Field-level validation upstream
    also blocks the individual characters that would make this possible;
    this is defense in depth on top of that, not instead of it."""
    return hostnet.run_host(
        'nft -c -f "$1"', [str(pending_path)],
        image="opensmart/netadmin", net_admin=True,
        mounts={str(pending_path.parent): str(pending_path.parent)},
    )


def live_query() -> tuple[bool, str]:
    return hostnet.run_host(
        f"nft -j list table inet {TABLE_NAME} 2>/dev/null || echo '{{}}'",
        image="opensmart/netadmin", net_admin=True,
    )


def is_applied(raw_output: str) -> bool:
    return raw_output.strip() not in ("", "{}")


def reapply(active_path: Path) -> tuple[bool, str]:
    return hostnet.run_host(
        'nft -f "$1"', [str(active_path)],
        image="opensmart/netadmin", net_admin=True,
        mounts={str(active_path.parent): str(active_path.parent)},
    )


def teardown_fragment() -> str:
    """Bash, safe to embed inside another engine's apply script to
    defensively remove this engine's artifacts before that engine's own
    ruleset is applied — enforces "at most one engine loaded at a time"
    even if DB/kernel state ever drift apart. Idempotent; a no-op if nothing
    of ours is loaded."""
    return f"nft delete table inet {TABLE_NAME} 2>/dev/null || true"


# Positional args: $1=token $2=confirm_seconds $3=state_dir. Never
# string-interpolated — the token/timeout/dir are validated ints/paths
# passed as real argv elements (see hostnet.py and firewall.apply()).
#
# __TEARDOWN_OTHER_ENGINES__ is replaced by firewall.apply() with the other
# registered engines' teardown_fragment() text — spliced into the CONFIRM
# branch below, not run up front. Tearing down the other engine before this
# ruleset is proven good would mean a cancel/timeout leaves NEITHER engine
# enforcing anything (this engine's own rollback only restores ITS prior
# state). Both engines' artifacts loaded simultaneously during the confirm
# window is fail-safe, not fail-open — nf_tables evaluates every hook
# registered at a given priority, so a DROP verdict from either engine still
# drops the packet; the overlap can only make the effective policy more
# restrictive. The other engine is only torn down once this one is
# confirmed as the new single source of truth.
APPLY_SCRIPT = """
set -uo pipefail
TOKEN="$1"; TIMEOUT="$2"; STATE_DIR="$3"
mkdir -p "$STATE_DIR/confirm" "$STATE_DIR/cancel" "$STATE_DIR/result"
PENDING="$STATE_DIR/pending-$TOKEN.nft"
ROLLBACK="$STATE_DIR/rollback-$TOKEN.nft"
if [ ! -f "$PENDING" ]; then
  echo "failed:pending ruleset file missing" > "$STATE_DIR/result/$TOKEN"
  exit 1
fi
CURRENT="$(nft list table inet opensmart_fw 2>/dev/null)"
if [ -n "$CURRENT" ]; then
  { echo "table inet opensmart_fw"; echo "delete table inet opensmart_fw"; echo "$CURRENT"; } > "$ROLLBACK"
else
  echo "delete table inet opensmart_fw" > "$ROLLBACK"
fi
if ! nft -f "$PENDING"; then
  echo "failed:nft -f apply failed" > "$STATE_DIR/result/$TOKEN"
  exit 1
fi
i=0
while [ "$i" -lt "$TIMEOUT" ]; do
  if [ -f "$STATE_DIR/confirm/$TOKEN" ]; then
    __TEARDOWN_OTHER_ENGINES__
    cp "$PENDING" "$STATE_DIR/active.nft"
    echo "confirmed" > "$STATE_DIR/result/$TOKEN"
    exit 0
  fi
  if [ -f "$STATE_DIR/cancel/$TOKEN" ]; then
    nft -f "$ROLLBACK"
    echo "reverted" > "$STATE_DIR/result/$TOKEN"
    exit 0
  fi
  sleep 1
  i=$((i + 1))
done
nft -f "$ROLLBACK"
echo "reverted" > "$STATE_DIR/result/$TOKEN"
"""

"""nftables Firewall module: structured rules stored in SQLite, rendered into
an nft ruleset and (Phase 4) applied to the host via a commit-confirm
watchdog — the same safety pattern as network_config.py's live MTU changes.
This file (Phase 3) covers the data model, the pure renderer, syntax
validation, static lockout analysis, and read-only live state; apply/confirm/
cancel land in Phase 4.

Everything this module generates lives in one nft table: `inet opensmart_fw`.
The renderer NEVER emits `flush ruleset` — the host runs Docker, which
programs its own tables via iptables-nft; a global flush would wipe Docker's
rules and break every container's networking, including the app's own
front-door proxy. Table replacement is always the atomic `table inet
opensmart_fw` / `delete table inet opensmart_fw` / `table inet opensmart_fw {
... }` idiom instead (see render_profile()).
"""
import ipaddress
import json
import logging
import sqlite3

from . import hostnet
from .database import get_db, now_iso

logger = logging.getLogger(__name__)

TABLE_NAME = "opensmart_fw"
CHAINS = ("input", "forward", "output")
_VALID_ACTIONS = {"accept", "drop", "reject"}
_VALID_FAMILIES = {"inet", "ip", "ip6"}
_MANAGEMENT_PORTS = {"22", "80", "443", "8000"}

_RULE_FIELDS = {
    "chain", "position", "enabled", "action", "reject_with", "family", "protocol",
    "iif", "oif", "src", "src_negate", "dst", "dst_negate", "sport", "dport",
    "ct_state", "icmp_type", "log", "log_prefix", "rate_limit", "description",
}
_PROFILE_FIELDS = {"name", "description", "policies", "custom_nft"}


class FirewallError(Exception):
    """User-facing firewall configuration failure."""


# ── Profile CRUD ────────────────────────────────────────────────────────────

def list_profiles() -> list[dict]:
    with get_db() as db:
        rows = db.execute("SELECT * FROM firewall_profiles ORDER BY name").fetchall()
    return [dict(row) for row in rows]


def get_profile(profile_id: int) -> dict:
    with get_db() as db:
        row = db.execute("SELECT * FROM firewall_profiles WHERE id = ?", (profile_id,)).fetchone()
    if row is None:
        raise FirewallError(f"Profile {profile_id} not found.")
    return dict(row)


def create_profile(name: str, description: str = "") -> dict:
    now = now_iso()
    with get_db() as db:
        try:
            cur = db.execute(
                "INSERT INTO firewall_profiles (name, description, active, created_at, updated_at) VALUES (?, ?, 0, ?, ?)",
                (name, description, now, now),
            )
            db.commit()
        except sqlite3.IntegrityError as error:
            raise FirewallError(f"A profile named '{name}' already exists.") from error
        profile_id = cur.lastrowid
    return get_profile(profile_id)


def update_profile(profile_id: int, fields: dict) -> dict:
    unknown = set(fields) - _PROFILE_FIELDS
    if unknown:
        raise FirewallError(f"Unknown field(s): {', '.join(sorted(unknown))}")
    get_profile(profile_id)  # 404 if missing
    if not fields:
        return get_profile(profile_id)
    columns = [f"{key} = ?" for key in fields]
    params = list(fields.values())
    columns.append("updated_at = ?")
    params.append(now_iso())
    params.append(profile_id)
    with get_db() as db:
        try:
            db.execute(f"UPDATE firewall_profiles SET {', '.join(columns)} WHERE id = ?", params)
            db.commit()
        except sqlite3.IntegrityError as error:
            raise FirewallError("A profile with that name already exists.") from error
    return get_profile(profile_id)


def delete_profile(profile_id: int) -> None:
    profile = get_profile(profile_id)
    if profile["active"]:
        raise FirewallError("Cannot delete the active profile — activate a different one first.")
    with get_db() as db:
        db.execute("DELETE FROM firewall_profiles WHERE id = ?", (profile_id,))
        db.commit()


def clone_profile(profile_id: int, new_name: str) -> dict:
    source = get_profile(profile_id)
    new_profile = create_profile(new_name, f"Cloned from {source['name']}")
    with get_db() as db:
        rules = db.execute("SELECT * FROM firewall_rules WHERE profile_id = ? ORDER BY chain, position", (profile_id,)).fetchall()
        now = now_iso()
        for rule in rules:
            data = dict(rule)
            columns = [key for key in data if key not in ("id", "profile_id", "created_at", "updated_at")]
            db.execute(
                f"INSERT INTO firewall_rules (profile_id, {', '.join(columns)}, created_at, updated_at) "
                f"VALUES (?, {', '.join('?' for _ in columns)}, ?, ?)",
                [new_profile["id"], *[data[c] for c in columns], now, now],
            )
        db.execute("UPDATE firewall_profiles SET policies = ?, custom_nft = ?, updated_at = ? WHERE id = ?", (source["policies"], source["custom_nft"], now, new_profile["id"]))
        db.commit()
    return get_profile(new_profile["id"])


def active_profile() -> dict | None:
    with get_db() as db:
        row = db.execute("SELECT * FROM firewall_profiles WHERE active = 1 LIMIT 1").fetchone()
    return dict(row) if row else None


# ── Rule CRUD ────────────────────────────────────────────────────────────────

def list_rules(profile_id: int) -> list[dict]:
    get_profile(profile_id)
    with get_db() as db:
        rows = db.execute("SELECT * FROM firewall_rules WHERE profile_id = ? ORDER BY chain, position", (profile_id,)).fetchall()
    return [dict(row) for row in rows]


def _next_position(db: sqlite3.Connection, profile_id: int, chain: str) -> int:
    row = db.execute("SELECT MAX(position) AS max_pos FROM firewall_rules WHERE profile_id = ? AND chain = ?", (profile_id, chain)).fetchone()
    return (row["max_pos"] or 0) + 1


def _validate_rule_fields(fields: dict) -> None:
    if "action" in fields and fields["action"] not in _VALID_ACTIONS:
        raise FirewallError(f"action must be one of {', '.join(sorted(_VALID_ACTIONS))}.")
    if "family" in fields and fields["family"] not in _VALID_FAMILIES:
        raise FirewallError(f"family must be one of {', '.join(sorted(_VALID_FAMILIES))}.")


def create_rule(profile_id: int, fields: dict) -> dict:
    get_profile(profile_id)
    if "chain" not in fields or fields["chain"] not in CHAINS:
        raise FirewallError(f"chain must be one of {', '.join(CHAINS)}.")
    unknown = set(fields) - _RULE_FIELDS
    if unknown:
        raise FirewallError(f"Unknown field(s): {', '.join(sorted(unknown))}")
    _validate_rule_fields(fields)
    now = now_iso()
    with get_db() as db:
        position = fields.get("position") or _next_position(db, profile_id, fields["chain"])
        columns = ["profile_id", "chain", "position"] + [k for k in fields if k not in ("chain", "position")]
        values = [profile_id, fields["chain"], position] + [fields[k] for k in fields if k not in ("chain", "position")]
        try:
            cur = db.execute(
                f"INSERT INTO firewall_rules ({', '.join(columns)}, created_at, updated_at) VALUES ({', '.join('?' for _ in columns)}, ?, ?)",
                [*values, now, now],
            )
            db.commit()
        except sqlite3.IntegrityError as error:
            raise FirewallError(f"Invalid rule field value: {error}") from error
        rule_id = cur.lastrowid
    return get_rule(rule_id)


def get_rule(rule_id: int) -> dict:
    with get_db() as db:
        row = db.execute("SELECT * FROM firewall_rules WHERE id = ?", (rule_id,)).fetchone()
    if row is None:
        raise FirewallError(f"Rule {rule_id} not found.")
    return dict(row)


def update_rule(rule_id: int, fields: dict) -> dict:
    rule = get_rule(rule_id)
    if rule["system_rule"] and set(fields) - {"enabled"}:
        raise FirewallError("System safety rules can only be enabled/disabled, not edited — clone the profile to customize them.")
    unknown = set(fields) - _RULE_FIELDS
    if unknown:
        raise FirewallError(f"Unknown field(s): {', '.join(sorted(unknown))}")
    _validate_rule_fields(fields)
    if not fields:
        return rule
    columns = [f"{key} = ?" for key in fields]
    params = list(fields.values())
    columns.append("updated_at = ?")
    params.append(now_iso())
    params.append(rule_id)
    with get_db() as db:
        try:
            db.execute(f"UPDATE firewall_rules SET {', '.join(columns)} WHERE id = ?", params)
            db.commit()
        except sqlite3.IntegrityError as error:
            raise FirewallError(f"Invalid rule field value: {error}") from error
    return get_rule(rule_id)


def delete_rule(rule_id: int) -> None:
    rule = get_rule(rule_id)
    if rule["system_rule"]:
        raise FirewallError("System safety rules cannot be deleted — disable them instead, or clone the profile to customize.")
    with get_db() as db:
        db.execute("DELETE FROM firewall_rules WHERE id = ?", (rule_id,))
        db.commit()


def move_rule(rule_id: int, direction: str) -> dict:
    if direction not in ("up", "down"):
        raise FirewallError("direction must be 'up' or 'down'.")
    rule = get_rule(rule_id)
    with get_db() as db:
        neighbor = db.execute(
            "SELECT id, position FROM firewall_rules WHERE profile_id = ? AND chain = ? AND position "
            + (" < ? ORDER BY position DESC LIMIT 1" if direction == "up" else " > ? ORDER BY position ASC LIMIT 1"),
            (rule["profile_id"], rule["chain"], rule["position"]),
        ).fetchone()
        if neighbor is None:
            return rule
        db.execute("UPDATE firewall_rules SET position = ? WHERE id = ?", (neighbor["position"], rule_id))
        db.execute("UPDATE firewall_rules SET position = ? WHERE id = ?", (rule["position"], neighbor["id"]))
        db.commit()
    return get_rule(rule_id)


# ── Renderer ─────────────────────────────────────────────────────────────────

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
        prefix = rule["log_prefix"] or f"osfw-{rule['id']}: "
        tokens.append(f'log prefix "{prefix}"')
    if rule["rate_limit"]:
        tokens.append(f"limit rate {rule['rate_limit']}")
    if rule["action"] == "reject":
        tokens.append(f"reject with {rule['reject_with']}" if rule["reject_with"] else "reject")
    else:
        tokens.append(rule["action"])
    tokens.append(f'comment "osfw:{rule["id"]}"')
    return "    " + " ".join(t for t in tokens if t) + ";"


def render_profile(profile_id: int) -> str:
    """Pure — no side effects, no docker calls. rules -> nft text. Never
    emits `flush ruleset`; always the atomic per-table replace idiom so
    Docker's own iptables-nft tables are left untouched."""
    profile = get_profile(profile_id)
    rules = list_rules(profile_id)
    policies = _json_policies(profile["policies"])

    lines = [
        f"table inet {TABLE_NAME}",
        f"delete table inet {TABLE_NAME}",
        f"table inet {TABLE_NAME} {{",
    ]
    for chain in CHAINS:
        hook = chain  # input/forward/output hooks share their chain name
        policy = policies.get(chain, "accept")
        lines.append(f"  chain {chain} {{")
        lines.append(f"    type filter hook {hook} priority filter; policy {policy};")
        for rule in [r for r in rules if r["chain"] == chain]:
            rendered = _render_rule(rule)
            if rendered:
                lines.append(rendered)
        lines.append("  }")
    lines.append("}")
    if profile["custom_nft"].strip():
        lines.append(profile["custom_nft"])
    return "\n".join(lines) + "\n"


def _json_policies(raw: str) -> dict:
    try:
        data = json.loads(raw)
        return {chain: data.get(chain, "accept") for chain in CHAINS}
    except (ValueError, TypeError):
        return dict.fromkeys(CHAINS, "accept")


# ── Validation (Layer 1: syntax) ─────────────────────────────────────────────

def validate(profile_id: int) -> tuple[bool, str]:
    """`nft -c` (check mode) against the rendered ruleset, inside a one-off
    host-networked container so interface names and any already-loaded
    tables resolve exactly as they will at apply time. Nothing is applied."""
    rendered = render_profile(profile_id)
    script = 'cat > /tmp/pending.nft << "OPENSMART_EOF"\n' + rendered + "\nOPENSMART_EOF\nnft -c -f /tmp/pending.nft"
    ok, output = hostnet.run_host(script, image="opensmart/netadmin", net_admin=True)
    return ok, output


# ── Static lockout analysis (Layer 2) ───────────────────────────────────────

def analyze(profile_id: int, client_ip: str = "") -> list[str]:
    """Inspect the STRUCTURED rules (not the rendered text) for changes that
    could sever the admin's own access. Warnings, not hard blocks — the
    caller (routes/firewall.py) decides whether to require confirmation."""
    profile = get_profile(profile_id)
    policies = _json_policies(profile["policies"])
    rules = [r for r in list_rules(profile_id) if r["enabled"]]
    warnings: list[str] = []

    def _has_established_accept(chain: str) -> bool:
        return any(r["chain"] == chain and r["action"] == "accept" and "established" in (r["ct_state"] or "") for r in rules)

    def _has_management_accept(chain: str) -> bool:
        for r in rules:
            if r["chain"] != chain or r["action"] != "accept" or not r["dport"]:
                continue
            if r["protocol"] not in ("tcp", "tcp+udp", "any"):
                continue
            ports = {p.strip() for p in r["dport"].split(",")}
            if not (ports & _MANAGEMENT_PORTS):
                continue
            if client_ip and r["src"] and not _ip_in_expr(client_ip, r["src"], bool(r["src_negate"])):
                continue
            return True
        return False

    for chain in ("input", "forward"):
        if policies.get(chain) == "drop" and not _has_established_accept(chain):
            warnings.append(f"'{chain}' policy is drop with no established/related accept rule ranked before it — return traffic for existing connections may be dropped.")
    if policies.get("input") == "drop" and not _has_management_accept("input"):
        warnings.append("'input' policy is drop with no accept rule for management/SSH ports — this may lock out web console and SSH access.")
    if policies.get("forward") == "drop" and not any(r["chain"] == "forward" and r["action"] == "accept" and ("docker0" in r["iif"] or "docker0" in r["oif"] or "br-" in r["iif"] or "br-" in r["oif"]) for r in rules):
        warnings.append("'forward' policy is drop with no Docker bridge accept rule — container-to-network traffic may break.")
    unknown_ifaces = {r["iif"] for r in rules if r["iif"]} | {r["oif"] for r in rules if r["oif"]}
    if unknown_ifaces:
        with get_db() as db:
            known = {row["name"] for row in db.execute("SELECT name FROM network_interfaces").fetchall()}
        for combo in unknown_ifaces:
            for name in combo.split(","):
                name = name.strip()
                if name and "*" not in name and name not in known and name not in ("docker0", "lo"):
                    warnings.append(f"Rule references interface '{name}', which is not in the interface registry — check it isn't a typo or a removed NIC.")
    return warnings


def _ip_in_expr(client_ip: str, expr: str, negate: bool) -> bool:
    try:
        ip = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    matched = False
    for part in expr.split(","):
        part = part.strip()
        try:
            if "-" in part:
                continue  # ranges not evaluated here — best-effort analysis only
            if ip in ipaddress.ip_network(part, strict=False):
                matched = True
                break
        except ValueError:
            continue
    return matched != negate


# ── Live state (read-only) ──────────────────────────────────────────────────

def live_state() -> dict:
    """Read-only: does the opensmart_fw table exist on the host right now,
    and if so, what does it look like? Phase 3 has no apply path yet, so this
    will normally report not_applied until Phase 4 lands."""
    ok, output = hostnet.run_host(
        f"nft -j list table inet {TABLE_NAME} 2>/dev/null || echo '{{}}'",
        image="opensmart/netadmin", net_admin=True,
    )
    if not ok:
        return {"applied": False, "detail": output}
    return {"applied": output.strip() not in ("", "{}"), "raw": output}

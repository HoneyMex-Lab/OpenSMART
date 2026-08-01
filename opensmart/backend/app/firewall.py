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
import re
import sqlite3

from . import hostnet
from .provisioning import CONTAINERS_ROOT
from .database import get_db, now_iso

logger = logging.getLogger(__name__)

TABLE_NAME = "opensmart_fw"
CHAINS = ("input", "forward", "output")
_VALID_ACTIONS = {"accept", "drop", "reject"}
_VALID_FAMILIES = {"inet", "ip", "ip6"}
_VALID_PROTOCOLS = {"any", "tcp", "udp", "tcp+udp", "icmp", "icmpv6", "esp", "gre", "ah"}
_VALID_CT_STATES = {"new", "established", "related", "invalid", "untracked"}
_VALID_REJECT_WITH = {
    "", "tcp reset", "icmp port-unreachable", "icmp admin-prohibited",
    "icmpv6 port-unreachable", "icmpv6 admin-prohibited",
}
_MANAGEMENT_PORTS = {"22", "80", "443", "8000"}

_STATE_DIR = CONTAINERS_ROOT / "firewall" / "volumes" / "state"

# All of these gate what ends up as literal text inside a generated .nft
# file that gets fed to `nft -c`/`nft -f` — nftables config is itself a
# scripting language (`;` separates statements, `#` comments, `{`/`}` open
# and close blocks), so every field embedded in render_profile() must be
# validated against a narrow grammar here, not just length-bounded at the
# API layer. custom_nft is the sole deliberate, documented raw escape hatch.
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.*-]{1,15}$")
_PORT_RE = re.compile(r"^\d{1,5}(-\d{1,5})?$")
_ICMP_TYPE_RE = re.compile(r"^\d{1,3}$")
_RATE_LIMIT_RE = re.compile(r"^\d+/(second|minute|hour|day)( burst \d+ packets)?$")
_LOG_PREFIX_RE = re.compile(r"^[A-Za-z0-9 _:.-]{0,60}$")

_RULE_FIELDS = {
    "chain", "position", "enabled", "action", "reject_with", "family", "protocol",
    "iif", "oif", "src", "src_negate", "dst", "dst_negate", "sport", "dport",
    "ct_state", "icmp_type", "log", "log_prefix", "rate_limit", "description",
}
_PROFILE_FIELDS = {"name", "description", "policies", "custom_nft"}


class FirewallError(Exception):
    """User-facing firewall configuration failure."""


def _validate_iface_list(value: str, field: str) -> None:
    for part in value.split(","):
        part = part.strip()
        if part and not _IFACE_RE.match(part):
            raise FirewallError(f"{field} contains an invalid interface name: '{part}'.")


def _validate_addr_list(value: str, field: str) -> None:
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ipaddress.ip_network(part, strict=False)
            continue
        except ValueError:
            pass
        if "-" in part:
            start, _, end = part.partition("-")
            try:
                ipaddress.ip_address(start.strip())
                ipaddress.ip_address(end.strip())
                continue
            except ValueError:
                pass
        raise FirewallError(f"{field} contains an invalid address/CIDR/range: '{part}'.")


def _validate_port_list(value: str, field: str) -> None:
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if not _PORT_RE.match(part):
            raise FirewallError(f"{field} contains an invalid port/range: '{part}'.")
        bounds = [int(x) for x in part.split("-")]
        if any(b > 65535 for b in bounds):
            raise FirewallError(f"{field} port out of range: '{part}'.")
        if len(bounds) == 2 and bounds[0] > bounds[1]:
            raise FirewallError(f"{field} range must be low-high: '{part}'.")


def _validate_rule_fields(effective: dict) -> None:
    """Validates the EFFECTIVE field set (existing rule merged with the
    patch, or the full create payload) — cross-field checks like "ports
    require a tcp/udp protocol" need the other fields even when only one
    changed."""
    if effective.get("action") not in (None, "") and effective["action"] not in _VALID_ACTIONS:
        raise FirewallError(f"action must be one of {', '.join(sorted(_VALID_ACTIONS))}.")
    if effective.get("family") not in (None, "") and effective["family"] not in _VALID_FAMILIES:
        raise FirewallError(f"family must be one of {', '.join(sorted(_VALID_FAMILIES))}.")
    protocol = effective.get("protocol") or "any"
    if protocol not in _VALID_PROTOCOLS:
        raise FirewallError(f"protocol must be one of {', '.join(sorted(_VALID_PROTOCOLS))}.")
    if effective.get("reject_with", "") not in _VALID_REJECT_WITH:
        raise FirewallError(f"reject_with must be one of {sorted(_VALID_REJECT_WITH)}.")
    if effective.get("ct_state"):
        for state in effective["ct_state"].split(","):
            if state.strip() not in _VALID_CT_STATES:
                raise FirewallError(f"ct_state must be a comma-separated list from {', '.join(sorted(_VALID_CT_STATES))}.")
    if effective.get("icmp_type") and not _ICMP_TYPE_RE.match(effective["icmp_type"]):
        raise FirewallError("icmp_type must be a plain number.")
    if effective.get("rate_limit") and not _RATE_LIMIT_RE.match(effective["rate_limit"]):
        raise FirewallError("rate_limit must look like '10/second' or '10/second burst 20 packets'.")
    if effective.get("log_prefix") and not _LOG_PREFIX_RE.match(effective["log_prefix"]):
        raise FirewallError("log_prefix may only contain letters, digits, spaces, and _:.- characters.")
    if effective.get("iif"):
        _validate_iface_list(effective["iif"], "iif")
    if effective.get("oif"):
        _validate_iface_list(effective["oif"], "oif")
    if effective.get("src"):
        _validate_addr_list(effective["src"], "src")
    if effective.get("dst"):
        _validate_addr_list(effective["dst"], "dst")
    if effective.get("sport"):
        _validate_port_list(effective["sport"], "sport")
    if effective.get("dport"):
        _validate_port_list(effective["dport"], "dport")
    # Silently dropping an unrenderable port/icmp-type match at render time
    # (protocol doesn't support it) would show the admin a constraint the
    # kernel never actually applied — reject instead of dropping.
    if (effective.get("sport") or effective.get("dport")) and protocol not in ("tcp", "udp", "tcp+udp"):
        raise FirewallError("sport/dport require protocol to be tcp, udp, or tcp+udp.")
    if effective.get("icmp_type") and protocol not in ("icmp", "icmpv6"):
        raise FirewallError("icmp_type requires protocol to be icmp or icmpv6.")


# ── Profile CRUD ────────────────────────────────────────────────────────────

def _coerce_profile(row: dict) -> dict:
    return {**row, "active": bool(row["active"])}


def _coerce_rule(row: dict) -> dict:
    return {
        **row,
        "enabled": bool(row["enabled"]),
        "system_rule": bool(row["system_rule"]),
        "src_negate": bool(row["src_negate"]),
        "dst_negate": bool(row["dst_negate"]),
        "log": bool(row["log"]),
    }


def list_profiles() -> list[dict]:
    with get_db() as db:
        rows = db.execute("SELECT * FROM firewall_profiles ORDER BY name").fetchall()
    return [_coerce_profile(dict(row)) for row in rows]


def get_profile(profile_id: int) -> dict:
    with get_db() as db:
        row = db.execute("SELECT * FROM firewall_profiles WHERE id = ?", (profile_id,)).fetchone()
    if row is None:
        raise FirewallError(f"Profile {profile_id} not found.")
    return _coerce_profile(dict(row))


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
    """Clones rules with system_rule reset to 0 — cloning is the documented
    way to customize/remove a safety rule (update_rule/delete_rule refuse to
    touch system rules directly), so a clone whose copies stayed pinned
    would make that escape hatch a dead end."""
    source = get_profile(profile_id)
    new_profile = create_profile(new_name, f"Cloned from {source['name']}")
    with get_db() as db:
        rules = db.execute("SELECT * FROM firewall_rules WHERE profile_id = ? ORDER BY chain, position", (profile_id,)).fetchall()
        now = now_iso()
        for rule in rules:
            data = dict(rule)
            data["system_rule"] = 0
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
    return _coerce_profile(dict(row)) if row else None


# ── Rule CRUD ────────────────────────────────────────────────────────────────

def list_rules(profile_id: int) -> list[dict]:
    get_profile(profile_id)
    with get_db() as db:
        rows = db.execute("SELECT * FROM firewall_rules WHERE profile_id = ? ORDER BY chain, position", (profile_id,)).fetchall()
    return [_coerce_rule(dict(row)) for row in rows]


def _next_position(db: sqlite3.Connection, profile_id: int, chain: str) -> int:
    row = db.execute("SELECT MAX(position) AS max_pos FROM firewall_rules WHERE profile_id = ? AND chain = ?", (profile_id, chain)).fetchone()
    return (row["max_pos"] or 0) + 1


def create_rule(profile_id: int, fields: dict) -> dict:
    get_profile(profile_id)
    if "chain" not in fields or fields["chain"] not in CHAINS:
        raise FirewallError(f"chain must be one of {', '.join(CHAINS)}.")
    unknown = set(fields) - _RULE_FIELDS
    if unknown:
        raise FirewallError(f"Unknown field(s): {', '.join(sorted(unknown))}")
    # `fields` here is a full RuleCreate.model_dump() (every field present,
    # defaults filled by pydantic), so it's already the "effective" set.
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
    return _coerce_rule(dict(row))


def update_rule(rule_id: int, fields: dict) -> dict:
    rule = get_rule(rule_id)
    if rule["system_rule"] and set(fields) - {"enabled"}:
        raise FirewallError("System safety rules can only be enabled/disabled, not edited — clone the profile to customize them.")
    unknown = set(fields) - _RULE_FIELDS
    if unknown:
        raise FirewallError(f"Unknown field(s): {', '.join(sorted(unknown))}")
    if not fields:
        return rule
    # Cross-field checks (e.g. "ports require tcp/udp") need the rule's
    # OTHER fields too, since an update may only touch one column.
    _validate_rule_fields({**rule, **fields})
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
    if rule["system_rule"]:
        raise FirewallError("System safety rules are pinned and cannot be reordered.")
    with get_db() as db:
        neighbor = db.execute(
            "SELECT id, position, system_rule FROM firewall_rules WHERE profile_id = ? AND chain = ? AND position "
            + (" < ? ORDER BY position DESC LIMIT 1" if direction == "up" else " > ? ORDER BY position ASC LIMIT 1"),
            (rule["profile_id"], rule["chain"], rule["position"]),
        ).fetchone()
        if neighbor is None:
            return rule
        if neighbor["system_rule"]:
            raise FirewallError("Cannot move a rule past a pinned system safety rule.")
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
    tables resolve exactly as they will at apply time. Nothing is applied.

    The ruleset is written to a real file (bind-mounted in) rather than
    embedded in the shell script text — rule fields like custom_nft or a
    crafted log_prefix could otherwise contain a line matching a heredoc
    delimiter and break out into arbitrary shell commands inside a
    NET_ADMIN, host-networked container. Field-level validation
    (_validate_rule_fields) also blocks the individual characters that would
    make this possible; this is defense in depth on top of that, not instead
    of it."""
    rendered = render_profile(profile_id)
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    token = hostnet.new_token()
    pending_path = _STATE_DIR / f"validate-{token}.nft"
    pending_path.write_text(rendered)
    try:
        ok, output = hostnet.run_host(
            'nft -c -f "$1"', [str(pending_path)],
            image="opensmart/netadmin", net_admin=True,
            mounts={str(_STATE_DIR): str(_STATE_DIR)},
        )
    finally:
        pending_path.unlink(missing_ok=True)
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

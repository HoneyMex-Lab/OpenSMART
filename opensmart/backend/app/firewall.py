"""Firewall module: structured rules stored in SQLite, dispatched to a
per-profile engine (nftables or iptables) that renders them into a real
ruleset and applies it to the host via a commit-confirm watchdog — the same
safety pattern as network_config.py's live MTU changes: apply, wait for a
confirm/cancel marker, auto-revert on timeout.

This file owns all DB access, profile/rule/alias CRUD, structural (Layer 2)
lockout analysis, and apply bookkeeping — all of it engine-agnostic. The
engine-specific renderer, syntax validation, live-state query, and apply
watchdog script live in firewall_nft.py / firewall_iptables.py (see
_engine_module() below); this module calls into them with already-fetched
structured data, never the other way around, to avoid a circular import.

A profile's `engine` column fixes it to exactly one engine's ruleset syntax
for its whole life (see design notes). At most one
engine's artifacts are ever meant to be loaded in the kernel at a time: every
apply first tears down the *other* engine's artifacts (see
CHAINS/_ENGINES and each engine module's teardown_fragment()), so switching
which engine is active is just an ordinary commit-confirm apply.
"""
import ipaddress
import json
import logging
import re
import sqlite3
from datetime import datetime, timedelta, timezone

from . import firewall_iptables, firewall_nft, hostnet
from .provisioning import CONTAINERS_ROOT
from .database import get_db, now_iso

logger = logging.getLogger(__name__)

CHAINS = ("input", "forward", "output")
_ENGINES = {"nftables": firewall_nft, "iptables": firewall_iptables}
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


def _engine_module(engine: str):
    module = _ENGINES.get(engine)
    if module is None:
        raise FirewallError(f"Unknown firewall engine '{engine}'. Must be one of {', '.join(sorted(_ENGINES))}.")
    return module


def _engine_capability(module, name: str, engine: str):
    """Some engine modules don't implement every capability yet (see
    design notes's phasing) — surface that as a clear
    FirewallError rather than an AttributeError."""
    func = getattr(module, name, None)
    if func is None:
        raise FirewallError(f"The '{engine}' engine does not support this operation yet.")
    return func


def _validate_iface_list(value: str, field: str) -> None:
    for part in value.split(","):
        part = part.strip()
        if part and not _IFACE_RE.fullmatch(part):
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
        if not _PORT_RE.fullmatch(part):
            raise FirewallError(f"{field} contains an invalid port/range: '{part}'.")
        bounds = [int(x) for x in part.split("-")]
        if any(b > 65535 for b in bounds):
            raise FirewallError(f"{field} port out of range: '{part}'.")
        if len(bounds) == 2 and bounds[0] > bounds[1]:
            raise FirewallError(f"{field} range must be low-high: '{part}'.")


def _validate_allowlist_src(value: str) -> None:
    """Lockout-prevention for system_rule=2 (allowlist-managed) rules: per
    the issue, adding ANY non-empty src makes the allowlist "effective"
    (the rule now only accepts from that network, and the drop policy
    catches everything else) — but 0.0.0.0, 255.255.255.255, ::, or any
    CIDR expression equivalent to "every address" would give the false
    impression of a restriction while functionally allowing everyone (or,
    for 255.255.255.255, being a meaningless "network" to restrict to).
    This blocks SAVING outright rather than just warning, per the issue —
    it's a lockout-prevention control, not a cosmetic one."""
    everyone_addresses = {ipaddress.ip_address("0.0.0.0"), ipaddress.ip_address("255.255.255.255"), ipaddress.ip_address("::")}
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        addr_part = part.split("/")[0].strip()
        try:
            if ipaddress.ip_address(addr_part) in everyone_addresses:
                raise FirewallError(f"'{part}' is not a usable allowlist entry — it does not meaningfully restrict access.")
        except ValueError:
            pass
        try:
            network = ipaddress.ip_network(part, strict=False)
        except ValueError:
            continue  # shape already validated elsewhere; not this check's job
        if network.num_addresses == 2 ** network.max_prefixlen:
            raise FirewallError(f"'{part}' matches every address and cannot be used as an allowlist entry — it defeats the purpose of restricting access.")


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
    if effective.get("icmp_type") and not _ICMP_TYPE_RE.fullmatch(effective["icmp_type"]):
        raise FirewallError("icmp_type must be a plain number.")
    if effective.get("rate_limit") and not _RATE_LIMIT_RE.fullmatch(effective["rate_limit"]):
        raise FirewallError("rate_limit must look like '10/second' or '10/second burst 20 packets'.")
    if effective.get("log_prefix") and not _LOG_PREFIX_RE.fullmatch(effective["log_prefix"]):
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


_STRING_RULE_FIELDS = {
    "chain", "action", "reject_with", "family", "protocol", "iif", "oif", "src", "dst",
    "sport", "dport", "ct_state", "icmp_type", "log_prefix", "rate_limit", "description",
}
_BOOL_RULE_FIELDS = {"enabled", "src_negate", "dst_negate", "log"}


def _check_row_types(row: dict) -> str | None:
    """_validate_rule_fields() and the field-list validators all assume
    strings/bools (their only other caller is a Pydantic model that already
    guarantees this) — a row from an untyped source like an import draft
    could carry any JSON scalar. Checked separately, up front, so a bad
    type reads as a clean validation message instead of an unhandled
    TypeError/AttributeError deep inside a regex or a .split() call."""
    for key in _STRING_RULE_FIELDS:
        if key in row and row[key] is not None and not isinstance(row[key], str):
            return f"{key} must be a string."
    for key in _BOOL_RULE_FIELDS:
        if key in row and row[key] is not None and not isinstance(row[key], bool):
            return f"{key} must be true/false."
    if "position" in row and row["position"] is not None and not isinstance(row["position"], int):
        return "position must be a whole number."
    return None


def validate_import_rows(rows: list[dict]) -> list[str]:
    """Pre-flight check for a batch import (routes/firewall.py's
    import_confirm()): every non-skipped row is checked the SAME way
    create_rule() would check it, WITHOUT creating anything. An import
    batch either fully succeeds or reports every problem up front — it
    must never partially create a profile and then silently stop partway
    through the rules, since nothing about the parser's own output
    guarantees these rows pass this app's normal field-grammar rules (real
    iptables-save output includes constructs, like the interface '+'
    wildcard, this schema doesn't itself use)."""
    errors: list[str] = []
    for index, row in enumerate(rows):
        if row.get("skip"):
            continue
        if "chain" not in row or row.get("chain") not in CHAINS:
            errors.append(f"row {index}: chain must be one of {', '.join(CHAINS)}.")
            continue
        unknown = set(row) - _RULE_FIELDS - {"skip"}
        if unknown:
            errors.append(f"row {index}: unknown field(s) {', '.join(sorted(unknown))}.")
            continue
        type_error = _check_row_types(row)
        if type_error:
            errors.append(f"row {index}: {type_error}")
            continue
        try:
            _validate_rule_fields(row)
        except FirewallError as error:
            errors.append(f"row {index}: {error}")
    return errors


# ── Profile CRUD ────────────────────────────────────────────────────────────

def _coerce_profile(row: dict) -> dict:
    return {**row, "active": bool(row["active"])}


def _coerce_rule(row: dict) -> dict:
    # system_rule is a tier, not a flag: 0 = fully user-owned; 1 = fixed
    # (position/fields locked, enable/disable only); 2 = allowlist-managed
    # (position/chain/action/protocol/port locked, but src/src_negate are
    # editable subject to _validate_allowlist_src — see update_rule()).
    # Kept as a raw int (not bool()'d) so the frontend can tell 1 and 2
    # apart; every existing truthiness check (`if rule["system_rule"]`)
    # still works unchanged since both 1 and 2 are truthy.
    return {
        **row,
        "enabled": bool(row["enabled"]),
        "system_rule": row["system_rule"],
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


def create_profile(name: str, description: str = "", engine: str = "nftables") -> dict:
    _engine_module(engine)  # raises FirewallError if not a recognized engine
    now = now_iso()
    with get_db() as db:
        try:
            cur = db.execute(
                "INSERT INTO firewall_profiles (name, description, engine, active, created_at, updated_at) VALUES (?, ?, ?, 0, ?, ?)",
                (name, description, engine, now, now),
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
        # A CONFIRMED apply for this profile writes it to active.nft and
        # marks it active — checked above. But a still-PENDING apply hasn't
        # done that yet, so deleting the profile here would leave the
        # watchdog confirming (or a startup reapply loading) a ruleset with
        # no corresponding profile row: active=1 goes nowhere, and the Rules/
        # Advanced tabs (gated on active_profile) can no longer show or edit
        # what's actually enforced.
        pending = db.execute("SELECT 1 FROM firewall_applies WHERE profile_id = ? AND state = 'pending'", (profile_id,)).fetchone()
        if pending:
            raise FirewallError("This profile has an apply pending confirmation — confirm or cancel it first.")
        db.execute("DELETE FROM firewall_profiles WHERE id = ?", (profile_id,))
        db.commit()


def clone_profile(profile_id: int, new_name: str) -> dict:
    """Clones rules with system_rule reset to 0 — cloning is the documented
    way to customize/remove a safety rule (update_rule/delete_rule refuse to
    touch system rules directly), so a clone whose copies stayed pinned
    would make that escape hatch a dead end."""
    source = get_profile(profile_id)
    new_profile = create_profile(new_name, f"Cloned from {source['name']}", engine=source["engine"])
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


def allowlist_status() -> dict:
    """Whether the platform is currently open to any network on the
    allowlist-managed ports — drives the global warning banner (see
    routes/firewall.py's summary() and AppShell.tsx). Only meaningful when
    the Firewall module is actually enabled and the active profile enforces
    a drop policy on input; a module that isn't enabled, or a profile that
    accepts everything by design, has no lockout-prevention story to warn
    about, so 'open' stays false in either case."""
    with get_db() as db:
        module_row = db.execute("SELECT enabled FROM opensmart_modules WHERE name = 'Firewall'").fetchone()
    if module_row is None or not module_row["enabled"]:
        return {"open": False}
    profile = active_profile()
    if profile is None or _json_policies(profile["policies"]).get("input") != "drop":
        return {"open": False}
    allowlist_rules = [r for r in list_rules(profile["id"]) if r["system_rule"] == 2 and r["enabled"]]
    if not allowlist_rules:
        return {"open": False}
    return {"open": any(not r["src"] for r in allowlist_rules)}


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


_ALLOWLIST_EDITABLE_FIELDS = {"enabled", "src", "src_negate"}


def update_rule(rule_id: int, fields: dict) -> dict:
    rule = get_rule(rule_id)
    # Compare against ACTUAL changes, not just which keys are present — the
    # frontend's rule editor round-trips the whole rule object (spread from
    # the loaded row) rather than a diff, so an update to a tier-1/2 rule's
    # allowed field(s) still carries every other field along at its current,
    # unchanged value. Rejecting on mere presence would make every such save
    # fail; rejecting only on an actual value change preserves the real
    # protection (those other fields still can't be CHANGED) without that
    # false positive.
    changed = {key: value for key, value in fields.items() if rule.get(key) != value}
    if rule["system_rule"] == 2:
        disallowed = set(changed) - _ALLOWLIST_EDITABLE_FIELDS
        if disallowed:
            raise FirewallError(
                f"This allowlist-managed rule only allows editing {', '.join(sorted(_ALLOWLIST_EDITABLE_FIELDS))} "
                f"— clone the profile to customize other fields."
            )
    elif rule["system_rule"] and set(changed) - {"enabled"}:
        raise FirewallError("System safety rules can only be enabled/disabled, not edited — clone the profile to customize them.")
    unknown = set(fields) - _RULE_FIELDS
    if unknown:
        raise FirewallError(f"Unknown field(s): {', '.join(sorted(unknown))}")
    if not fields:
        return rule
    # Cross-field checks (e.g. "ports require tcp/udp") need the rule's
    # OTHER fields too, since an update may only touch one column.
    _validate_rule_fields({**rule, **fields})
    if rule["system_rule"] == 2:
        _validate_allowlist_src(fields.get("src", rule["src"]))
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


# ── Renderer (dispatched to the profile's engine module) ────────────────────

def render_profile(profile_id: int) -> str:
    """Pure — no side effects, no docker calls. rules -> engine-specific
    ruleset text, via the profile's engine module (firewall_nft/
    firewall_iptables). Engine modules raise plain ValueError for
    rules they can't represent (e.g. IPv6 fields on the iptables engine,
    which is IPv4-only in v1) rather than importing FirewallError
    themselves, to avoid a circular import — translated here."""
    profile = get_profile(profile_id)
    rules = list_rules(profile_id)
    policies = _json_policies(profile["policies"])
    module = _engine_module(profile["engine"])
    render = _engine_capability(module, "render", profile["engine"])
    try:
        return render(rules, policies, profile["custom_nft"])
    except ValueError as error:
        raise FirewallError(str(error)) from error


def _json_policies(raw: str) -> dict:
    try:
        data = json.loads(raw)
        return {chain: data.get(chain, "accept") for chain in CHAINS}
    except (ValueError, TypeError):
        return dict.fromkeys(CHAINS, "accept")


# ── Validation (Layer 1: syntax) ─────────────────────────────────────────────

def validate(profile_id: int) -> tuple[bool, str]:
    """Syntax/semantic check against the rendered ruleset, inside a one-off
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
    profile = get_profile(profile_id)
    module = _engine_module(profile["engine"])
    validate_fn = _engine_capability(module, "validate", profile["engine"])
    rendered = render_profile(profile_id)
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    token = hostnet.new_token()
    pending_path = _STATE_DIR / f"validate-{token}.{module.STATE_EXT}"
    pending_path.write_text(rendered)
    try:
        return validate_fn(rendered, pending_path)
    finally:
        pending_path.unlink(missing_ok=True)


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


# ── Live state ───────────────────────────────────────────────────────────────

def live_state() -> dict:
    """Does the active profile's engine have anything loaded on the host
    right now, and if so, does it match what that profile currently renders
    to (a "dirty" flag — the profile was edited since the last apply, not
    "someone ran nft/iptables by hand", which would need parsing the live
    state structurally). With no active profile, defaults to the nftables
    engine purely to answer "is anything of ours loaded" — matches this
    project's only engine before this feature, and is harmless either way
    since is_applied() would report False with nothing loaded."""
    profile = active_profile()
    engine = profile["engine"] if profile else "nftables"
    module = _engine_module(engine)
    live_query = _engine_capability(module, "live_query", engine)
    ok, output = live_query()
    if not ok:
        return {"applied": False, "detail": output}
    applied = module.is_applied(output)
    dirty = False
    active_path = _STATE_DIR / f"active.{module.STATE_EXT}"
    if applied and profile is not None and active_path.is_file():
        dirty = active_path.read_text() != render_profile(profile["id"])
    return {"applied": applied, "raw": output, "dirty": dirty}


def read_logs(lines: int = 200) -> list[str]:
    """Rules with `log` enabled write to the kernel ring buffer (there's no
    other destination for nft's `log` statement) — read it back via `dmesg`,
    filtered to our own comment tag so this doesn't turn into a firehose of
    unrelated kernel messages. Needs CAP_SYSLOG (not NET_ADMIN — dmesg reads
    kernel messages, it doesn't touch the network namespace), so this is the
    one hostnet call in this module that adds a capability beyond NET_ADMIN's
    default rather than reusing it."""
    lines = max(1, min(lines, 2000))
    ok, output = hostnet.run_host(
        f'dmesg -T 2>/dev/null | grep -F "osfw" | tail -n {lines} || true',
        image="opensmart/netadmin", net_admin=False, extra_caps=["SYSLOG"],
    )
    if not ok or not output.strip():
        return []
    return output.splitlines()


# ── Aliases (saved address/port groups) ─────────────────────────────────────
#
# Scoped deliberately simple for v1: an alias is just a named, reusable,
# validated comma-separated value that the rule editor can insert into a
# rule's src/dst/sport/dport field — NOT an nft named `set` referenced at
# render time. True nft sets would let the renderer emit `ip saddr @alias`
# and update membership without re-rendering every rule, but they also mean
# the renderer must track set-vs-rule dependencies and their own
# create/update semantics; this simpler "saved value, copied in" version
# gets the practical benefit (reuse a group of addresses/ports across many
# rules without retyping them) with no new render-time surface at all — it
# reuses the exact same _validate_addr_list/_validate_port_list validation
# already proven for rule fields.

def list_aliases() -> list[dict]:
    with get_db() as db:
        rows = db.execute("SELECT * FROM firewall_aliases ORDER BY name").fetchall()
    return [dict(row) for row in rows]


def create_alias(name: str, kind: str, values_csv: str, description: str = "") -> dict:
    if kind not in ("address", "port"):
        raise FirewallError("kind must be 'address' or 'port'.")
    if kind == "address":
        _validate_addr_list(values_csv, "values")
    else:
        _validate_port_list(values_csv, "values")
    now = now_iso()
    with get_db() as db:
        try:
            cur = db.execute(
                "INSERT INTO firewall_aliases (name, kind, values_csv, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (name, kind, values_csv, description, now, now),
            )
            db.commit()
        except sqlite3.IntegrityError as error:
            raise FirewallError(f"An alias named '{name}' already exists.") from error
    with get_db() as db:
        row = db.execute("SELECT * FROM firewall_aliases WHERE id = ?", (cur.lastrowid,)).fetchone()
    return dict(row)


def update_alias(alias_id: int, fields: dict) -> dict:
    unknown = set(fields) - {"name", "values_csv", "description"}
    if unknown:
        raise FirewallError(f"Unknown field(s): {', '.join(sorted(unknown))}")
    with get_db() as db:
        row = db.execute("SELECT * FROM firewall_aliases WHERE id = ?", (alias_id,)).fetchone()
        if row is None:
            raise FirewallError(f"Alias {alias_id} not found.")
        if "values_csv" in fields:
            if row["kind"] == "address":
                _validate_addr_list(fields["values_csv"], "values")
            else:
                _validate_port_list(fields["values_csv"], "values")
        if not fields:
            return dict(row)
        columns = [f"{key} = ?" for key in fields]
        params = [*fields.values(), now_iso(), alias_id]
        try:
            db.execute(f"UPDATE firewall_aliases SET {', '.join(columns)}, updated_at = ? WHERE id = ?", params)
            db.commit()
        except sqlite3.IntegrityError as error:
            raise FirewallError("An alias with that name already exists.") from error
        updated = db.execute("SELECT * FROM firewall_aliases WHERE id = ?", (alias_id,)).fetchone()
    return dict(updated)


def delete_alias(alias_id: int) -> None:
    with get_db() as db:
        db.execute("DELETE FROM firewall_aliases WHERE id = ?", (alias_id,))
        db.commit()


# ── Apply pipeline (Layer 3: commit-confirm with auto-rollback) ────────────

_APPLY_CONFIRM_MIN_SECONDS = 30
_APPLY_CONFIRM_MAX_SECONDS = 600
_APPLY_CONFIRM_DEFAULT_SECONDS = 60

def _ensure_apply_state_dirs() -> None:
    """Same reasoning as network_config._ensure_state_dirs(): 0o700, because
    a marker's mere presence is the entire authorization decision for the
    safety net, and the watchdog (root) can read/write regardless of mode."""
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    for sub in ("confirm", "cancel", "result"):
        path = _STATE_DIR / sub
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o700)


def apply(profile_id: int, *, confirm_seconds: int = _APPLY_CONFIRM_DEFAULT_SECONDS, actor: str = "", client_ip: str = "") -> dict:
    """Validate (Layer 1), analyze (Layer 2, non-blocking — warnings are
    returned for the UI to show, not raised), then hand off to a detached
    watchdog that applies the rendered ruleset and auto-reverts unless
    confirmed within confirm_seconds. Always commit-confirm; no
    fire-and-forget path exists, by design (see the plan's Decisions)."""
    if not (_APPLY_CONFIRM_MIN_SECONDS <= confirm_seconds <= _APPLY_CONFIRM_MAX_SECONDS):
        raise FirewallError(f"Confirm window must be between {_APPLY_CONFIRM_MIN_SECONDS} and {_APPLY_CONFIRM_MAX_SECONDS} seconds.")
    # Refuse a second concurrent apply: two overlapping watchdogs each
    # snapshot "whatever's live" as their OWN rollback target, so watchdog B
    # would capture watchdog A's not-yet-confirmed ruleset as "the good
    # state" — the two auto-revert timers then race independently and can
    # silently defeat each other's commit-confirm outcome. apply_status()
    # reconciles as a side effect, so this also picks up a just-finished
    # apply rather than blocking on a stale row. (A rare exact-instant TOCTOU
    # between two racing apply() calls is not fully closed by this check
    # alone — acceptable given this is a human-paced admin action, not a
    # high-frequency path — but the common case of "an apply is already
    # visibly in flight" is.)
    existing = apply_status()
    if existing is not None and existing["state"] == "pending":
        raise FirewallError(f"Another apply (profile {existing['profile_id']}, token {existing['token'][:12]}…) is still pending — confirm or cancel it first.")
    profile = get_profile(profile_id)
    module = _engine_module(profile["engine"])
    apply_script = getattr(module, "APPLY_SCRIPT", None)
    if not apply_script:
        raise FirewallError(f"The '{profile['engine']}' engine does not support apply yet.")
    ok, detail = validate(profile_id)
    if not ok:
        raise FirewallError(f"Ruleset failed syntax validation, nothing applied: {detail}")
    warnings = analyze(profile_id, client_ip=client_ip)
    rendered = render_profile(profile_id)
    _ensure_apply_state_dirs()
    token = hostnet.new_token()
    pending_path = _STATE_DIR / f"pending-{token}.{module.STATE_EXT}"
    pending_path.write_text(rendered)
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(seconds=confirm_seconds)).isoformat()
    with get_db() as db:
        db.execute(
            "INSERT INTO firewall_applies (profile_id, token, state, actor, applied_at, expires_at) VALUES (?, ?, 'pending', ?, ?, ?)",
            (profile_id, token, actor, now.isoformat(), expires_at),
        )
        db.commit()
    # At most one engine's artifacts are ever meant to be loaded at once —
    # every apply first tears down every OTHER registered engine's artifacts
    # inside the same watchdog run, so switching engines is just an ordinary
    # apply and the invariant self-heals even if DB/kernel state ever drift.
    teardown_other_engines = "\n".join(
        other.teardown_fragment() for name, other in _ENGINES.items() if name != profile["engine"]
    )
    script = apply_script.replace("__TEARDOWN_OTHER_ENGINES__", teardown_other_engines)
    ok, detail = hostnet.run_host_detached(
        f"opensmart-fw-apply-{token[:12]}",
        script,
        [token, str(confirm_seconds), str(_STATE_DIR)],
        image="opensmart/netadmin", net_admin=True,
        mounts={str(_STATE_DIR): str(_STATE_DIR)},
    )
    if not ok:
        with get_db() as db:
            db.execute("UPDATE firewall_applies SET state = 'failed', detail = ? WHERE token = ?", (detail[:2000], token))
            db.commit()
        pending_path.unlink(missing_ok=True)
        raise FirewallError(f"Could not start the apply watchdog: {detail}")
    return {"token": token, "expires_at": expires_at, "warnings": warnings}


def confirm_apply(token: str) -> None:
    """'Keep changes' — a local file write, nothing more. No dependency on
    Docker or the network being reachable, since the whole point is that
    this must work even when the new ruleset is borderline."""
    if not hostnet.valid_token(token):
        raise FirewallError("Invalid apply token.")
    _ensure_apply_state_dirs()
    (_STATE_DIR / "confirm" / token).write_text("")


def cancel_apply(token: str) -> None:
    """'Revert now' — same mechanism as an auto-revert, just triggered early."""
    if not hostnet.valid_token(token):
        raise FirewallError("Invalid apply token.")
    _ensure_apply_state_dirs()
    (_STATE_DIR / "cancel" / token).write_text("")


def apply_status() -> dict | None:
    """The most recent apply overall, reconciled against the watchdog's
    result marker if one has appeared since we last checked. A CONFIRMED
    apply also becomes the active profile here (never on reverted/failed) —
    "switch profile" is just "apply a different profile, then confirm it",
    per the plan; there is no separate activate step."""
    with get_db() as db:
        row = db.execute("SELECT * FROM firewall_applies ORDER BY id DESC LIMIT 1").fetchone()
        if row is None:
            return None
        result = dict(row)
        if result["state"] == "pending":
            result_file = _STATE_DIR / "result" / result["token"]
            if result_file.is_file():
                outcome_raw = result_file.read_text().strip()
                outcome, _, detail = outcome_raw.partition(":")
                new_state = {"confirmed": "confirmed", "reverted": "reverted"}.get(outcome, "failed")
                db.execute("UPDATE firewall_applies SET state = ?, detail = ? WHERE token = ?", (new_state, detail, result["token"]))
                if new_state == "confirmed":
                    db.execute("UPDATE firewall_profiles SET active = 0")
                    activated = db.execute("UPDATE firewall_profiles SET active = 1, updated_at = ? WHERE id = ?", (now_iso(), result["profile_id"]))
                    if activated.rowcount == 0:
                        # delete_profile() now refuses this while an apply is
                        # pending, so this should no longer be reachable —
                        # kept as a loud signal in case some other path
                        # removes the row (e.g. a future admin action).
                        logger.error(
                            "firewall apply %s confirmed for profile %s, which no longer exists — "
                            "the host is enforcing a ruleset with no corresponding profile row",
                            result["token"], result["profile_id"],
                        )
                db.commit()
                result["state"] = new_state
                result["detail"] = detail
                for prefix in ("pending", "rollback"):
                    for module in _ENGINES.values():
                        (_STATE_DIR / f"{prefix}-{result['token']}.{module.STATE_EXT}").unlink(missing_ok=True)
    return result


def list_applies(limit: int = 20) -> list[dict]:
    with get_db() as db:
        rows = db.execute("SELECT * FROM firewall_applies ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(row) for row in rows]


def reapply_active() -> None:
    """Startup hook. Fail-open by design (see the plan's Decisions): if
    nothing was ever confirmed, there's nothing to re-apply and the host
    simply has no OpenSMART ruleset until an admin applies one. If a
    watchdog was killed mid-apply (host reboot, `docker kill`) before it
    could revert, the pending row is force-marked reverted here — the
    active state file is only ever written by a CONFIRMED apply, so it's
    always safe to treat as "the last known-good state" and reload it.

    A plain backend restart (not a host reboot) does NOT kill the detached
    watchdog container — it keeps running in the Docker daemon, independent
    of the backend process. Left alone, it would eventually fire its own
    confirm-window timeout and call its engine's revert(), undoing whatever
    this reapply loads (including removing jump rules it thinks it added,
    even though those jumps may now be serving the freshly-reloaded
    ruleset). Kill it explicitly before superseding its state, rather than
    hoping nothing races it."""
    with get_db() as db:
        pending = db.execute("SELECT id, token FROM firewall_applies WHERE state = 'pending' ORDER BY id DESC LIMIT 1").fetchone()
        if pending is not None:
            hostnet.kill_container(f"opensmart-fw-apply-{pending['token'][:12]}")
            db.execute(
                "UPDATE firewall_applies SET state = 'reverted', detail = 'backend restarted mid-apply' WHERE id = ?",
                (pending["id"],),
            )
            db.commit()
            logger.warning("firewall apply %s was left pending at startup — treating as reverted", pending["token"])
    profile = active_profile()
    engine = profile["engine"] if profile else "nftables"
    module = _engine_module(engine)
    reapply_fn = getattr(module, "reapply", None)
    active_path = _STATE_DIR / f"active.{module.STATE_EXT}"
    if reapply_fn is None or not active_path.is_file():
        return
    ok, detail = reapply_fn(active_path)
    if not ok:
        logger.warning("startup firewall re-apply failed: %s", detail[:500])
    else:
        logger.info("startup firewall re-apply: active.%s loaded", module.STATE_EXT)

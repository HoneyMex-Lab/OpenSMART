"""Persistent registry of host network interfaces: alias, description, role,
MTU override, and monitor (capture) flag — keyed by the interface's real
kernel name (the only identifier `ip link`, `nft`, and Suricata's
CAPTURE_IFACES all agree on). The alias is a display label only, never an
identifier; a renamed/replaced NIC is handled explicitly via remap(), not
silently.

Live enumeration (name/up/mtu/mac/addresses) comes from
provisioning.host_interfaces(); this module merges that with the stored rows.

Live MTU changes go through hostnet.py's one-off, host-networked containers,
always via commit-confirm: a detached watchdog applies the new MTU, waits for
either a confirm or cancel marker file, and auto-reverts on timeout — so a
value that breaks the admin's own path back to the box heals itself. See
set_mtu()/confirm_mtu()/cancel_mtu()/mtu_apply_status() below.
"""
import ipaddress
import logging
from datetime import datetime, timedelta, timezone

from . import hostnet
from .database import get_db, now_iso
from .provisioning import CONTAINERS_ROOT, host_interfaces

logger = logging.getLogger(__name__)

# docker0/br-*/veth*/wg*/tun*/tap* are Docker/VPN plumbing, not physical NICs —
# mirrors provisioning.host_interfaces()'s own "virtual" flag.
_EDITABLE_FIELDS = {"alias", "description", "role", "monitor"}
_VALID_ROLES = {"", "wan", "lan", "dmz", "mgmt", "monitor"}

_MTU_MIN = 576
_MTU_MIN_IPV6 = 1280  # kernel drops IPv6 on a link below this
_MTU_MAX = 9000
_MTU_CONFIRM_MIN_SECONDS = 30
_MTU_CONFIRM_MAX_SECONDS = 600
_MTU_CONFIRM_DEFAULT_SECONDS = 60

_STATE_DIR = CONTAINERS_ROOT / "network" / "volumes" / "state"

# Positional args: $1=iface $2=new_mtu $3=confirm_seconds $4=state_dir $5=token.
# Never string-interpolated — always passed as real argv elements (see hostnet.py).
_MTU_APPLY_SCRIPT = """
set -uo pipefail
IFACE="$1"; NEW_MTU="$2"; TIMEOUT="$3"; STATE_DIR="$4"; TOKEN="$5"
mkdir -p "$STATE_DIR/confirm" "$STATE_DIR/cancel" "$STATE_DIR/result"
OLD_MTU="$(ip -o link show dev "$IFACE" | grep -oP 'mtu \\K[0-9]+')"
if [ -z "$OLD_MTU" ]; then
  echo "failed:could not read current MTU for $IFACE" > "$STATE_DIR/result/$TOKEN"
  exit 1
fi
if ! ip link set dev "$IFACE" mtu "$NEW_MTU"; then
  echo "failed:ip link set mtu $NEW_MTU failed" > "$STATE_DIR/result/$TOKEN"
  exit 1
fi
i=0
while [ "$i" -lt "$TIMEOUT" ]; do
  if [ -f "$STATE_DIR/confirm/$TOKEN" ]; then
    echo "confirmed:$NEW_MTU" > "$STATE_DIR/result/$TOKEN"
    exit 0
  fi
  if [ -f "$STATE_DIR/cancel/$TOKEN" ]; then
    ip link set dev "$IFACE" mtu "$OLD_MTU"
    echo "reverted:$OLD_MTU" > "$STATE_DIR/result/$TOKEN"
    exit 0
  fi
  sleep 1
  i=$((i + 1))
done
ip link set dev "$IFACE" mtu "$OLD_MTU"
echo "reverted:$OLD_MTU" > "$STATE_DIR/result/$TOKEN"
"""


class NetworkConfigError(Exception):
    """User-facing network configuration failure."""


def _rows() -> dict[str, dict]:
    with get_db() as db:
        rows = db.execute("SELECT * FROM network_interfaces").fetchall()
    return {row["name"]: dict(row) for row in rows}


def _upsert_seen(names: list[str]) -> None:
    """Ensure every currently-enumerated interface has a row, and bump
    last_seen_at for it. Never touches metadata fields."""
    now = now_iso()
    with get_db() as db:
        for name in names:
            db.execute(
                "INSERT INTO network_interfaces (name, first_seen_at, last_seen_at, updated_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET last_seen_at = excluded.last_seen_at",
                (name, now, now, now),
            )
        db.commit()


def list_interfaces(*, force: bool = False) -> list[dict]:
    """Merge live enumeration with stored metadata. Interfaces that are stored
    but no longer present on the host are kept (aliases/roles survive an
    unplugged NIC) and flagged present=False rather than dropped."""
    live = host_interfaces(force=force)
    _upsert_seen([iface["name"] for iface in live])
    stored = _rows()
    live_by_name = {iface["name"]: iface for iface in live}

    result: list[dict] = []
    for name, live_iface in live_by_name.items():
        row = stored.get(name, {})
        result.append({
            "name": name,
            "alias": row.get("alias", ""),
            "description": row.get("description", ""),
            "role": row.get("role", ""),
            "mac": live_iface.get("mac", ""),
            "mac_drift": bool(row.get("mac") and live_iface.get("mac") and row["mac"] != live_iface["mac"]),
            "up": live_iface["up"],
            "virtual": live_iface["virtual"],
            "mtu": live_iface["mtu"],
            "mtu_override": row.get("mtu_override"),
            "monitor": bool(row.get("monitor")),
            "addresses": live_iface.get("addresses", []),
            "present": True,
        })
    # Stored interfaces no longer seen live (unplugged, renamed) — keep visible.
    for name, row in stored.items():
        if name in live_by_name:
            continue
        result.append({
            "name": name,
            "alias": row.get("alias", ""),
            "description": row.get("description", ""),
            "role": row.get("role", ""),
            "mac": row.get("mac", ""),
            "mac_drift": False,
            "up": False,
            "virtual": False,
            "mtu": None,
            "mtu_override": row.get("mtu_override"),
            "monitor": bool(row.get("monitor")),
            "addresses": [],
            "present": False,
        })
    result.sort(key=lambda item: (not item["present"], item["virtual"], item["name"]))
    return result


def update_interface(name: str, fields: dict[str, object]) -> dict:
    """Metadata-only update (alias/description/role/monitor). Never touches
    the live NIC — see hostnet.py / set_mtu for that."""
    unknown = set(fields) - _EDITABLE_FIELDS
    if unknown:
        raise NetworkConfigError(f"Unknown field(s): {', '.join(sorted(unknown))}")
    if "role" in fields and fields["role"] not in _VALID_ROLES:
        raise NetworkConfigError(f"Invalid role '{fields['role']}'.")
    with get_db() as db:
        row = db.execute("SELECT name FROM network_interfaces WHERE name = ?", (name,)).fetchone()
        if row is None:
            raise NetworkConfigError(f"Interface '{name}' is not in the registry yet — rescan first.")
        columns = []
        params: list[object] = []
        for key in ("alias", "description", "role"):
            if key in fields:
                columns.append(f"{key} = ?")
                params.append(str(fields[key]))
        if "monitor" in fields:
            columns.append("monitor = ?")
            params.append(1 if fields["monitor"] else 0)
        if not columns:
            return dict(row)
        columns.append("updated_at = ?")
        params.append(now_iso())
        params.append(name)
        db.execute(f"UPDATE network_interfaces SET {', '.join(columns)} WHERE name = ?", params)
        db.commit()
    return {"name": name, **fields}


def remap(old_name: str, new_name: str) -> None:
    """Move metadata from a missing interface's stored name to a newly-seen
    one (host renamed/replaced a NIC). One explicit admin action, never
    automatic — a name collision or guessing a rename would be worse than
    asking."""
    if old_name == new_name:
        raise NetworkConfigError("Old and new interface names are the same.")
    live_names = {iface["name"] for iface in host_interfaces()}
    if new_name not in live_names:
        raise NetworkConfigError(f"'{new_name}' is not a currently-detected interface.")
    with get_db() as db:
        old_row = db.execute("SELECT * FROM network_interfaces WHERE name = ?", (old_name,)).fetchone()
        if old_row is None:
            raise NetworkConfigError(f"'{old_name}' is not in the registry.")
        existing_new = db.execute("SELECT name FROM network_interfaces WHERE name = ?", (new_name,)).fetchone()
        now = now_iso()
        if existing_new is None:
            db.execute(
                "UPDATE network_interfaces SET name = ?, updated_at = ? WHERE name = ?",
                (new_name, now, old_name),
            )
        else:
            db.execute(
                "UPDATE network_interfaces SET alias = ?, description = ?, role = ?, monitor = ?, updated_at = ? WHERE name = ?",
                (old_row["alias"], old_row["description"], old_row["role"], old_row["monitor"], now, new_name),
            )
            db.execute("DELETE FROM network_interfaces WHERE name = ?", (old_name,))
        db.commit()
    logger.info("network interface remapped: %s -> %s", old_name, new_name)


def monitor_names() -> list[str]:
    """The authoritative capture-interface list for Suricata/traffic
    monitoring — empty if the registry has no monitor=1 rows yet (caller
    falls back to the legacy monitor_interfaces setting in that case)."""
    with get_db() as db:
        rows = db.execute("SELECT name FROM network_interfaces WHERE monitor = 1 ORDER BY name").fetchall()
    return [row["name"] for row in rows]


# ── Live MTU (commit-confirm) ──────────────────────────────────────────────

def _live_interface(name: str) -> dict:
    for iface in host_interfaces():
        if iface["name"] == name:
            return iface
    raise NetworkConfigError(f"'{name}' is not a currently-detected interface.")


def set_mtu(name: str, mtu: int, *, confirm_seconds: int = _MTU_CONFIRM_DEFAULT_SECONDS, actor: str = "", client_ip: str = "") -> dict:
    """Apply `mtu` to a live host interface via a detached watchdog that
    auto-reverts unless confirmed within `confirm_seconds` — see
    _MTU_APPLY_SCRIPT. Always commit-confirm; there is no fire-and-forget path."""
    iface = _live_interface(name)
    if iface["virtual"]:
        raise NetworkConfigError(f"'{name}' is a virtual/container interface — its MTU is managed by Docker/VPN, not here.")
    if not isinstance(mtu, int) or isinstance(mtu, bool):
        raise NetworkConfigError("MTU must be an integer.")
    has_ipv6 = any(addr["family"] == "inet6" for addr in iface.get("addresses", []))
    floor = _MTU_MIN_IPV6 if has_ipv6 else _MTU_MIN
    if not (floor <= mtu <= _MTU_MAX):
        raise NetworkConfigError(f"MTU must be between {floor} and {_MTU_MAX}{' (this interface has IPv6 configured)' if has_ipv6 else ''}.")
    if not (_MTU_CONFIRM_MIN_SECONDS <= confirm_seconds <= _MTU_CONFIRM_MAX_SECONDS):
        raise NetworkConfigError(f"Confirm window must be between {_MTU_CONFIRM_MIN_SECONDS} and {_MTU_CONFIRM_MAX_SECONDS} seconds.")

    session_risk = False
    if client_ip:
        for addr in iface.get("addresses", []):
            try:
                if ipaddress.ip_address(client_ip) in ipaddress.ip_network(addr["address"], strict=False):
                    session_risk = True
                    break
            except ValueError:
                continue

    token = hostnet.new_token()
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(seconds=confirm_seconds)).isoformat()
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    with get_db() as db:
        db.execute(
            "INSERT INTO network_interface_applies (name, token, old_mtu, new_mtu, state, actor, applied_at, expires_at) "
            "VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)",
            (name, token, iface["mtu"], mtu, actor, now.isoformat(), expires_at),
        )
        db.commit()
    ok, detail = hostnet.run_host_detached(
        f"opensmart-mtu-apply-{token[:12]}",
        _MTU_APPLY_SCRIPT,
        [name, str(mtu), str(confirm_seconds), str(_STATE_DIR), token],
        mounts={str(_STATE_DIR): str(_STATE_DIR)},
    )
    if not ok:
        with get_db() as db:
            db.execute("UPDATE network_interface_applies SET state = 'failed', detail = ? WHERE token = ?", (detail[:2000], token))
            db.commit()
        raise NetworkConfigError(f"Could not start the MTU apply watchdog: {detail}")
    return {"token": token, "old_mtu": iface["mtu"], "new_mtu": mtu, "expires_at": expires_at, "session_risk": session_risk}


def _write_marker(kind: str, token: str) -> None:
    if not hostnet.valid_token(token):
        raise NetworkConfigError("Invalid apply token.")
    marker_dir = _STATE_DIR / kind
    marker_dir.mkdir(parents=True, exist_ok=True)
    (marker_dir / token).write_text("")


def confirm_mtu(token: str) -> None:
    """'Keep changes' — a local file write, nothing more. No dependency on
    Docker or the network being reachable, since the whole point is that this
    must work even when the new MTU is borderline."""
    _write_marker("confirm", token)


def cancel_mtu(token: str) -> None:
    """'Revert now' — same mechanism as an auto-revert, just triggered early."""
    _write_marker("cancel", token)


def mtu_apply_status(name: str) -> dict | None:
    """The most recent MTU apply for `name`, reconciled against the
    watchdog's result marker if one has appeared since we last checked."""
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM network_interface_applies WHERE name = ? ORDER BY id DESC LIMIT 1",
            (name,),
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        if result["state"] == "pending":
            result_file = _STATE_DIR / "result" / result["token"]
            if result_file.is_file():
                outcome, _, detail = result_file.read_text().strip().partition(":")
                new_state = {"confirmed": "confirmed", "reverted": "reverted", "failed": "failed"}.get(outcome, "failed")
                db.execute(
                    "UPDATE network_interface_applies SET state = ?, detail = ? WHERE token = ?",
                    (new_state, detail, result["token"]),
                )
                if new_state == "confirmed":
                    # Persist so reapply_mtus() restores this after a reboot —
                    # a reverted/failed apply leaves whatever override (if any)
                    # was already confirmed before this attempt untouched.
                    db.execute(
                        "UPDATE network_interfaces SET mtu_override = ?, updated_at = ? WHERE name = ?",
                        (result["new_mtu"], now_iso(), name),
                    )
                db.commit()
                result["state"] = new_state
                result["detail"] = detail
            elif datetime.now(timezone.utc).isoformat() > result["expires_at"]:
                # Watchdog should have reverted by now but hasn't written a
                # result yet (still mid-revert, or was killed) — the row stays
                # pending; the next poll will pick up the result file once it
                # lands, or reapply_mtus() will force-correct at next startup.
                pass
    return result


def reapply_mtus() -> None:
    """Startup hook: restore any admin-set MTU override that doesn't match
    the live value. Not commit-confirm — this re-applies an already-confirmed
    setting after a reboot/DHCP renewal, it isn't a new risky change."""
    with get_db() as db:
        rows = db.execute("SELECT name, mtu_override FROM network_interfaces WHERE mtu_override IS NOT NULL").fetchall()
    if not rows:
        return
    live_by_name = {iface["name"]: iface for iface in host_interfaces(force=True)}
    for row in rows:
        iface = live_by_name.get(row["name"])
        if iface is None or iface["virtual"] or iface["mtu"] == row["mtu_override"]:
            continue
        ok, detail = hostnet.run_host("ip link set dev \"$1\" mtu \"$2\"", [row["name"], str(row["mtu_override"])])
        if not ok:
            logger.warning("startup MTU re-apply failed for %s: %s", row["name"], detail[:500])
        else:
            logger.info("startup MTU re-apply: %s -> %s", row["name"], row["mtu_override"])

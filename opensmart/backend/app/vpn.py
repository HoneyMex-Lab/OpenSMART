"""VPN instance manager: OpenVPN/WireGuard servers as generated compose
projects under containers/run/vpn/<name>/, each running with HOST
networking (like suricata/zeek) and listening on its own UDP port directly
on the host's interfaces — a VPN server must be reachable on the real
network and route client traffic to the LAN, which bridge+NAT breaks.
WireGuard instances get a uniquely-named host interface (wg<id>).
Key/cert material is produced by one-off containers run through the
docker-socket-proxy (EXEC is blocked, but CONTAINERS+POST one-off runs are
allowed, same pattern as provisioning.host_interfaces()); everything else
is plain file work on the bind-mounted volumes, which the backend sees at
host-parity paths (OPENSMART_PROJECT_DIR).
"""
import ipaddress
import json
import logging
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .database import get_db
from .provisioning import CONTAINERS_ROOT, _docker_inspect, _uptime_seconds

logger = logging.getLogger(__name__)

INSTANCES_ROOT = CONTAINERS_ROOT / "vpn"

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,29}$")
USER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$")

# The gen-pki templates default to OpenVPN's standard port; _init_openvpn
# rewrites it to the instance's real port (host networking, no remapping).
_OPENVPN_SERVICE_PORT = 1194

_RUN_TIMEOUT_SECONDS = 180
_SUBNET_LOW, _SUBNET_HIGH = 60, 250  # 10.<n>.0.0/24 pool for instances

_PEER_BEGIN = "# BEGIN peer "
_PEER_END = "# END peer "

# OpenVPN writes a machine-readable (status-version 2, CSV) list of currently
# connected clients + byte counters here every few seconds; instance_status()
# reads it to show live connections. Path is inside the bind-mounted /data.
_OPENVPN_STATUS_FILE = "log/openvpn-status.log"
_OPENVPN_EXTRAS_DIRECTIVE = (
    "\n# OpenSMART VPN dashboard: live connected-client status (status-version 2)\n"
    "# and a client-config-dir so users can be disabled without revoking.\n"
    f"status /data/{_OPENVPN_STATUS_FILE} 5\n"
    "status-version 2\n"
    "client-config-dir /data/ccd\n"
)

# Editable per-instance server settings (stored as JSON in vpn_instances.settings).
# dns: comma-separated client DNS; tunnel: 'full' routes all client traffic
# through the VPN, 'split' only the routes below; routes: comma-separated CIDRs
# for split tunnel (defaults to the instance subnet).
_DEFAULT_SETTINGS = {"dns": "1.1.1.1", "tunnel": "full", "routes": ""}
_OFF = "#OFF "  # marks a disabled WireGuard peer's lines (wg-quick ignores them)
# OpenVPN's DNS/route/gateway pushes are regenerated between these markers so
# editing settings replaces them cleanly instead of stacking duplicates.
_OVPN_SETTINGS_BEGIN = "# BEGIN opensmart-settings"
_OVPN_SETTINGS_END = "# END opensmart-settings"


def _cidr_to_net_mask(cidr: str) -> tuple[str, str]:
    net = ipaddress.ip_network(cidr, strict=False)
    return str(net.network_address), str(net.netmask)


def _split_csv(value: str) -> list[str]:
    return [v.strip() for v in str(value or "").split(",") if v.strip()]


def _instance_settings(instance: dict) -> dict:
    try:
        stored = json.loads(instance.get("settings") or "{}")
    except (json.JSONDecodeError, TypeError):
        stored = {}
    return {**_DEFAULT_SETTINGS, **{k: v for k, v in stored.items() if k in _DEFAULT_SETTINGS}}


def _validate_addresses(tokens: list[str], *, cidr: bool = False) -> None:
    for token in tokens:
        try:
            ipaddress.ip_network(token, strict=False) if cidr else ipaddress.ip_address(token)
        except ValueError as error:
            raise VpnError(f"Invalid {'route' if cidr else 'DNS address'} '{token}'.") from error


def _wg_client_allowed_ips(settings: dict, subnet: str) -> str:
    if settings["tunnel"] == "split":
        routes = _split_csv(settings["routes"]) or [subnet]
        return ", ".join(routes)
    return "0.0.0.0/0"


def _validate_settings(settings: dict, base: dict | None = None) -> dict:
    base = base or dict(_DEFAULT_SETTINGS)
    dns = str(settings.get("dns", base["dns"])).strip()
    tunnel = str(settings.get("tunnel", base["tunnel"])).strip()
    routes = str(settings.get("routes", base["routes"])).strip()
    if tunnel not in ("full", "split"):
        raise VpnError("Tunnel mode must be 'full' or 'split'.")
    _validate_addresses(_split_csv(dns), cidr=False)
    _validate_addresses(_split_csv(routes), cidr=True)
    return {"dns": dns, "tunnel": tunnel, "routes": routes}


def _validate_subnet(subnet: str) -> str:
    """Normalise a user-supplied VPN network. Restricted to a /24 — the peer
    address allocation (hosts .2–.254) and _subnet_base() both assume one."""
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError as error:
        raise VpnError("Network must be a valid CIDR, e.g. 10.20.0.0/24.") from error
    if net.version != 4 or net.prefixlen != 24:
        raise VpnError("VPN network must be an IPv4 /24 (e.g. 10.20.0.0/24).")
    return str(net)


class VpnError(Exception):
    """User-facing VPN operation failure."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _instance_dir(name: str) -> Path:
    return INSTANCES_ROOT / name


def _data_dir(name: str) -> Path:
    return _instance_dir(name) / "volumes" / "data"


def _container_name(name: str) -> str:
    return f"opensmart-vpn-{name}"


def _compose(name: str, *args: str) -> tuple[bool, str]:
    path = _instance_dir(name) / "docker-compose.yml"
    if not path.is_file():
        return False, f"No docker-compose.yml for VPN instance '{name}'"
    try:
        result = subprocess.run(
            ["docker", "compose", "-f", str(path), *args],
            cwd=str(path.parent),
            capture_output=True,
            text=True,
            timeout=_RUN_TIMEOUT_SECONDS,
            shell=False,
        )
    except FileNotFoundError:
        return False, "docker CLI is not available in this environment."
    except subprocess.TimeoutExpired:
        return False, f"Timed out after {_RUN_TIMEOUT_SECONDS}s."
    output = (result.stderr or result.stdout or "").strip()
    if result.returncode != 0:
        logger.warning("vpn compose %s failed for %s: %s", args, name, output[:2000])
        return False, output[-2000:]
    return True, output[-2000:]


def _docker_run(image: str, script: str, data_dir: Path) -> tuple[bool, str]:
    """One-off `bash -c <script>` in the given image with the instance's
    data dir mounted at /data (host-parity path, see module docstring)."""
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "--entrypoint", "bash",
             "-v", f"{data_dir}:/data", image, "-c", script],
            capture_output=True,
            text=True,
            timeout=_RUN_TIMEOUT_SECONDS,
            shell=False,
        )
    except FileNotFoundError:
        return False, "docker CLI is not available in this environment."
    except subprocess.TimeoutExpired:
        return False, f"Timed out after {_RUN_TIMEOUT_SECONDS}s."
    output = (result.stderr or result.stdout or "").strip()
    if result.returncode != 0:
        logger.warning("vpn one-off run failed (%s): %s", image, output[:2000])
        return False, output[-2000:]
    return True, (result.stdout or "").strip()


def _allocate_subnet(db) -> str:
    used = {row["subnet"] for row in db.execute("SELECT subnet FROM vpn_instances").fetchall()}
    for n in range(_SUBNET_LOW, _SUBNET_HIGH + 1):
        subnet = f"10.{n}.0.0/24"
        if subnet not in used:
            return subnet
    raise VpnError("No free VPN subnets left.")


def _subnet_base(subnet: str) -> str:
    return subnet.split("/", 1)[0].rsplit(".", 1)[0]  # "10.60.0.0/24" -> "10.60.0"


def _wg_iface(instance_id: int) -> str:
    """WireGuard interface name for an instance. Host networking means every
    instance shares the host's interface namespace, so names must be unique
    (and <= 15 chars) — the numeric instance id guarantees both."""
    return f"wg{instance_id}"


def _write_compose(name: str, vpn_type: str, port: int, instance_id: int) -> None:
    container = _container_name(name)
    if vpn_type == "openvpn":
        service = f"""services:
  vpn:
    image: opensmart/openvpn
    container_name: {container}
    hostname: vpn-{name}
    network_mode: host
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    command: ["-c", "mkdir -p /data/log && exec openvpn --config /data/server.conf"]
    volumes:
      - ./volumes/data:/data
    restart: unless-stopped
"""
    else:
        iface = _wg_iface(instance_id)
        service = f"""services:
  vpn:
    image: opensmart/wireguard
    container_name: {container}
    hostname: vpn-{name}
    network_mode: host
    cap_add:
      - NET_ADMIN
    # No sysctls: section — Docker rejects per-container sysctls together
    # with host networking (they'd mutate the host namespace). Not needed
    # anyway: the Docker daemon itself enables net.ipv4.ip_forward on the
    # host, and src_valid_mark only matters for fwmark'd client configs.
    # The image's default entrypoint (wg-up.sh) is single-instance: it owns
    # a fixed wg0 and port 51820. Instances bring up their own uniquely-named
    # interface from the config the backend generated instead.
    entrypoint: ["bash", "-c"]
    command:
      - "wg-quick down /data/{iface}.conf 2>/dev/null || true; wg-quick up /data/{iface}.conf && wg show {iface} && exec sleep infinity"
    volumes:
      - ./volumes/data:/data
    restart: unless-stopped
"""
    compose = (
        "# Generated by OpenSMART's VPN module (backend/app/vpn.py) — edits here\n"
        "# are overwritten when the instance is recreated. The opensmart/openvpn\n"
        "# and opensmart/wireguard images are built host-side by opensmart.sh.\n"
        "#\n"
        "# Host networking on purpose: a VPN server has to be reachable on the\n"
        "# host's real interfaces and route client traffic to the LAN — behind a\n"
        f"# bridge + NAT that breaks. The service listens directly on UDP {port}.\n"
        + service
    )
    path = _instance_dir(name) / "docker-compose.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(compose)


# The one-off containers' root maps to a different host UID than the backend
# (unprivileged nesting, same story as arkime's init-data-dir service), so
# after every PKI mutation the run re-opens /data so BOTH sides keep working:
# the backend edits server.conf/templates and reads index.txt/client configs,
# the server container reads the key material. The host-side path above the
# bind mount stays root-only.
_OPENVPN_CHMOD = "chmod -R a+rwX /data"


def _init_openvpn(name: str, subnet: str, port: int, auth_mode: str, ldap_config: dict) -> None:
    data = _data_dir(name)
    data.mkdir(parents=True, exist_ok=True)
    data.chmod(0o777)
    ok, detail = _docker_run("opensmart/openvpn", f"/opt/opensmart/gen-pki.sh && {_OPENVPN_CHMOD}", data)
    if not ok:
        raise VpnError(f"PKI generation failed: {detail}")
    server_conf = data / "server.conf"
    conf = server_conf.read_text()
    conf = conf.replace("server 10.20.0.0 255.255.255.0", f"server {_subnet_base(subnet)}.0 255.255.255.0")
    # Host networking: the daemon binds the instance's UDP port directly on
    # the host interfaces (no compose port mapping to remap it).
    conf = conf.replace(f"port {_OPENVPN_SERVICE_PORT}", f"port {port}", 1)
    if auth_mode == "ldap":
        conf += (
            "\n# LDAP / Samba AD authentication (auth_mode=ldap)\n"
            "verify-client-cert optional\n"
            "plugin /usr/lib/openvpn/openvpn-auth-ldap.so /data/auth-ldap.conf\n"
        )
        _write_ldap_conf(data / "auth-ldap.conf", ldap_config)
    conf += _OPENVPN_EXTRAS_DIRECTIVE
    (data / "ccd").mkdir(exist_ok=True)
    server_conf.write_text(conf)
    # Client template: point the remote at this instance's published port.
    template = data / "client.ovpn.tmpl"
    if template.is_file():
        text = template.read_text().replace(f"remote __SERVER_IP__ {_OPENVPN_SERVICE_PORT}", f"remote __SERVER_IP__ {port}")
        if auth_mode == "ldap":
            text += "auth-user-pass\n"
        template.write_text(text)


def _write_ldap_conf(path: Path, ldap_config: dict) -> None:
    url = str(ldap_config.get("url", "")).strip()
    base_dn = str(ldap_config.get("base_dn", "")).strip()
    bind_dn = str(ldap_config.get("bind_dn", "")).strip()
    bind_password = str(ldap_config.get("bind_password", "")).strip()
    search_filter = str(ldap_config.get("search_filter", "(sAMAccountName=%u)")).strip()
    if not url or not base_dn:
        raise VpnError("LDAP auth requires at least 'url' and 'base_dn'.")
    bind_lines = ""
    if bind_dn:
        bind_lines = f"\tBindDN\t\t\"{bind_dn}\"\n\tPassword\t\"{bind_password}\"\n"
    path.write_text(
        "<LDAP>\n"
        f"\tURL\t\t{url}\n"
        + bind_lines
        + "\tTimeout\t\t15\n"
        "\tTLSEnable\tno\n"
        "</LDAP>\n"
        "<Authorization>\n"
        f"\tBaseDN\t\t\"{base_dn}\"\n"
        f"\tSearchFilter\t\"{search_filter}\"\n"
        "\tRequireGroup\tfalse\n"
        "</Authorization>\n"
    )
    path.chmod(0o600)


def _wg_keypair(data: Path) -> tuple[str, str]:
    """Generate a WireGuard keypair via a one-off container, returned on
    stdout rather than written to files: the one-off container's root maps
    to a different host UID than the backend (unprivileged nesting), so
    files it creates with restrictive modes are unreadable here."""
    ok, output = _docker_run(
        "opensmart/wireguard",
        "priv=$(wg genkey); printf '%s\\n' \"$priv\"; printf '%s' \"$priv\" | wg pubkey",
        data,
    )
    if not ok:
        raise VpnError(f"WireGuard key generation failed: {output}")
    lines = output.splitlines()
    if len(lines) < 2:
        raise VpnError("Unexpected key generation output.")
    return lines[0].strip(), lines[1].strip()


def _wg_conf_path(name: str) -> Path:
    """The instance's WireGuard config (wg<id>.conf). Located by glob so
    read paths (peer list/revoke) don't need the instance id."""
    matches = sorted(_data_dir(name).glob("wg*.conf"))
    if not matches:
        raise VpnError("Instance not initialized (missing WireGuard config).")
    return matches[0]


def _init_wireguard(name: str, subnet: str, port: int, instance_id: int) -> None:
    data = _data_dir(name)
    data.mkdir(parents=True, exist_ok=True)
    data.chmod(0o777)  # the wireguard container's root is a different host UID
    private_key, public_key = _wg_keypair(data)
    for filename, key in (("server_private.key", private_key), ("server_public.key", public_key)):
        path = data / filename
        path.write_text(key + "\n")
        path.chmod(0o600)
    base = _subnet_base(subnet)
    # Host networking: the config filename doubles as the (unique) host
    # interface name, and ListenPort is the instance's real UDP port.
    conf = data / f"{_wg_iface(instance_id)}.conf"
    conf.write_text(
        "[Interface]\n"
        f"Address = {base}.1/24\n"
        f"ListenPort = {port}\n"
        f"PrivateKey = {private_key}\n"
        "PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE\n"
        "PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE\n"
    )
    # Must stay readable by the wireguard container's (differently-mapped)
    # root. The host-side directory tree above it is root-only.
    conf.chmod(0o644)


def _public_instance(instance: dict) -> dict:
    """API-safe view of an instance row: drop the LDAP bind password, expose
    settings as a parsed object."""
    data = dict(instance)
    data.pop("ldap_config", None)
    data["settings"] = _instance_settings(instance)
    return data


def list_instances() -> list[dict]:
    with get_db() as db:
        rows = db.execute("SELECT * FROM vpn_instances ORDER BY name").fetchall()
    instances = [_public_instance(dict(row)) for row in rows]
    inspected = {i["Name"].lstrip("/"): i for i in _docker_inspect([_container_name(r["name"]) for r in instances])} if instances else {}
    for instance in instances:
        state = inspected.get(_container_name(instance["name"]), {}).get("State", {})
        instance["running"] = bool(state.get("Running"))
        instance["status"] = state.get("Status", "not created")
        instance["uptime_seconds"] = _uptime_seconds(state.get("StartedAt", "")) if state.get("Running") else None
        instance["users"] = len(list_users(instance["name"], instance["vpn_type"]))
    return instances


def _get_instance(name: str) -> dict:
    with get_db() as db:
        row = db.execute("SELECT * FROM vpn_instances WHERE name = ?", (name,)).fetchone()
    if row is None:
        raise VpnError(f"Unknown VPN instance '{name}'")
    return dict(row)


def create_instance(name: str, vpn_type: str, port: int, auth_mode: str = "certs",
                    ldap_config: dict | None = None, subnet: str | None = None,
                    settings: dict | None = None) -> dict:
    if not NAME_RE.match(name or ""):
        raise VpnError("Instance name must be 1-30 chars: lowercase letters, digits, dashes.")
    if vpn_type not in ("openvpn", "wireguard"):
        raise VpnError("vpn_type must be 'openvpn' or 'wireguard'.")
    if not (1024 <= port <= 65535):
        raise VpnError("Port must be between 1024 and 65535.")
    if auth_mode not in ("certs", "ldap"):
        raise VpnError("auth_mode must be 'certs' or 'ldap'.")
    if auth_mode == "ldap" and vpn_type != "openvpn":
        raise VpnError("LDAP authentication is only supported for OpenVPN.")
    ldap_config = ldap_config or {}
    requested_subnet = _validate_subnet(subnet) if subnet else None
    settings_json = json.dumps(_validate_settings(settings)) if settings else "{}"
    with get_db() as db:
        existing = db.execute("SELECT 1 FROM vpn_instances WHERE name = ? OR port = ?", (name, port)).fetchone()
        if existing:
            raise VpnError("An instance with that name or port already exists.")
        if requested_subnet:
            if db.execute("SELECT 1 FROM vpn_instances WHERE subnet = ?", (requested_subnet,)).fetchone():
                raise VpnError(f"Network {requested_subnet} is already used by another instance.")
            subnet = requested_subnet
        else:
            subnet = _allocate_subnet(db)
        cursor = db.execute(
            "INSERT INTO vpn_instances (name, vpn_type, port, subnet, auth_mode, ldap_config, settings, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (name, vpn_type, port, subnet, auth_mode, json.dumps(ldap_config), settings_json, _now()),
        )
        instance_id = int(cursor.lastrowid or 0)
        db.commit()
    try:
        _write_compose(name, vpn_type, port, instance_id)
        if vpn_type == "openvpn":
            _init_openvpn(name, subnet, port, auth_mode, ldap_config)
            # Bake the chosen DNS / tunnel mode into the server's pushed config.
            _apply_openvpn_settings(name, _get_instance(name), None)
        else:
            _init_wireguard(name, subnet, port, instance_id)
    except Exception:
        # Roll back the registration so a failed init can be retried cleanly.
        with get_db() as db:
            db.execute("DELETE FROM vpn_instances WHERE name = ?", (name,))
            db.commit()
        shutil.rmtree(_instance_dir(name), ignore_errors=True)
        raise
    return _public_instance(_get_instance(name))


def delete_instance(name: str) -> None:
    instance = _get_instance(name)
    _compose(instance["name"], "down")
    shutil.rmtree(_instance_dir(name), ignore_errors=True)
    with get_db() as db:
        db.execute("DELETE FROM vpn_instances WHERE name = ?", (name,))
        db.commit()


def start_instance(name: str) -> tuple[bool, str]:
    instance = _get_instance(name)
    if instance["vpn_type"] == "openvpn":
        _ensure_openvpn_status(name)
    return _compose(name, "up", "-d")


def _ensure_openvpn_status(name: str) -> None:
    """Backfill the status-file + client-config-dir directives into an OpenVPN
    instance created before those existed, so it emits connected-client data
    and supports per-user disable."""
    conf_path = _data_dir(name) / "server.conf"
    try:
        conf = conf_path.read_text()
    except OSError:
        return
    (_data_dir(name) / "ccd").mkdir(exist_ok=True)
    if _OPENVPN_STATUS_FILE not in conf:
        conf_path.write_text(conf + _OPENVPN_EXTRAS_DIRECTIVE)


def stop_instance(name: str) -> tuple[bool, str]:
    _get_instance(name)
    return _compose(name, "down")


def restart_instance(name: str) -> tuple[bool, str]:
    _get_instance(name)
    return _compose(name, "restart")


# --- Users / peers -----------------------------------------------------------

def list_users(name: str, vpn_type: str | None = None) -> list[dict]:
    vpn_type = vpn_type or _get_instance(name)["vpn_type"]
    if vpn_type == "openvpn":
        return _openvpn_users(name)
    return _wireguard_peers(name)


def _openvpn_users(name: str) -> list[dict]:
    index = _data_dir(name) / "pki" / "index.txt"
    if not index.is_file():
        return []
    users = []
    for line in index.read_text().splitlines():
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        status, expiry, cn = parts[0].strip(), parts[1].strip(), parts[5].strip()
        common_name = cn.split("/CN=")[-1] if "/CN=" in cn else cn
        if common_name == "server":
            continue
        label = {"V": "valid", "R": "revoked", "E": "expired"}.get(status, status)
        if label == "valid" and _openvpn_user_disabled(name, common_name):
            label = "disabled"
        users.append({
            "name": common_name,
            "status": label,
            "expires_at": _parse_index_ts(expiry),
            "has_config": (_data_dir(name) / "clients" / f"{common_name}.ovpn").is_file(),
        })
    return users


def _openvpn_user_disabled(name: str, username: str) -> bool:
    ccd = _data_dir(name) / "ccd" / username
    try:
        return "disable" in ccd.read_text()
    except OSError:
        return False


def _parse_index_ts(raw: str) -> str:
    # easy-rsa index.txt timestamps: YYMMDDHHMMSSZ
    match = re.match(r"^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$", raw)
    if not match:
        return ""
    yy, mm, dd, hh, mi, ss = match.groups()
    return f"20{yy}-{mm}-{dd}T{hh}:{mi}:{ss}+00:00"


def _wireguard_peers(name: str) -> list[dict]:
    try:
        conf = _wg_conf_path(name)
    except VpnError:
        return []
    peers = []
    current: str | None = None
    disabled = False
    for line in conf.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith(_PEER_BEGIN):
            current, disabled = stripped[len(_PEER_BEGIN):].strip(), False
        elif stripped.startswith(_PEER_END):
            if current:
                peers.append({
                    "name": current,
                    "status": "disabled" if disabled else "valid",
                    "expires_at": "",
                    "has_config": (_data_dir(name) / "clients" / f"{current}.conf").is_file(),
                })
            current = None
        elif current and stripped.startswith(_OFF.strip()):
            disabled = True
    return peers


def create_user(name: str, username: str, server_host: str) -> dict:
    if not USER_RE.match(username or ""):
        raise VpnError("User name must be 1-40 chars: letters, digits, dot, underscore, dash.")
    server_host = (server_host or "").strip()
    if not server_host or re.search(r"[\s'\"\\;|&$`]", server_host):
        raise VpnError("A valid server host/IP is required.")
    instance = _get_instance(name)
    if any(u["name"] == username and u["status"] == "valid" for u in list_users(name, instance["vpn_type"])):
        raise VpnError(f"User '{username}' already exists.")
    if instance["vpn_type"] == "openvpn":
        ok, detail = _docker_run(
            "opensmart/openvpn",
            f"/opt/opensmart/make-client.sh {username} {server_host} && {_OPENVPN_CHMOD}",
            _data_dir(name),
        )
        if not ok:
            raise VpnError(f"Client creation failed: {detail}")
    else:
        _create_wireguard_peer(instance, username, server_host)
    return {"name": username, "instance": name}


def _create_wireguard_peer(instance: dict, username: str, server_host: str) -> None:
    name = instance["name"]
    data = _data_dir(name)
    conf_path = _wg_conf_path(name)
    conf = conf_path.read_text()
    base = _subnet_base(instance["subnet"])
    used = {int(m) for m in re.findall(rf"AllowedIPs = {re.escape(base)}\.(\d+)/32", conf)}
    host_id = next((n for n in range(2, 255) if n not in used), None)
    if host_id is None:
        raise VpnError("No free peer addresses left in this instance's subnet.")
    client_private, client_public = _wg_keypair(data)
    server_public = (data / "server_public.key").read_text().strip()
    conf += (
        f"\n{_PEER_BEGIN}{username}\n"
        "[Peer]\n"
        f"PublicKey = {client_public}\n"
        f"AllowedIPs = {base}.{host_id}/32\n"
        f"{_PEER_END}{username}\n"
    )
    conf_path.write_text(conf)
    clients = data / "clients"
    clients.mkdir(exist_ok=True)
    settings = _instance_settings(instance)
    dns = settings["dns"] or _DEFAULT_SETTINGS["dns"]
    client_conf = clients / f"{username}.conf"
    client_conf.write_text(
        "[Interface]\n"
        f"PrivateKey = {client_private}\n"
        f"Address = {base}.{host_id}/32\n"
        f"DNS = {dns}\n\n"
        "[Peer]\n"
        f"PublicKey = {server_public}\n"
        f"Endpoint = {server_host}:{instance['port']}\n"
        f"AllowedIPs = {_wg_client_allowed_ips(settings, instance['subnet'])}\n"
        "PersistentKeepalive = 25\n"
    )
    client_conf.chmod(0o600)
    _restart_if_running(name)


def revoke_user(name: str, username: str) -> None:
    if not USER_RE.match(username or ""):
        raise VpnError("Invalid user name.")
    instance = _get_instance(name)
    if instance["vpn_type"] == "openvpn":
        ok, detail = _docker_run(
            "opensmart/openvpn",
            "export EASYRSA_PKI=/data/pki EASYRSA_BATCH=1; EASY=/usr/share/easy-rsa/easyrsa; "
            f'"$EASY" revoke {username} && "$EASY" gen-crl && {_OPENVPN_CHMOD}',
            _data_dir(name),
        )
        if not ok:
            raise VpnError(f"Revocation failed: {detail}")
        client = _data_dir(name) / "clients" / f"{username}.ovpn"
        client.unlink(missing_ok=True)
        # The running server re-reads crl.pem per handshake; no restart needed.
    else:
        conf_path = _wg_conf_path(name)
        lines = conf_path.read_text().splitlines()
        out: list[str] = []
        skipping = False
        found = False
        for line in lines:
            if line.strip() == f"{_PEER_BEGIN}{username}".strip():
                skipping = True
                found = True
                continue
            if skipping and line.strip() == f"{_PEER_END}{username}".strip():
                skipping = False
                continue
            if not skipping:
                out.append(line)
        if not found:
            raise VpnError(f"No such peer '{username}'.")
        conf_path.write_text("\n".join(out).rstrip("\n") + "\n")
        (_data_dir(name) / "clients" / f"{username}.conf").unlink(missing_ok=True)
        _restart_if_running(name)


def _restart_if_running(name: str) -> None:
    inspected = _docker_inspect([_container_name(name)])
    if inspected and inspected[0].get("State", {}).get("Running"):
        _compose(name, "restart")


# --- Server settings ---------------------------------------------------------

def update_instance(name: str, settings: dict | None = None, ldap_config: dict | None = None) -> dict:
    """Edit an instance's server settings (client DNS, tunnel mode/routes) and,
    for OpenVPN, its LDAP config. Changes are applied to the live config and
    existing client configs (WireGuard keys are preserved)."""
    instance = _get_instance(name)
    merged = _instance_settings(instance)
    if settings is not None:
        merged = _validate_settings(settings, base=merged)
    if ldap_config is not None and instance["vpn_type"] != "openvpn":
        raise VpnError("LDAP settings apply only to OpenVPN instances.")
    with get_db() as db:
        if ldap_config is not None:
            db.execute("UPDATE vpn_instances SET settings = ?, ldap_config = ? WHERE name = ?",
                       (json.dumps(merged), json.dumps(ldap_config), name))
        else:
            db.execute("UPDATE vpn_instances SET settings = ? WHERE name = ?", (json.dumps(merged), name))
        db.commit()
    instance = _get_instance(name)
    if instance["vpn_type"] == "wireguard":
        _regenerate_wg_clients(name, instance)
    else:
        _apply_openvpn_settings(name, instance, ldap_config)
    return _public_instance(instance)


def _regenerate_wg_clients(name: str, instance: dict) -> None:
    """Rewrite existing WireGuard client configs' DNS + AllowedIPs from the
    current settings, preserving each client's keys (users must re-download)."""
    settings = _instance_settings(instance)
    dns = settings["dns"] or _DEFAULT_SETTINGS["dns"]
    allowed = _wg_client_allowed_ips(settings, instance["subnet"])
    clients = _data_dir(name) / "clients"
    if not clients.is_dir():
        return
    for conf in clients.glob("*.conf"):
        text = conf.read_text()
        text = re.sub(r"(?m)^DNS = .*$", f"DNS = {dns}", text)
        text = re.sub(r"(?m)^AllowedIPs = .*$", f"AllowedIPs = {allowed}", text)
        conf.write_text(text)


def _openvpn_settings_block(settings: dict) -> str:
    lines = [_OVPN_SETTINGS_BEGIN]
    dns_list = _split_csv(settings["dns"])
    lines += [f'push "dhcp-option DNS {dns}"' for dns in dns_list]
    if dns_list:
        lines.append('push "block-outside-dns"')
    if settings["tunnel"] == "full":
        lines.append('push "redirect-gateway def1 bypass-dhcp"')
    else:
        for route in _split_csv(settings["routes"]):
            net, mask = _cidr_to_net_mask(route)
            lines.append(f'push "route {net} {mask}"')
    lines.append(_OVPN_SETTINGS_END)
    return "\n".join(lines) + "\n"


def _apply_openvpn_settings(name: str, instance: dict, ldap_config: dict | None) -> None:
    data = _data_dir(name)
    conf_path = data / "server.conf"
    if conf_path.is_file():
        conf = conf_path.read_text()
        # Drop any prior managed block and the pushes we now own, then re-add.
        conf = re.sub(re.escape(_OVPN_SETTINGS_BEGIN) + r".*?" + re.escape(_OVPN_SETTINGS_END) + r"\n?", "", conf, flags=re.S)
        conf = re.sub(r'(?m)^push "(redirect-gateway|dhcp-option DNS|route |block-outside-dns).*\n?', "", conf)
        conf = conf.rstrip() + "\n" + _openvpn_settings_block(_instance_settings(instance))
        conf_path.write_text(conf)
    if ldap_config is not None and instance["auth_mode"] == "ldap":
        _write_ldap_conf(data / "auth-ldap.conf", ldap_config)
    _restart_if_running(name)


# --- User enable / disable ---------------------------------------------------

def set_user_enabled(name: str, username: str, enabled: bool) -> None:
    """Toggle a user's access without deleting them. WireGuard comments the
    peer out of the live config; OpenVPN uses a client-config-dir 'disable'
    (reversible, unlike a certificate revocation)."""
    if not USER_RE.match(username or ""):
        raise VpnError("Invalid user name.")
    instance = _get_instance(name)
    match = next((u for u in list_users(name, instance["vpn_type"]) if u["name"] == username), None)
    if match is None:
        raise VpnError(f"No such user '{username}'.")
    if instance["vpn_type"] == "openvpn" and match["status"] == "revoked":
        raise VpnError("A revoked user can't be re-enabled — create a new user instead.")
    if instance["vpn_type"] == "wireguard":
        _wg_set_peer_enabled(name, username, enabled)
    else:
        _openvpn_set_user_enabled(name, username, enabled)
    _restart_if_running(name)


def _wg_set_peer_enabled(name: str, username: str, enabled: bool) -> None:
    conf_path = _wg_conf_path(name)
    begin, end = f"{_PEER_BEGIN}{username}".strip(), f"{_PEER_END}{username}".strip()
    out: list[str] = []
    in_block = found = False
    for line in conf_path.read_text().splitlines():
        stripped = line.strip()
        if stripped == begin:
            in_block = found = True
            out.append(line)
        elif in_block and stripped == end:
            in_block = False
            out.append(line)
        elif in_block:
            if enabled:
                out.append(line[len(_OFF):] if line.startswith(_OFF) else line)
            else:
                out.append(line if (not line.strip() or line.startswith(_OFF)) else _OFF + line)
        else:
            out.append(line)
    if not found:
        raise VpnError(f"No such peer '{username}'.")
    conf_path.write_text("\n".join(out).rstrip("\n") + "\n")


def _openvpn_set_user_enabled(name: str, username: str, enabled: bool) -> None:
    ccd_dir = _data_dir(name) / "ccd"
    ccd_dir.mkdir(exist_ok=True)
    ccd_file = ccd_dir / username
    if enabled:
        ccd_file.unlink(missing_ok=True)
    else:
        ccd_file.write_text("disable\n")
    # Must stay readable by the server container's (differently-mapped) root.
    try:
        ccd_dir.chmod(0o777)
        if ccd_file.exists():
            ccd_file.chmod(0o644)
    except OSError:
        pass


def user_config(name: str, username: str) -> tuple[str, str]:
    """-> (filename, content) of the client's config for download."""
    if not USER_RE.match(username or ""):
        raise VpnError("Invalid user name.")
    instance = _get_instance(name)
    ext = "ovpn" if instance["vpn_type"] == "openvpn" else "conf"
    path = _data_dir(name) / "clients" / f"{username}.{ext}"
    if not path.is_file():
        raise VpnError(f"No client config for '{username}'.")
    return f"{name}-{username}.{ext}", path.read_text()


# --- Live status / network stats ---------------------------------------------

def _docker_run_host(image: str, script: str, *, net_admin: bool = False) -> tuple[bool, str]:
    """One-off `bash -c <script>` with host networking — needed to read live
    WireGuard state, since with host networking the wg<id> interface lives in
    the host's network namespace, not the server container's."""
    cmd = ["docker", "run", "--rm", "--network", "host", "--entrypoint", "bash"]
    if net_admin:
        cmd += ["--cap-add", "NET_ADMIN"]
    cmd += [image, "-c", script]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=_RUN_TIMEOUT_SECONDS, shell=False)
    except FileNotFoundError:
        return False, "docker CLI is not available in this environment."
    except subprocess.TimeoutExpired:
        return False, f"Timed out after {_RUN_TIMEOUT_SECONDS}s."
    if result.returncode != 0:
        return False, (result.stderr or result.stdout or "").strip()
    return True, (result.stdout or "").strip()


def instance_status(name: str) -> dict:
    """Live runtime status for one instance: running state, uptime, and the
    list of currently connected users with per-user network stats."""
    instance = _get_instance(name)
    inspected = _docker_inspect([_container_name(name)])
    state = inspected[0].get("State", {}) if inspected else {}
    running = bool(state.get("Running"))
    result = {
        "name": name,
        "vpn_type": instance["vpn_type"],
        "running": running,
        "uptime_seconds": _uptime_seconds(state.get("StartedAt", "")) if running else None,
        "total_users": len(list_users(name, instance["vpn_type"])),
        "connected": [],
    }
    if not running:
        return result
    try:
        if instance["vpn_type"] == "wireguard":
            result["connected"] = _wireguard_status(name, instance)
        else:
            result["connected"] = _openvpn_status(name)
    except VpnError:
        pass
    return result


def _wireguard_peer_pubkeys(name: str) -> dict[str, str]:
    """Map each peer's public key -> username, from the server config's peer
    blocks, so live `wg show` output (keyed by public key) can be labelled."""
    try:
        conf = _wg_conf_path(name).read_text()
    except VpnError:
        return {}
    mapping: dict[str, str] = {}
    current: str | None = None
    for line in conf.splitlines():
        stripped = line.strip()
        if stripped.startswith(_PEER_BEGIN):
            current = stripped[len(_PEER_BEGIN):].strip()
        elif stripped.startswith(_PEER_END):
            current = None
        elif current and stripped.startswith("PublicKey"):
            mapping[stripped.split("=", 1)[1].strip()] = current
    return mapping


def _wireguard_status(name: str, instance: dict) -> list[dict]:
    iface = _wg_iface(instance["id"])
    ok, out = _docker_run_host("opensmart/wireguard", f"wg show {iface} dump 2>/dev/null || true", net_admin=True)
    if not ok or not out:
        return []
    pub_to_user = _wireguard_peer_pubkeys(name)
    peers: list[dict] = []
    # `wg show <iface> dump`: first line is the interface itself; the rest are
    # peers: pubkey, psk, endpoint, allowed-ips, latest-handshake(unix),
    # rx-bytes, tx-bytes, keepalive (tab-separated).
    for line in out.splitlines()[1:]:
        f = line.split("\t")
        if len(f) < 8:
            continue
        handshake = int(f[4]) if f[4].isdigit() else 0
        peers.append({
            "name": pub_to_user.get(f[0], f[0][:10] + "…"),
            "endpoint": "" if f[2] in ("(none)", "") else f[2],
            "allowed_ips": f[3],
            "last_handshake": handshake,
            "rx_bytes": int(f[5]) if f[5].isdigit() else 0,
            "tx_bytes": int(f[6]) if f[6].isdigit() else 0,
            # A peer is "connected" if it handshook within the last ~3 minutes.
            "online": handshake > 0 and (datetime.now(timezone.utc).timestamp() - handshake) < 180,
        })
    return peers


def _openvpn_status(name: str) -> list[dict]:
    status_file = _data_dir(name) / _OPENVPN_STATUS_FILE
    try:
        text = status_file.read_text()
    except OSError:
        return []
    clients: list[dict] = []
    for line in text.splitlines():
        f = line.split(",")
        # status-version 2 CLIENT_LIST row: CLIENT_LIST, Common Name, Real
        # Address, Virtual Address, Virtual IPv6, Bytes Received, Bytes Sent,
        # Connected Since, Connected Since (t), Username, ...
        if f[0] != "CLIENT_LIST" or len(f) < 9:
            continue
        clients.append({
            "name": f[1],
            "endpoint": f[2],
            "allowed_ips": f[3],
            "rx_bytes": int(f[5]) if f[5].isdigit() else 0,
            "tx_bytes": int(f[6]) if f[6].isdigit() else 0,
            "last_handshake": int(f[8]) if f[8].isdigit() else 0,
            "online": True,
        })
    return clients


def instance_logs(name: str, tail: int = 200) -> str:
    """Recent server logs (connection/handshake events) for one instance."""
    _get_instance(name)
    tail = max(1, min(tail, 2000))
    try:
        result = subprocess.run(
            ["docker", "logs", "--tail", str(tail), _container_name(name)],
            capture_output=True, text=True, timeout=30, shell=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""
    # OpenVPN/WireGuard write to both streams; interleave chronologically-ish.
    return ((result.stdout or "") + (result.stderr or "")).strip()

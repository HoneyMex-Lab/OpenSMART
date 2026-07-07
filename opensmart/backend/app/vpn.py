"""VPN instance manager: OpenVPN/WireGuard servers as generated compose
projects under containers/run/vpn/<name>/, each publishing its own host
port. Key/cert material is produced by one-off containers run through the
docker-socket-proxy (EXEC is blocked, but CONTAINERS+POST one-off runs are
allowed, same pattern as provisioning.host_interfaces()); everything else
is plain file work on the bind-mounted volumes, which the backend sees at
host-parity paths (OPENSMART_PROJECT_DIR).
"""
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

# In-container service ports are fixed; the instance's host port maps to them.
_OPENVPN_SERVICE_PORT = 1194
_WIREGUARD_SERVICE_PORT = 51820

_RUN_TIMEOUT_SECONDS = 180
_SUBNET_LOW, _SUBNET_HIGH = 60, 250  # 10.<n>.0.0/24 pool for instances

_PEER_BEGIN = "# BEGIN peer "
_PEER_END = "# END peer "


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


def _write_compose(name: str, vpn_type: str, port: int) -> None:
    container = _container_name(name)
    if vpn_type == "openvpn":
        service = f"""services:
  vpn:
    image: opensmart/openvpn
    container_name: {container}
    hostname: vpn-{name}
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    command: ["-c", "mkdir -p /data/log && exec openvpn --config /data/server.conf"]
    volumes:
      - ./volumes/data:/data
    ports:
      - "{port}:{_OPENVPN_SERVICE_PORT}/udp"
    networks:
      - opensmart
    restart: unless-stopped
"""
    else:
        service = f"""services:
  vpn:
    image: opensmart/wireguard
    container_name: {container}
    hostname: vpn-{name}
    cap_add:
      - NET_ADMIN
    sysctls:
      - net.ipv4.ip_forward=1
      - net.ipv4.conf.all.src_valid_mark=1
    volumes:
      - ./volumes/data:/data
    ports:
      - "{port}:{_WIREGUARD_SERVICE_PORT}/udp"
    networks:
      - opensmart
    restart: unless-stopped
"""
    compose = (
        "# Generated by OpenSMART's VPN module (backend/app/vpn.py) — edits here\n"
        "# are overwritten when the instance is recreated. The opensmart/openvpn\n"
        "# and opensmart/wireguard images are built host-side by opensmart.sh.\n"
        + service
        + """networks:
  opensmart:
    external: true
    name: opensmart
"""
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
    if auth_mode == "ldap":
        conf += (
            "\n# LDAP / Samba AD authentication (auth_mode=ldap)\n"
            "verify-client-cert optional\n"
            "plugin /usr/lib/openvpn/openvpn-auth-ldap.so /data/auth-ldap.conf\n"
        )
        _write_ldap_conf(data / "auth-ldap.conf", ldap_config)
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


def _init_wireguard(name: str, subnet: str) -> None:
    data = _data_dir(name)
    data.mkdir(parents=True, exist_ok=True)
    data.chmod(0o777)  # the wireguard container's root is a different host UID
    private_key, public_key = _wg_keypair(data)
    for filename, key in (("server_private.key", private_key), ("server_public.key", public_key)):
        path = data / filename
        path.write_text(key + "\n")
        path.chmod(0o600)
    base = _subnet_base(subnet)
    conf = data / "wg0.conf"
    conf.write_text(
        "[Interface]\n"
        f"Address = {base}.1/24\n"
        f"ListenPort = {_WIREGUARD_SERVICE_PORT}\n"
        f"PrivateKey = {private_key}\n"
        "PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE\n"
        "PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE\n"
    )
    # Must stay readable by the wireguard container's (differently-mapped)
    # root. The host-side directory tree above it is root-only.
    conf.chmod(0o644)


def list_instances() -> list[dict]:
    with get_db() as db:
        rows = db.execute("SELECT * FROM vpn_instances ORDER BY name").fetchall()
    instances = [dict(row) for row in rows]
    inspected = {i["Name"].lstrip("/"): i for i in _docker_inspect([_container_name(r["name"]) for r in instances])} if instances else {}
    for instance in instances:
        instance.pop("ldap_config", None)  # may hold a bind password
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


def create_instance(name: str, vpn_type: str, port: int, auth_mode: str = "certs", ldap_config: dict | None = None) -> dict:
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
    with get_db() as db:
        existing = db.execute("SELECT 1 FROM vpn_instances WHERE name = ? OR port = ?", (name, port)).fetchone()
        if existing:
            raise VpnError("An instance with that name or port already exists.")
        subnet = _allocate_subnet(db)
        db.execute(
            "INSERT INTO vpn_instances (name, vpn_type, port, subnet, auth_mode, ldap_config, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (name, vpn_type, port, subnet, auth_mode, json.dumps(ldap_config), _now()),
        )
        db.commit()
    try:
        _write_compose(name, vpn_type, port)
        if vpn_type == "openvpn":
            _init_openvpn(name, subnet, port, auth_mode, ldap_config)
        else:
            _init_wireguard(name, subnet)
    except Exception:
        # Roll back the registration so a failed init can be retried cleanly.
        with get_db() as db:
            db.execute("DELETE FROM vpn_instances WHERE name = ?", (name,))
            db.commit()
        shutil.rmtree(_instance_dir(name), ignore_errors=True)
        raise
    return _get_instance(name)


def delete_instance(name: str) -> None:
    instance = _get_instance(name)
    _compose(instance["name"], "down")
    shutil.rmtree(_instance_dir(name), ignore_errors=True)
    with get_db() as db:
        db.execute("DELETE FROM vpn_instances WHERE name = ?", (name,))
        db.commit()


def start_instance(name: str) -> tuple[bool, str]:
    _get_instance(name)
    return _compose(name, "up", "-d")


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
        users.append({
            "name": common_name,
            "status": {"V": "valid", "R": "revoked", "E": "expired"}.get(status, status),
            "expires_at": _parse_index_ts(expiry),
            "has_config": (_data_dir(name) / "clients" / f"{common_name}.ovpn").is_file(),
        })
    return users


def _parse_index_ts(raw: str) -> str:
    # easy-rsa index.txt timestamps: YYMMDDHHMMSSZ
    match = re.match(r"^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$", raw)
    if not match:
        return ""
    yy, mm, dd, hh, mi, ss = match.groups()
    return f"20{yy}-{mm}-{dd}T{hh}:{mi}:{ss}+00:00"


def _wireguard_peers(name: str) -> list[dict]:
    conf = _data_dir(name) / "wg0.conf"
    if not conf.is_file():
        return []
    peers = []
    for line in conf.read_text().splitlines():
        if line.startswith(_PEER_BEGIN):
            peer = line[len(_PEER_BEGIN):].strip()
            peers.append({
                "name": peer,
                "status": "valid",
                "expires_at": "",
                "has_config": (_data_dir(name) / "clients" / f"{peer}.conf").is_file(),
            })
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
    conf_path = data / "wg0.conf"
    if not conf_path.is_file():
        raise VpnError("Instance not initialized (missing wg0.conf).")
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
    client_conf = clients / f"{username}.conf"
    client_conf.write_text(
        "[Interface]\n"
        f"PrivateKey = {client_private}\n"
        f"Address = {base}.{host_id}/32\n"
        "DNS = 1.1.1.1\n\n"
        "[Peer]\n"
        f"PublicKey = {server_public}\n"
        f"Endpoint = {server_host}:{instance['port']}\n"
        "AllowedIPs = 0.0.0.0/0\n"
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
        conf_path = _data_dir(name) / "wg0.conf"
        if not conf_path.is_file():
            raise VpnError("Instance not initialized (missing wg0.conf).")
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

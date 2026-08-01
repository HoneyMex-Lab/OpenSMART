"""Starts/stops the per-tool sibling containers under containers/run/ via
`docker compose`, talking to the host Docker daemon through the
docker-socket-proxy sidecar (DOCKER_HOST is set in
containers/run/opensmart/docker-compose.yml) — this process never touches
docker.sock directly.
"""
import json
import logging
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from .config import PROJECT_ROOT

logger = logging.getLogger(__name__)

CONTAINERS_ROOT = PROJECT_ROOT / "containers" / "run"

# Compose projects that actually exist under containers/run/ today.
KNOWN_CONTAINERS = frozenset({"suricata", "zeek", "arkime", "opensearch", "wireguard", "openvpn", "wazuh", "nginx"})

# Provisioning X should provision these first (shared infrastructure).
CONTAINER_DEPENDENCIES: dict[str, list[str]] = {
    "arkime": ["opensearch"],
}

# Containers whose service is gated behind a compose profile not activated
# by default. openvpn's docker-compose.yml keeps it out of a bare
# `docker compose up` (see that file's own header comment: no /dev/net/tun
# on this environment's host) — without passing this along, `up`/`down`/`ps`
# would silently no-op on it instead of actually starting, stopping, or
# checking it.
CONTAINER_PROFILES: dict[str, str] = {
    "openvpn": "manual",
}

# Compose project -> the actual container_name(s) its services create.
# Needed because status has to be read per-container via `docker inspect`
# (the docker-socket-proxy blocks EXEC, so container state is the richest
# signal available), and several projects run more than one container.
CONTAINER_SERVICES: dict[str, list[str]] = {
    "suricata": ["opensmart-suricata"],
    "zeek": ["opensmart-zeek"],
    "arkime": ["opensmart-arkime-capture", "opensmart-arkime-viewer", "opensmart-arkime-viewer-redirect"],
    "opensearch": ["opensmart-opensearch"],
    "wireguard": ["opensmart-wireguard"],
    "openvpn": ["opensmart-openvpn"],
    "wazuh": ["opensmart-wazuh-manager", "opensmart-wazuh-indexer", "opensmart-wazuh-dashboard"],
    "nginx": ["opensmart-nginx"],
}

# OpenSMART module name -> required container(s), or None if no container
# template exists for it yet (reported to the caller, not silently skipped).
MODULE_CONTAINERS: dict[str, list[str] | None] = {
    "Threat Detection Alerts": ["wazuh"],
    "Network Traffic Monitoring": ["suricata", "zeek"],
    "Network IDS": ["suricata"],
    "Endpoint": ["wazuh"],
    "Vulnerability Management": ["wazuh"],
    "Honeypot": None,  # T-Pot, not supported yet
    "Access VPN": ["openvpn", "wireguard"],
    "LXC Manager": None,  # not supported yet
    # Empty list, not None: real and supported, but enforced by the kernel via
    # one-off `nft`/`docker run --network host` calls (see firewall.py), not by
    # a long-running compose container — so there's nothing to start/stop.
    "Firewall": [],
}

# Tool name -> required container(s), or None if not applicable.
TOOL_CONTAINERS: dict[str, list[str] | None] = {
    "Arkime": ["arkime"],
    "OPNsense": None,  # link-only, not an installable container
    "Proxmox": None,  # link-only, not an installable container
    "Wazuh": ["wazuh"],
    "Graylog": None,  # no container template yet
}

_COMPOSE_TIMEOUT_SECONDS = 300

# wazuh.manager/.indexer/.dashboard mount their mutual-TLS material from
# here; it's produced by the profile-gated wazuh-certs-generator one-off
# service (see that compose file's header comment), which has to run
# successfully exactly once before the three real services can start.
# admin.pem is the last file that generator writes, so its presence is a
# reasonable "certs are ready" marker.
_WAZUH_CERTS_MARKER = CONTAINERS_ROOT / "wazuh" / "volumes" / "data" / "wazuh_indexer_ssl_certs" / "admin.pem"


def _fix_wazuh_certs_permissions() -> None:
    """The certs-generator one-off container's root maps to a different
    host UID than the backend (same unprivileged-nesting issue as arkime's
    init-data-dir and vpn.py's OpenVPN/WireGuard chmod fixes), so its
    output is created unreadable here (observed: dir mode 700, file mode
    400/440, various owning UIDs) without this."""
    try:
        subprocess.run(
            ["docker", "run", "--rm", "-v", f"{_WAZUH_CERTS_MARKER.parent}:/certs", "busybox", "chmod", "-R", "a+rX", "/certs"],
            capture_output=True,
            text=True,
            timeout=60,
            shell=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as error:
        logger.warning("wazuh certs permission fix failed: %s", error)


def _ensure_wazuh_certs() -> tuple[bool, str]:
    try:
        ready = _WAZUH_CERTS_MARKER.is_file()
    except PermissionError:
        # Certs from a prior run, unreadable due to the UID mapping above —
        # fix permissions in place rather than regenerating.
        _fix_wazuh_certs_permissions()
        try:
            ready = _WAZUH_CERTS_MARKER.is_file()
        except PermissionError:
            ready = False
    if ready:
        return True, ""
    ok, detail = _run_compose("wazuh", "--profile", "certs", "run", "--rm", "wazuh-certs-generator")
    if ok:
        _fix_wazuh_certs_permissions()
    return ok, detail


def _compose_path(container: str) -> Path:
    if container not in KNOWN_CONTAINERS:
        raise ValueError(f"Unknown container '{container}'")
    return CONTAINERS_ROOT / container / "docker-compose.yml"


def _run_compose(container: str, *args: str, extra_env: dict[str, str] | None = None) -> tuple[bool, str]:
    path = _compose_path(container)
    if not path.is_file():
        return False, f"No docker-compose.yml found for '{container}' at {path}"
    profile = CONTAINER_PROFILES.get(container)
    profile_args = ["--profile", profile] if profile else []
    env = {**os.environ, **extra_env} if extra_env else None
    try:
        result = subprocess.run(
            ["docker", "compose", "-f", str(path), *profile_args, *args],
            cwd=str(path.parent),
            capture_output=True,
            text=True,
            timeout=_COMPOSE_TIMEOUT_SECONDS,
            shell=False,
            env=env,
        )
    except FileNotFoundError:
        return False, "docker CLI is not available in this environment."
    except subprocess.TimeoutExpired:
        return False, f"Timed out after {_COMPOSE_TIMEOUT_SECONDS}s."
    output = (result.stderr or result.stdout or "").strip()
    if result.returncode != 0:
        logger.warning("docker compose %s failed for %s: %s", args, container, output[:2000])
        return False, output[-2000:]
    return True, output[-2000:]


def _setting(key: str) -> str:
    from .database import get_db
    with get_db() as db:
        row = db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return (row["value"] if row else "").strip()


def _monitor_interfaces_env() -> dict[str, str]:
    """CAPTURE_IFACES for the suricata compose file. Prefers the
    network_interfaces registry (monitor=1 rows); falls back to the legacy
    monitor_interfaces setting for installs that haven't populated the
    registry yet. Falls back to eth0 via the compose file's own default when
    both are unset."""
    from . import network_config
    names = network_config.monitor_names()
    value = ",".join(names) if names else _setting("monitor_interfaces").strip(",")
    return {"CAPTURE_IFACES": value} if value else {}


_NGINX_ENV_FILE = CONTAINERS_ROOT / "nginx" / ".env"


def _set_env_kv(file: Path, key: str, value: str) -> None:
    """Update-or-append KEY=VALUE in an env file without touching other
    keys. Python mirror of opensmart.sh's own _set_env_kv — used so both
    sides agree on the same persisted value (see _proxy_hostname_env)."""
    file.parent.mkdir(parents=True, exist_ok=True)
    lines = file.read_text().splitlines() if file.is_file() else []
    prefix = f"{key}="
    new_line = f"{key}={value}"
    for i, line in enumerate(lines):
        if line.startswith(prefix):
            lines[i] = new_line
            break
    else:
        lines.append(new_line)
    file.write_text("\n".join(lines) + "\n")


def _proxy_hostname_env() -> dict[str, str]:
    """OPENSMART_HOSTNAME for the nginx front-door, from the proxy_hostname
    setting (chosen in the Wizard's Basics step). Drives the proxy's
    server_name and the self-signed certificate SAN — the compose file's
    init-certs one-off re-issues the certificate when it changes.

    Also PERSISTS the value into the proxy's own .env (not just passed as a
    transient subprocess env var) — confirmed live: without this, this
    function's value and opensmart.sh's own bare `docker compose up -d`
    (which never passes this override, e.g. from _start_front_proxy on
    `start`/`recreate`) disagreed about the "current" OPENSMART_HOSTNAME,
    so Docker Compose detected a config diff and RECREATED nginx on every
    single call that alternated between the two paths — self-referentially
    killing whatever request was itself proxied through nginx, which is
    exactly what the Wizard's own provisioning request is (nginx is both
    the target being provisioned and the transport carrying the request
    that provisions it). Persisting here makes both paths converge on the
    same value, so nginx only actually recreates when the hostname
    genuinely changes."""
    value = _setting("proxy_hostname")
    # The value is expanded by a shell inside the init-certs one-off (cert
    # subject/SAN), so only RFC-hostname characters may pass — anything else
    # is dropped, falling back to the compose default.
    if not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", value or ""):
        return {}
    try:
        _set_env_kv(_NGINX_ENV_FILE, "OPENSMART_HOSTNAME", value)
    except OSError as error:
        logger.warning("failed to persist OPENSMART_HOSTNAME into %s: %s", _NGINX_ENV_FILE, error)
    return {"OPENSMART_HOSTNAME": value}


# ── Pending admin password (bootstraps tool credential sync) ─────────────────
#
# Passwords are only ever stored as Argon2 hashes — by design, this process
# can never recover the plaintext of a password after the change request
# that set it has completed. The tool-credential sync (sync_arkime_password/
# sync_wazuh_password below) therefore can only ever run at the MOMENT of a
# password change, using the plaintext from that one request.
#
# That collides with how a fresh install actually unfolds: the forced
# first-login password change happens BEFORE the Wizard has provisioned
# anything, so the very first sync attempt (fired immediately on that
# change, see routes/account.py) has no Arkime/Wazuh admin user to sync
# against yet — it silently no-ops. The tool then gets provisioned later,
# via the Wizard's Provision step, using its own default password, and
# stays there until some LATER, unrelated password change happens to catch
# it already provisioned. Confirmed as the actual reported bug: "not
# updated until another password change."
#
# Since the plaintext can't be recovered after the fact, the fix is to
# briefly remember it: cache in process memory only (never written to
# disk/DB/logs, never returned by any API), for a bounded window, and apply
# it retroactively the moment a tool that needed it gets provisioned. This
# doesn't worsen the threat model — the plaintext already transits this
# process on every login/password-change request regardless — it just
# extends how long it survives in memory, bounded by the TTL below.
_PENDING_ADMIN_PASSWORD: tuple[float, str] | None = None
_PENDING_ADMIN_PASSWORD_TTL_SECONDS = 1800  # long enough to cover a full Wizard run


def remember_admin_password(password: str) -> None:
    """Call this whenever an admin's password changes (see
    routes/account.py) so a tool provisioned shortly after — even in a
    later, separate request — can still be synced to it once."""
    global _PENDING_ADMIN_PASSWORD
    _PENDING_ADMIN_PASSWORD = (time.time(), password)


def _pending_admin_password() -> str | None:
    """Read-only peek (not consumed/cleared on read) so multiple tools
    provisioned within the same Wizard run can all pick up the same
    recently-changed password, not just the first one."""
    if _PENDING_ADMIN_PASSWORD is None:
        return None
    changed_at, password = _PENDING_ADMIN_PASSWORD
    if time.time() - changed_at > _PENDING_ADMIN_PASSWORD_TTL_SECONDS:
        return None
    return password


def _sync_pending_password(container: str) -> None:
    """Apply a cached pending admin password to a tool right after it is
    provisioned. Only used for Wazuh — Arkime is handled deterministically at
    `up -d` time via .env + its init-admin-user one-off (see
    _arkime_admin_password_env), which is immune to the provision-time race
    this post-hoc sync would otherwise lose on a fresh install."""
    password = _pending_admin_password()
    if not password:
        return
    if container == "wazuh":
        ok, detail = sync_wazuh_password(password)
    else:
        return
    if not ok:
        logger.warning("pending admin password sync to %s failed: %s", container, detail[:300])


def start_container(container: str) -> tuple[bool, str]:
    for dependency in CONTAINER_DEPENDENCIES.get(container, []):
        ok, detail = _run_compose(dependency, "up", "-d")
        if not ok:
            return False, f"Dependency '{dependency}' failed: {detail}"
    if container == "wazuh":
        ok, detail = _ensure_wazuh_certs()
        if not ok:
            return False, f"Certificate generation failed: {detail}"
    extra_env = None
    if container == "suricata":
        extra_env = _monitor_interfaces_env()
    elif container == "nginx":
        extra_env = _proxy_hostname_env()
    elif container == "arkime":
        # Seed ARKIME_ADMIN_PASSWORD into .env before `up -d` so the compose's
        # own init-admin-user applies the pending admin password directly — no
        # race against a post-provision single-shot sync (see the helper).
        extra_env = _arkime_admin_password_env()
    ok, detail = _run_compose(container, "up", "-d", extra_env=extra_env)
    # Wazuh's admin password lives in a bcrypt hash baked into internal_users.yml
    # at provision time, not in an env var, so a fresh provision always comes up
    # on the vendored default — it needs an explicit post-provision sync. Arkime
    # is handled deterministically above via .env + init-admin-user instead.
    if ok and container == "wazuh":
        _sync_pending_password(container)
    return ok, detail


def stop_container(container: str) -> tuple[bool, str]:
    return _run_compose(container, "down")


def restart_container(container: str) -> tuple[bool, str]:
    return _run_compose(container, "restart")


def _docker_inspect(names: list[str]) -> list[dict]:
    """Raw `docker inspect` for the given container names. Missing containers
    are simply absent from the result (inspect exits non-zero for them, but
    still prints JSON for the ones it found)."""
    try:
        result = subprocess.run(
            ["docker", "inspect", *names],
            capture_output=True,
            text=True,
            timeout=30,
            shell=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    try:
        return json.loads(result.stdout or "[]")
    except json.JSONDecodeError:
        return []


def _uptime_seconds(started_at: str) -> int | None:
    # Docker timestamps carry nanosecond precision Python can't parse;
    # truncate to microseconds.
    match = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?\d*(Z|[+-]\d{2}:\d{2})?", started_at)
    if not match:
        return None
    stamp = match.group(1) + ("." + match.group(2) if match.group(2) else "") + "+00:00"
    try:
        started = datetime.fromisoformat(stamp)
    except ValueError:
        return None
    return max(0, int((datetime.now(timezone.utc) - started).total_seconds()))


def container_overview() -> list[dict]:
    """Per-container detail for every known compose project: running state,
    image version, uptime, restart count, health, and derived warnings."""
    overview: list[dict] = []
    for project in sorted(KNOWN_CONTAINERS):
        names = CONTAINER_SERVICES.get(project, [])
        inspected = {c.get("Name", "").lstrip("/"): c for c in _docker_inspect(names)}
        containers = []
        for name in names:
            data = inspected.get(name)
            if data is None:
                containers.append({"name": name, "exists": False, "status": "not-created"})
                continue
            state = data.get("State", {})
            status = state.get("Status", "unknown")
            restart_count = data.get("RestartCount", 0)
            image = data.get("Config", {}).get("Image", "")
            uptime = _uptime_seconds(state.get("StartedAt", "")) if status == "running" else None
            health = (state.get("Health") or {}).get("Status", "")
            warnings = []
            if status == "restarting":
                warnings.append("Container is stuck restarting — check its logs.")
            if status == "running" and restart_count > 3:
                warnings.append(f"Restarted {restart_count} times since creation.")
            if state.get("OOMKilled"):
                warnings.append("Killed by the kernel OOM killer at least once.")
            if health and health not in ("healthy", "none"):
                warnings.append(f"Health check reports: {health}.")
            if state.get("ExitCode", 0) != 0 and status == "exited":
                warnings.append(f"Exited with code {state.get('ExitCode')}.")
            # The Wazuh dashboard can be "running" yet serve a persistent HTTP
            # 500 (see the auto-healer); surface that app-level assessment here
            # since no Docker-level signal reflects it.
            if name == _WAZUH_DASHBOARD_CONTAINER and _WAZUH_HEALTH["assessment"]:
                warnings.append(_WAZUH_HEALTH["assessment"])
            containers.append({
                "name": name,
                "exists": True,
                "status": status,
                "image": image,
                "uptime_seconds": uptime,
                "restart_count": restart_count,
                "health": health or None,
                "warnings": warnings,
            })
        running = sum(1 for c in containers if c.get("status") == "running")
        overview.append({
            "project": project,
            "containers": containers,
            "running": running,
            "total": len(names),
            "profile": CONTAINER_PROFILES.get(project),
        })
    return overview


# ── Host network interfaces ───────────────────────────────────────────────────
#
# This process runs on a bridge network, so its own netns only has eth0/lo —
# the host's capture-capable NICs (span/mirror ports) are invisible to it.
# Enumerate them by running a one-off busybox container with host networking
# through the docker-socket-proxy (CONTAINERS+POST are allowlisted; EXEC
# stays blocked — this creates a new container rather than entering one).

_HOST_IFACES_CACHE: tuple[float, list[dict]] = (0.0, [])
_HOST_IFACES_TTL_SECONDS = 60


_ADDR_MARKER = "===OPENSMART_ADDR==="


def host_interfaces(force: bool = False) -> list[dict]:
    global _HOST_IFACES_CACHE
    cached_at, cached = _HOST_IFACES_CACHE
    if not force and cached and time.time() - cached_at < _HOST_IFACES_TTL_SECONDS:
        return cached
    try:
        result = subprocess.run(
            [
                "docker", "run", "--rm", "--network", "host", "busybox", "sh", "-c",
                f"ip -o link show; echo {_ADDR_MARKER}; ip -o addr show",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            shell=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return cached
    if result.returncode != 0:
        logger.warning("host interface enumeration failed: %s", (result.stderr or "")[:500])
        return cached
    link_output, _, addr_output = result.stdout.partition(_ADDR_MARKER)
    interfaces: list[dict] = []
    by_name: dict[str, dict] = {}
    # busybox `ip -o link show` lines: "2: eth0: <BROADCAST,MULTICAST,UP,...> mtu 1300 ... link/ether aa:bb:cc:dd:ee:ff ..."
    for line in link_output.splitlines():
        match = re.match(r"\d+:\s+([^:@]+)(?:@\S+)?:\s+<([^>]*)>\s+mtu\s+(\d+)", line)
        if not match:
            continue
        name, flags, mtu = match.group(1).strip(), match.group(2).split(","), int(match.group(3))
        if name == "lo":
            continue
        mac_match = re.search(r"link/ether\s+(\S+)", line)
        entry = {
            "name": name,
            "up": "UP" in flags,
            "mtu": mtu,
            "mac": mac_match.group(1) if mac_match else "",
            # veth/br/docker interfaces are usually container plumbing, not
            # span/mirror candidates — flagged so the UI can de-emphasize them.
            "virtual": bool(re.match(r"^(veth|br-|docker|virbr|tap|tun|wg)", name)),
            "addresses": [],
        }
        interfaces.append(entry)
        by_name[name] = entry
    # busybox `ip -o addr show` lines: "2: eth0    inet 192.168.1.5/24 brd ... scope global eth0"
    for line in addr_output.splitlines():
        match = re.match(r"\d+:\s+(\S+)\s+(inet6?)\s+(\S+)", line)
        if not match:
            continue
        name, family, address = match.groups()
        entry = by_name.get(name)
        if entry is not None:
            entry["addresses"].append({"family": "inet6" if family == "inet6" else "inet", "address": address})
    if interfaces:
        _HOST_IFACES_CACHE = (time.time(), interfaces)
    return interfaces


# ── Host resource capability (set at install time) ────────────────────────────
#
# The numbers here are not measured live by this process — they were
# detected once by opensmart.sh's _install_check_host_resources at install
# time and written into this container's environment (see that function's
# comment for the full "why", kept in sync with these by hand). Re-run
# `sudo ./opensmart.sh install` after resizing the host to refresh them.

# Same two tiers as opensmart.sh's _install_check_host_resources — shown to
# the operator so the numbers driving the Wizard's warning are visible, not
# just the pre-computed verdict.
HOST_RESOURCE_TIERS = {
    "core": {"cpu": 2, "memory_mb": 3800, "disk_gb": 9},
    "full": {"cpu": 4, "memory_mb": 7500, "disk_gb": 18},
}


def host_resources() -> dict:
    from . import config
    return {
        "cpu_count": config.RESOURCE_CPU,
        "memory_total_mb": config.RESOURCE_MEM_MB,
        "disk_free_gb": config.RESOURCE_DISK_GB,
        "tier": config.RESOURCE_TIER,
        "constrained_tools": list(config.RESOURCE_CONSTRAINED_TOOLS),
        "constrained_modules": list(config.RESOURCE_CONSTRAINED_MODULES),
        "recommended_tiers": HOST_RESOURCE_TIERS,
    }


# ── Arkime admin password sync ────────────────────────────────────────────────

_ARKIME_IMAGE = "ghcr.io/arkime/arkime/arkime:v6-latest"
_ARKIME_CONFIG = CONTAINERS_ROOT / "arkime" / "etc" / "config.ini"
_ARKIME_ENV_FILE = CONTAINERS_ROOT / "arkime" / ".env"

# Arkime's own name for this theme value is "Green on Black" (see the theme
# list in the viewer bundle). addUser.js replaces the whole user document, so
# both this sync and the compose init-admin-user reset settings.theme whenever
# they run; each re-seeds the default afterwards. Painless sets it only when
# unset, so a theme the user picked in the UI survives until the admin user is
# next (re)created.
_ARKIME_DEFAULT_THEME = "dark-2-theme"
_ARKIME_THEME_UPDATE = (
    '{"script":{"lang":"painless","source":'
    '"if(ctx._source.settings==null){ctx._source.settings=[:];} '
    'if(ctx._source.settings.theme==null){ctx._source.settings.theme=params.t;}",'
    '"params":{"t":"' + _ARKIME_DEFAULT_THEME + '"}}}'
)


def _arkime_admin_password_env() -> dict[str, str]:
    """ARKIME_ADMIN_PASSWORD for the arkime compose, from the pending admin
    password if one is cached. Persists it into arkime's own .env (source of
    truth) AND returns it as a transient subprocess env override.

    This is the deterministic half of the first-install fix. Arkime's compose
    ships an init-admin-user one-off that, on every `up -d`, runs the image's
    addUser.js in a retry loop until the users index exists and sets the admin
    password from ARKIME_ADMIN_PASSWORD (default: changeme-arkime-admin). That
    retry loop reliably wins any race against a single-shot addUser fired right
    after `up -d` (the users index typically isn't ready for 15-120s on a fresh
    install), which is exactly why the old post-provision sync silently lost and
    Arkime stayed on the default until a *second*, later password change caught
    it already up. Writing the real password to .env before `up -d` makes
    init-admin-user itself apply it — both writers now converge on one value, so
    there is no race left to lose. Passing it as env too forces compose to
    recreate (re-run) init-admin-user when the password changed."""
    password = _pending_admin_password()
    if not password:
        return {}
    try:
        _set_env_kv(_ARKIME_ENV_FILE, "ARKIME_ADMIN_PASSWORD", password)
    except OSError as error:
        logger.warning("failed to persist ARKIME_ADMIN_PASSWORD into %s: %s", _ARKIME_ENV_FILE, error)
    return {"ARKIME_ADMIN_PASSWORD": password}


def sync_arkime_password(password: str, *, username: str = "admin") -> tuple[bool, str]:
    """Set Arkime's admin user password via a one-off container running the
    image's own addUser.js (upsert — updates the password when the user
    exists). Used to keep the Arkime tool credential in step with the
    OpenSMART admin password.

    First persists the password into arkime's .env as ARKIME_ADMIN_PASSWORD —
    the single source of truth the compose's init-admin-user one-off reads on
    every provision. Without this, init-admin-user would reset the admin back
    to its default password on the next `up -d`, silently undoing this sync
    (the root cause of "Arkime password not updated after first install"). The
    .env write happens even if the addUser step below fails (e.g. Arkime not
    running yet), so a later provision still applies the correct password.

    Also re-seeds the admin's default UI theme (addUser.js replaces the whole
    user document, so it wipes settings.theme) — see _ARKIME_THEME_UPDATE.

    Best-effort on the live-apply step: callers treat failure as non-fatal
    (Arkime may not be provisioned/running yet). The password is passed through
    the environment, never interpolated into the shell command, so it can't
    break quoting or inject anything.
    """
    if not _ARKIME_CONFIG.is_file():
        return False, "Arkime is not provisioned (no config.ini)."
    try:
        _set_env_kv(_ARKIME_ENV_FILE, "ARKIME_ADMIN_PASSWORD", password)
    except OSError as error:
        logger.warning("failed to persist ARKIME_ADMIN_PASSWORD into %s: %s", _ARKIME_ENV_FILE, error)
    # addUser first (must succeed for the sync to count), then best-effort
    # re-seed the default theme addUser just wiped (|| true so a theme hiccup
    # never reports the password change as failed). $0 is the username arg.
    script = (
        'cd /opt/arkime/viewer && '
        '/opt/arkime/bin/node addUser.js "$0" "OpenSMART Admin" "$ARKIME_NEW_PASSWORD" --admin && '
        '{ curl -s -XPOST "http://opensearch:9200/arkime_users/_update/$0" '
        '-H "Content-Type: application/json" -d ' + "'" + _ARKIME_THEME_UPDATE + "'" + ' || true; }'
    )
    try:
        result = subprocess.run(
            [
                "docker", "run", "--rm", "--network", "opensmart",
                "-e", "ARKIME__elasticsearch=http://opensearch:9200",
                "-e", f"ARKIME_NEW_PASSWORD={password}",
                "-v", f"{_ARKIME_CONFIG}:/opt/arkime/etc/config.ini",
                "--entrypoint", "bash",
                _ARKIME_IMAGE, "-c", script, username,
            ],
            capture_output=True,
            text=True,
            timeout=120,
            shell=False,
        )
    except FileNotFoundError:
        return False, "docker CLI is not available in this environment."
    except subprocess.TimeoutExpired:
        return False, "Timed out setting the Arkime password."
    output = (result.stderr or result.stdout or "").strip()
    if result.returncode != 0:
        logger.warning("arkime password sync failed: %s", output[:1000])
        return False, output[-1000:]
    return True, output[-1000:]


# ── Wazuh admin password sync ─────────────────────────────────────────────────

_WAZUH_INDEXER_IMAGE = "wazuh/wazuh-indexer:4.14.6"
_WAZUH_USERS_FILE = CONTAINERS_ROOT / "wazuh" / "config" / "wazuh_indexer" / "internal_users.yml"
_WAZUH_CERTS_DIR = CONTAINERS_ROOT / "wazuh" / "volumes" / "data" / "wazuh_indexer_ssl_certs"
_WAZUH_ENV_FILE = CONTAINERS_ROOT / "wazuh" / ".env"

# Wazuh ships wazuh-passwords-tool.sh for exactly this, but its "is this
# installed" check is a package-manager query (rpm -q wazuh-indexer / apt
# list --installed) that never matches this project's images — they're
# built by copying files in, not via a package manager — confirmed live:
# every invocation reports "the given user does not exist" regardless of
# username, because the code path that would populate its known-users list
# from a live query never runs without that detection succeeding. This
# replicates what the tool does under the hood instead, using the same
# image's own bundled tools: hash.sh (bcrypt, guaranteed format-compatible
# since it's the same tool the security plugin itself ships) generates the
# hash; sed patches just the admin user's hash line in the vendored
# internal_users.yml (the range between "^admin:" and the next top-level
# key "^kibanaserver:" brackets exactly one hash: line, so this is safe
# without a real YAML parser); securityadmin.sh pushes it to the live
# cluster, authenticating via the admin certificate rather than a password.
# chmod first: this directory's host-side ownership varies by how the repo
# was checked out (confirmed different across hosts in this project), and
# the container's own uid may not match — best-effort, the sed step below
# fails with a clear, caught error if it's still not writable after this.
_WAZUH_SYNC_SCRIPT = r"""
set -e
chmod -R a+rwX /work 2>/dev/null || true
export JAVA_HOME=/usr/share/wazuh-indexer/jdk
TOOLS=/usr/share/wazuh-indexer/plugins/opensearch-security/tools
HASH="$(bash "$TOOLS/hash.sh" -p "$WAZUH_NEW_PASSWORD" | tail -n1)"
sed -i '/^admin:/,/^kibanaserver:/{s|^\(\s*hash:\s*\).*|\1"'"$HASH"'"|}' /work/internal_users.yml
bash "$TOOLS/securityadmin.sh" \
  -f /work/internal_users.yml -t internalusers \
  -icl -nhnv -p 9200 -h wazuh.indexer \
  -cacert /certs/root-ca.pem -cert /certs/admin.pem -key /certs/admin-key.pem
"""


def sync_wazuh_password(password: str, *, username: str = "admin") -> tuple[bool, str]:
    """Set the Wazuh indexer's admin user password — the credential that
    actually gates human login to the Wazuh dashboard (the dashboard's own
    DASHBOARD_USERNAME/kibanaserver user is a separate, unrelated internal
    service account). See _WAZUH_SYNC_SCRIPT's comment for why this doesn't
    just shell out to Wazuh's own wazuh-passwords-tool.sh.

    Also updates WAZUH_INDEXER_PASSWORD in wazuh's own .env and recreates
    wazuh.manager/wazuh.dashboard — both authenticate to the indexer as
    this same admin user via that env var, so without refreshing them
    they'd silently lose their own indexer connection the moment this
    changes the password out from under them.

    Only username="admin" is meaningful today — that's the one user a
    human actually logs into the dashboard with; other indexer service
    accounts (kibanaserver, logstash, ...) aren't tied to any OpenSMART
    login and are left alone.

    The password is passed through the environment, never interpolated
    into the shell command or written to argv, so it can't break quoting
    or show up in `docker inspect`/process listings. Best-effort: callers
    treat failure as non-fatal (Wazuh may not be provisioned yet).
    """
    if username != "admin":
        return False, "Only the 'admin' indexer user is supported."
    if not _WAZUH_USERS_FILE.is_file() or not (_WAZUH_CERTS_DIR / "admin.pem").is_file():
        return False, "Wazuh is not provisioned yet."
    try:
        result = subprocess.run(
            [
                "docker", "run", "--rm", "--network", "opensmart",
                "-e", f"WAZUH_NEW_PASSWORD={password}",
                "-v", f"{_WAZUH_USERS_FILE.parent}:/work",
                "-v", f"{_WAZUH_CERTS_DIR}:/certs:ro",
                "--entrypoint", "bash",
                _WAZUH_INDEXER_IMAGE, "-c", _WAZUH_SYNC_SCRIPT,
            ],
            capture_output=True,
            text=True,
            timeout=120,
            shell=False,
        )
    except FileNotFoundError:
        return False, "docker CLI is not available in this environment."
    except subprocess.TimeoutExpired:
        return False, "Timed out setting the Wazuh password."
    output = (result.stderr or result.stdout or "").strip()
    if result.returncode != 0:
        logger.warning("wazuh password sync failed: %s", output[:1000])
        return False, output[-1000:]

    try:
        _set_env_kv(_WAZUH_ENV_FILE, "WAZUH_INDEXER_PASSWORD", password)
    except OSError as error:
        logger.warning("failed to persist WAZUH_INDEXER_PASSWORD into %s: %s", _WAZUH_ENV_FILE, error)
        return True, output[-1000:] + "\n(warning: manager/dashboard not refreshed — see server log)"

    ok, refresh_detail = _run_compose("wazuh", "up", "-d", "wazuh.manager", "wazuh.dashboard")
    if not ok:
        logger.warning("wazuh manager/dashboard refresh after password sync failed: %s", refresh_detail[:500])
        return True, output[-1000:] + "\n(warning: manager/dashboard refresh failed — see server log)"
    return True, output[-1000:]


# ── Wazuh dashboard auto-healing ──────────────────────────────────────────────
#
# On a first install the Wazuh dashboard frequently comes up before the indexer
# has finished initializing its security/.kibana indices, gets stuck, and serves
# a persistent HTTP 500 ("An internal server error occurred.") until it is
# restarted by hand — confirmed reproducible, and confirmed that a plain restart
# clears it once the indexer is ready. The container itself stays "running" the
# whole time (no Docker healthcheck), so container-state warnings never catch it;
# only an HTTP probe does.
#
# This runs a small background state machine (driven by main.py's loop) that
# probes the dashboard, and — only for a *sustained* 5xx well past startup —
# restarts it a bounded number of times, then stops and posts a human-readable
# assessment. State is surfaced in the Status section via container_overview().
_WAZUH_DASHBOARD_CONTAINER = "opensmart-wazuh-dashboard"
_WAZUH_DASHBOARD_URL = "https://wazuh.dashboard:5601/wazuh/api/status"
_WAZUH_INDEXER_URL = "https://wazuh.indexer:9200/"
_WAZUH_HEAL_STARTUP_GRACE_SECONDS = 150  # normal startup shows transient 000/503/500
_WAZUH_HEAL_ERROR_THRESHOLD = 2          # consecutive bad probes before healing
_WAZUH_HEAL_MAX_ATTEMPTS = 3             # restarts before giving up and assessing
_WAZUH_HEAL_BACKOFF_SECONDS = 120        # min gap between restart attempts

# Shared, read by container_overview() (any thread) and written by the heal tick.
_WAZUH_HEALTH: dict = {
    "state": "unknown",       # unknown|not-provisioned|stopped|starting|healthy|degraded|healing|unhealthy
    "http_code": None,
    "assessment": "",         # human-readable line shown in the Status section (empty = nothing to show)
    "consecutive_errors": 0,
    "heal_attempts": 0,
    "last_heal_ts": 0.0,
    "checked_at": 0.0,
}


def _probe_wazuh_dashboard() -> int | None:
    """Return the dashboard's HTTP status code, or None if unreachable. Uses a
    one-off curl on the opensmart network (the wazuh-indexer image ships curl
    and is already present) so it works whether this process runs in-container
    on that network or natively on the host — same rationale as host_interfaces
    and the password syncs."""
    try:
        result = subprocess.run(
            [
                "docker", "run", "--rm", "--network", "opensmart",
                "--entrypoint", "curl", _WAZUH_INDEXER_IMAGE,
                "-sk", "-o", "/dev/null", "-w", "%{http_code}",
                "--max-time", "8", _WAZUH_DASHBOARD_URL,
            ],
            capture_output=True, text=True, timeout=40, shell=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    code = (result.stdout or "").strip()
    if code.isdigit() and code != "000":
        return int(code)
    return None


def _dashboard_healthy(code: int | None) -> bool:
    # 401 is healthy here: the server is up and demanding auth (the dashboard
    # requires login). 2xx/3xx are healthy too. 5xx / None are not.
    return code is not None and (200 <= code < 400 or code == 401)


def _probe_wazuh_indexer() -> int | None:
    """HTTP status of the indexer's root, or None if unreachable — same one-off
    curl mechanism as the dashboard probe."""
    try:
        result = subprocess.run(
            [
                "docker", "run", "--rm", "--network", "opensmart",
                "--entrypoint", "curl", _WAZUH_INDEXER_IMAGE,
                "-sk", "-o", "/dev/null", "-w", "%{http_code}",
                "--max-time", "8", _WAZUH_INDEXER_URL,
            ],
            capture_output=True, text=True, timeout=40, shell=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    code = (result.stdout or "").strip()
    if code.isdigit() and code != "000":
        return int(code)
    return None


def _indexer_ready(code: int | None) -> bool:
    # 401/200 = up with the security index initialized (demands auth). 503 = up
    # but security not initialized yet; 000/None = not listening. Only the first
    # means the dashboard has a backend it can actually talk to.
    return code is not None and (200 <= code < 400 or code == 401)


def _restart_wazuh_dashboard() -> tuple[bool, str]:
    return _run_compose("wazuh", "restart", "wazuh.dashboard")


def wazuh_autoheal_tick() -> None:
    """One iteration of the dashboard auto-healer. Safe to call on a timer;
    never raises. Updates _WAZUH_HEALTH (surfaced in the Status section)."""
    now = time.time()
    inspected = _docker_inspect([_WAZUH_DASHBOARD_CONTAINER])
    if not inspected:
        _WAZUH_HEALTH.update(state="not-provisioned", http_code=None, assessment="",
                             consecutive_errors=0, heal_attempts=0, checked_at=now)
        return
    state = inspected[0].get("State", {})
    if state.get("Status") != "running":
        # Respect a deliberately stopped tool: report, but don't fight the user
        # by auto-starting it.
        _WAZUH_HEALTH.update(state="stopped", http_code=None,
                             assessment="Wazuh dashboard is not running. Start it from the Tools/Status section.",
                             consecutive_errors=0, heal_attempts=0, checked_at=now)
        return
    uptime = _uptime_seconds(state.get("StartedAt", ""))
    if uptime is not None and uptime < _WAZUH_HEAL_STARTUP_GRACE_SECONDS:
        _WAZUH_HEALTH.update(state="starting", http_code=None, assessment="",
                             consecutive_errors=0, checked_at=now)
        return

    code = _probe_wazuh_dashboard()
    if _dashboard_healthy(code):
        if _WAZUH_HEALTH["heal_attempts"] or _WAZUH_HEALTH["consecutive_errors"]:
            logger.info("wazuh dashboard healthy again (HTTP %s)", code)
        _WAZUH_HEALTH.update(state="healthy", http_code=code, assessment="",
                             consecutive_errors=0, heal_attempts=0, checked_at=now)
        return

    # Unhealthy (5xx or unreachable) past the startup grace.
    code_label = str(code) if code is not None else "no response"

    # Is the *indexer* even ready? The dashboard 500s/503s whenever its indexer
    # is still initializing (the classic fresh-install / post-password-change
    # window), and restarting the dashboard can't fix that — it just burns the
    # attempt budget and then wrongly "gives up". So when the indexer isn't
    # ready, wait for it (no restart, no attempt spent); the dashboard recovers
    # on its own once the indexer is up. This is the fix for the auto-heal being
    # "inconsistent / still failing minutes after a password change".
    if not _indexer_ready(_probe_wazuh_indexer()):
        _WAZUH_HEALTH.update(
            state="degraded", http_code=code, consecutive_errors=0, checked_at=now,
            assessment=(f"Wazuh dashboard unavailable (HTTP {code_label}) while its indexer is "
                        "still starting — waiting for the indexer to become ready (no restart)."))
        return

    errors = _WAZUH_HEALTH["consecutive_errors"] + 1
    attempts = _WAZUH_HEALTH["heal_attempts"]

    if errors < _WAZUH_HEAL_ERROR_THRESHOLD:
        _WAZUH_HEALTH.update(state="degraded", http_code=code, consecutive_errors=errors,
                             assessment=f"Wazuh dashboard health check failing (HTTP {code_label}); watching before auto-restart.",
                             checked_at=now)
        return

    if attempts >= _WAZUH_HEAL_MAX_ATTEMPTS:
        _WAZUH_HEALTH.update(
            state="unhealthy", http_code=code, consecutive_errors=errors, checked_at=now,
            assessment=(f"Wazuh dashboard still failing (HTTP {code_label}) after "
                        f"{_WAZUH_HEAL_MAX_ATTEMPTS} automatic restarts, even though the indexer is "
                        "up — check the wazuh.dashboard container logs; a full Wazuh restart may be "
                        "required."))
        return

    if now - _WAZUH_HEALTH["last_heal_ts"] < _WAZUH_HEAL_BACKOFF_SECONDS:
        # A restart is still settling; keep the current assessment, wait.
        _WAZUH_HEALTH.update(http_code=code, consecutive_errors=errors, checked_at=now)
        return

    attempts += 1
    logger.warning("wazuh dashboard unhealthy (HTTP %s) — auto-restart attempt %d/%d",
                   code_label, attempts, _WAZUH_HEAL_MAX_ATTEMPTS)
    _WAZUH_HEALTH.update(
        state="healing", http_code=code, heal_attempts=attempts, last_heal_ts=now,
        consecutive_errors=0, checked_at=now,
        assessment=(f"Wazuh dashboard returned HTTP {code_label} — auto-healing "
                    f"(restart {attempts}/{_WAZUH_HEAL_MAX_ATTEMPTS})…"))
    ok, detail = _restart_wazuh_dashboard()
    if not ok:
        logger.warning("wazuh dashboard auto-restart failed: %s", detail[:300])


# ── VPN summary (read-only, from bind-mounted files) ──────────────────────────
#
# The docker-socket-proxy blocks EXEC on purpose, so peer/cert state is read
# straight from the files the VPN containers write into their bind-mounted
# ./volumes/data directories — visible to this process because the whole
# project tree is mounted at host-parity paths.

_WIREGUARD_CONF = CONTAINERS_ROOT / "wireguard" / "volumes" / "data" / "wg0.conf"
_OPENVPN_INDEX = CONTAINERS_ROOT / "openvpn" / "volumes" / "data" / "pki" / "index.txt"


def vpn_summary() -> dict:
    wireguard_peers = 0
    if _WIREGUARD_CONF.is_file():
        try:
            wireguard_peers = _WIREGUARD_CONF.read_text().count("[Peer]")
        except OSError:
            pass
    openvpn_valid = 0
    openvpn_revoked = 0
    if _OPENVPN_INDEX.is_file():
        try:
            for line in _OPENVPN_INDEX.read_text().splitlines():
                # easy-rsa index.txt: V=valid, R=revoked, E=expired; first
                # valid entry is the server cert itself, not a user.
                if line.startswith("V"):
                    openvpn_valid += 1
                elif line.startswith("R"):
                    openvpn_revoked += 1
        except OSError:
            pass
    return {
        "wireguard": {"configured": _WIREGUARD_CONF.is_file(), "peers": wireguard_peers},
        "openvpn": {
            "configured": _OPENVPN_INDEX.is_file(),
            # Exclude the server certificate from the user count.
            "valid_certs": max(0, openvpn_valid - 1) if openvpn_valid else 0,
            "revoked_certs": openvpn_revoked,
        },
    }


def container_status(container: str) -> dict:
    ok, detail = _run_compose(container, "ps", "-q")
    running = ok and bool(detail.strip())
    return {"container": container, "running": running, "detail": detail if not ok else ""}


def provision_target(name: str, kind: str) -> dict:
    mapping = MODULE_CONTAINERS if kind == "module" else TOOL_CONTAINERS
    containers = mapping.get(name)
    if containers is None:
        return {"name": name, "ok": False, "detail": "No container template available yet for this module/tool.", "containers": []}
    results = []
    all_ok = True
    for container in containers:
        ok, detail = start_container(container)
        results.append({"container": container, "ok": ok, "detail": detail})
        all_ok = all_ok and ok
    return {"name": name, "ok": all_ok, "detail": "" if all_ok else "One or more containers failed to start.", "containers": results}

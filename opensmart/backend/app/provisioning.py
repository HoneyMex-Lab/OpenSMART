"""Starts/stops the per-tool sibling containers under containers/run/ via
`docker compose`, talking to the host Docker daemon through the
docker-socket-proxy sidecar (DOCKER_HOST is set in
containers/run/opensmart/docker-compose.yml) — this process never touches
docker.sock directly.
"""
import json
import logging
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .config import PROJECT_ROOT

logger = logging.getLogger(__name__)

CONTAINERS_ROOT = PROJECT_ROOT / "containers" / "run"

# Compose projects that actually exist under containers/run/ today.
KNOWN_CONTAINERS = frozenset({"suricata", "zeek", "arkime", "opensearch", "wireguard", "openvpn", "wazuh"})

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
    "arkime": ["opensmart-arkime-capture", "opensmart-arkime-viewer"],
    "opensearch": ["opensmart-opensearch"],
    "wireguard": ["opensmart-wireguard"],
    "openvpn": ["opensmart-openvpn"],
    "wazuh": ["opensmart-wazuh-manager", "opensmart-wazuh-indexer", "opensmart-wazuh-dashboard"],
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


def _ensure_wazuh_certs() -> tuple[bool, str]:
    if _WAZUH_CERTS_MARKER.is_file():
        return True, ""
    return _run_compose("wazuh", "--profile", "certs", "run", "--rm", "wazuh-certs-generator")


def _compose_path(container: str) -> Path:
    if container not in KNOWN_CONTAINERS:
        raise ValueError(f"Unknown container '{container}'")
    return CONTAINERS_ROOT / container / "docker-compose.yml"


def _run_compose(container: str, *args: str) -> tuple[bool, str]:
    path = _compose_path(container)
    if not path.is_file():
        return False, f"No docker-compose.yml found for '{container}' at {path}"
    profile = CONTAINER_PROFILES.get(container)
    profile_args = ["--profile", profile] if profile else []
    try:
        result = subprocess.run(
            ["docker", "compose", "-f", str(path), *profile_args, *args],
            cwd=str(path.parent),
            capture_output=True,
            text=True,
            timeout=_COMPOSE_TIMEOUT_SECONDS,
            shell=False,
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


def start_container(container: str) -> tuple[bool, str]:
    for dependency in CONTAINER_DEPENDENCIES.get(container, []):
        ok, detail = _run_compose(dependency, "up", "-d")
        if not ok:
            return False, f"Dependency '{dependency}' failed: {detail}"
    if container == "wazuh":
        ok, detail = _ensure_wazuh_certs()
        if not ok:
            return False, f"Certificate generation failed: {detail}"
    return _run_compose(container, "up", "-d")


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

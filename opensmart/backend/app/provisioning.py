"""Starts/stops the per-tool sibling containers under containers/run/ via
`docker compose`, talking to the host Docker daemon through the
docker-socket-proxy sidecar (DOCKER_HOST is set in
containers/run/opensmart/docker-compose.yml) — this process never touches
docker.sock directly.
"""
import logging
import subprocess
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

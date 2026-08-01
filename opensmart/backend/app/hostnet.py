"""Run commands in the HOST's real network namespace, for features that must
affect the host's actual network stack (live interface MTU, and later
nftables) rather than a sibling container's isolated netns.

Reuses opensmart/base (already has iproute2 + bash) via the same one-off,
`--network host [--cap-add NET_ADMIN] --entrypoint bash <image> -c '<script>'`
shape vpn.py's `_docker_run_host()` established — this file exists because a
second, security-sensitive feature (Firewall, see firewall.py) needs the exact
same primitive plus a detached/watchdog variant, so it's factored out here
instead of duplicated. A dedicated image (`opensmart/netadmin`) is only
introduced once a feature needs a tool this base image doesn't have (nftables).

Positional values (interface names, MTU numbers, tokens) are always passed as
real subprocess argv elements — available inside the script as $1, $2, ... —
never interpolated into the script string, so a value can't break out of its
argument no matter what a caller forgot to validate.
"""
import logging
import re
import secrets
import subprocess

logger = logging.getLogger(__name__)

_RUN_TIMEOUT_SECONDS = 60
_START_TIMEOUT_SECONDS = 30
_TOKEN_RE = re.compile(r"^[a-f0-9]{32}$")


def new_token() -> str:
    return secrets.token_hex(16)


def valid_token(token: str) -> bool:
    return bool(_TOKEN_RE.match(token))


def _base_cmd(*, net_admin: bool, mounts: dict[str, str] | None, image: str) -> list[str]:
    cmd = ["docker", "run", "--rm", "--network", "host"]
    if net_admin:
        cmd += ["--cap-add", "NET_ADMIN"]
    for host_path, container_path in (mounts or {}).items():
        cmd += ["-v", f"{host_path}:{container_path}"]
    cmd += ["--entrypoint", "bash", image]
    return cmd


def run_host(
    script: str,
    args: list[str] | None = None,
    *,
    image: str = "opensmart/base",
    net_admin: bool = True,
    mounts: dict[str, str] | None = None,
    timeout: int = _RUN_TIMEOUT_SECONDS,
) -> tuple[bool, str]:
    """Synchronous one-off run of `script` (a bash -c string) in the host's
    network namespace. `args` are available inside the script as $1, $2, ..."""
    cmd = _base_cmd(net_admin=net_admin, mounts=mounts, image=image)
    cmd += ["-c", script, "bash", *(args or [])]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False)
    except FileNotFoundError:
        return False, "docker CLI is not available in this environment."
    except subprocess.TimeoutExpired:
        return False, f"Timed out after {timeout}s."
    output = (result.stdout or result.stderr or "").strip()
    if result.returncode != 0:
        logger.warning("hostnet.run_host failed: %s", output[:1000])
        return False, output
    return True, output


def run_host_detached(
    name: str,
    script: str,
    args: list[str] | None = None,
    *,
    image: str = "opensmart/base",
    net_admin: bool = True,
    mounts: dict[str, str] | None = None,
) -> tuple[bool, str]:
    """Launch a detached, self-contained watchdog container running `script`
    in the background and return immediately once it's confirmed started.
    The caller reconciles the outcome later from bind-mounted result files
    (via `mounts`) — never by waiting on this process, since the whole point
    of a watchdog is that it keeps running independently of the backend."""
    cmd = ["docker", "run", "-d", "--rm", "--name", name, "--network", "host"]
    if net_admin:
        cmd += ["--cap-add", "NET_ADMIN"]
    for host_path, container_path in (mounts or {}).items():
        cmd += ["-v", f"{host_path}:{container_path}"]
    cmd += ["--entrypoint", "bash", image, "-c", script, "bash", *(args or [])]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=_START_TIMEOUT_SECONDS, shell=False)
    except FileNotFoundError:
        return False, "docker CLI is not available in this environment."
    except subprocess.TimeoutExpired:
        return False, "Timed out starting the watchdog container."
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        logger.warning("hostnet.run_host_detached failed to start %s: %s", name, detail[:1000])
        return False, detail
    return True, result.stdout.strip()

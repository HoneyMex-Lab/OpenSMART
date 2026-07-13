"""Manage the Suricata IDS configuration: rulesets (via suricata-update),
classification, detection variables, custom rules, and the raw suricata.yaml.

Suricata's config + rules are bind-mounted from the host (see the suricata
compose file's init-config service, which seeds them from the image), so this
module edits them as plain files at host-parity paths. Privileged operations
(suricata-update, `suricata -T` config test) run as one-off containers of the
same image with those dirs mounted — the docker-socket-proxy blocks EXEC, so
we can't run them inside the live container (same pattern as vpn.py).
"""
import logging
import re
import subprocess
from pathlib import Path

from .provisioning import CONTAINERS_ROOT, _docker_inspect, restart_container

logger = logging.getLogger(__name__)

_SURICATA_ROOT = CONTAINERS_ROOT / "suricata"
_CONFIG_ETC = _SURICATA_ROOT / "volumes" / "config" / "etc"
_CONFIG_LIB = _SURICATA_ROOT / "volumes" / "config" / "lib"
_IMAGE = "opensmart/suricata"
_CONTAINER = "opensmart-suricata"

# Editable files, by API key. Custom rules live under the managed rules dir
# (default-rule-path) so suricata.yaml can reference them by bare name.
_FILES: dict[str, Path] = {
    "suricata_yaml": _CONFIG_ETC / "suricata.yaml",
    "classification": _CONFIG_ETC / "classification.config",
    "threshold": _CONFIG_ETC / "threshold.config",
    "local_rules": _CONFIG_LIB / "rules" / "local.rules",
}

_UPDATE_TIMEOUT = 600   # rule downloads can be slow
_RUN_TIMEOUT = 180


class IdsConfigError(Exception):
    """User-facing IDS configuration failure."""


def _run(args: list[str], *, timeout: int = _RUN_TIMEOUT, entrypoint: str | None = None) -> subprocess.CompletedProcess:
    """One-off container of the Suricata image with the host config + rules
    mounted, running suricata/suricata-update against the same files the live
    container uses."""
    cmd = ["docker", "run", "--rm",
           "-v", f"{_CONFIG_ETC}:/etc/suricata",
           "-v", f"{_CONFIG_LIB}:/var/lib/suricata"]
    if entrypoint is not None:
        cmd += ["--entrypoint", entrypoint]
    cmd += [_IMAGE, *args]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False)


def _require_config() -> None:
    if not _FILES["suricata_yaml"].is_file():
        raise IdsConfigError("Suricata configuration is not available yet — provision the Network IDS module first.")


# ── File read / write ─────────────────────────────────────────────────────────

def read_config(kind: str) -> str:
    if kind not in _FILES:
        raise IdsConfigError(f"Unknown config file '{kind}'.")
    path = _FILES[kind]
    try:
        return path.read_text()
    except OSError:
        return ""  # local.rules / threshold may not exist yet — treat as empty


def write_config(kind: str, content: str) -> None:
    """Write a config file, then validate the whole Suricata config with
    `suricata -T`. On failure the previous content is restored so a bad edit
    can never take the sensor down."""
    if kind not in _FILES:
        raise IdsConfigError(f"Unknown config file '{kind}'.")
    _require_config()
    path = _FILES[kind]
    path.parent.mkdir(parents=True, exist_ok=True)
    previous = path.read_text() if path.is_file() else None
    path.write_text(content)
    if kind == "local_rules":
        _ensure_local_rules_referenced()
    ok, detail = test_config()
    if not ok:
        if previous is None:
            path.unlink(missing_ok=True)
        else:
            path.write_text(previous)
        raise IdsConfigError(f"Rejected — the configuration test failed:\n{detail}")


def _ensure_local_rules_referenced() -> None:
    """Make sure suricata.yaml's rule-files list includes local.rules so custom
    rules are actually loaded (idempotent)."""
    yaml_path = _FILES["suricata_yaml"]
    try:
        text = yaml_path.read_text()
    except OSError:
        return
    if re.search(r"(?m)^\s*-\s*local\.rules\s*$", text):
        return
    match = re.search(r"(?m)^(\s*)-\s*suricata\.rules\s*$", text)
    if match:
        indent = match.group(1)
        text = text[:match.end()] + f"\n{indent}- local.rules" + text[match.end():]
        yaml_path.write_text(text)


# ── Config test / apply ───────────────────────────────────────────────────────

def test_config() -> tuple[bool, str]:
    """Validate the current config with `suricata -T` (also compiles all rules)."""
    _require_config()
    try:
        result = _run(["-T", "-c", "/etc/suricata/suricata.yaml", "-l", "/var/lib/suricata"], entrypoint="suricata")
    except FileNotFoundError:
        return False, "docker CLI is not available in this environment."
    except subprocess.TimeoutExpired:
        return False, "Configuration test timed out."
    output = (result.stderr or result.stdout or "").strip()
    # Keep the meaningful lines (errors/warnings + the success marker).
    lines = [ln for ln in output.splitlines() if re.search(r"<(Error|Warning)>|Configuration provided was successfully", ln)]
    return result.returncode == 0, "\n".join(lines[-40:]) or output[-2000:]


def restart() -> tuple[bool, str]:
    """Apply config/rule changes by restarting the sensor."""
    return restart_container("suricata")


def is_running() -> bool:
    inspected = _docker_inspect([_CONTAINER])
    return bool(inspected and inspected[0].get("State", {}).get("Running"))


# ── Rulesets (suricata-update) ────────────────────────────────────────────────

def list_sources() -> list[dict]:
    """All known ruleset sources + which are enabled."""
    _require_config()
    enabled = set(_enabled_source_names())
    try:
        result = _run(["list-sources"], entrypoint="suricata-update")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    sources: list[dict] = []
    current: dict | None = None
    for raw in _strip_ansi(result.stdout or "").splitlines():
        name = re.match(r"^Name:\s*(\S+)", raw.strip())
        if name:
            current = {"name": name.group(1), "vendor": "", "summary": "", "license": "",
                       "subscription": False, "enabled": name.group(1) in enabled}
            sources.append(current)
        elif current:
            for key, field in (("Vendor", "vendor"), ("Summary", "summary"), ("License", "license")):
                m = re.match(rf"^{key}:\s*(.+)", raw.strip())
                if m:
                    current[field] = m.group(1).strip()
            if re.match(r"^(Subscription|Parameters):", raw.strip()):
                current["subscription"] = True
    return sources


def _enabled_source_names() -> list[str]:
    try:
        result = _run(["list-enabled-sources"], entrypoint="suricata-update")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    names = []
    for raw in _strip_ansi(result.stdout or "").splitlines():
        m = re.match(r"^\s*-\s*(\S+)", raw)
        if m:
            names.append(m.group(1))
    return names


def enable_source(name: str, params: dict | None = None) -> None:
    _validate_source_name(name)
    args = ["enable-source", name]
    for key, value in (params or {}).items():
        if re.fullmatch(r"[a-zA-Z0-9_-]+", str(key)) and "\n" not in str(value):
            args.append(f"{key}={value}")
    try:
        result = _run(args, entrypoint="suricata-update")
    except (FileNotFoundError, subprocess.TimeoutExpired) as error:
        raise IdsConfigError(f"Could not enable source: {error}") from error
    if result.returncode != 0:
        raise IdsConfigError(_strip_ansi((result.stderr or result.stdout))[-500:])


def disable_source(name: str) -> None:
    _validate_source_name(name)
    try:
        result = _run(["disable-source", name], entrypoint="suricata-update")
    except (FileNotFoundError, subprocess.TimeoutExpired) as error:
        raise IdsConfigError(f"Could not disable source: {error}") from error
    if result.returncode != 0:
        raise IdsConfigError(_strip_ansi((result.stderr or result.stdout))[-500:])


def update_rules() -> tuple[bool, str]:
    """Fetch enabled sources and rebuild /var/lib/suricata/rules/suricata.rules.
    Does not reload the sensor — callers restart() to apply."""
    _require_config()
    try:
        result = _run(["--no-test", "--no-reload"], entrypoint="suricata-update", timeout=_UPDATE_TIMEOUT)
    except FileNotFoundError:
        return False, "docker CLI is not available in this environment."
    except subprocess.TimeoutExpired:
        return False, "Rule update timed out."
    output = _strip_ansi(result.stderr or result.stdout or "")
    summary = [ln for ln in output.splitlines() if re.search(r"Loaded|enabled|added|removed|modified|Error|Warning|rules", ln)]
    return result.returncode == 0, "\n".join(summary[-30:]) or output[-1500:]


def _validate_source_name(name: str) -> None:
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._/-]{0,80}", name or ""):
        raise IdsConfigError("Invalid source name.")


# ── Detection variables (HOME_NET / EXTERNAL_NET etc.) ────────────────────────

_ADDRESS_VARS = ("HOME_NET", "EXTERNAL_NET")


def detection_settings() -> dict:
    text = _FILES["suricata_yaml"].read_text() if _FILES["suricata_yaml"].is_file() else ""
    settings: dict[str, str] = {}
    for var in _ADDRESS_VARS:
        m = re.search(rf'(?m)^\s*{var}:\s*"?(.*?)"?\s*$', text)
        settings[var] = m.group(1) if m else ""
    return settings


def update_detection_settings(values: dict) -> None:
    _require_config()
    yaml_path = _FILES["suricata_yaml"]
    text = yaml_path.read_text()
    previous = text
    for var in _ADDRESS_VARS:
        if var not in values:
            continue
        value = str(values[var]).strip()
        if "\n" in value or '"' in value:
            raise IdsConfigError(f"Invalid value for {var}.")
        replacement = rf'\g<1>{var}: "{value}"'
        new_text, count = re.subn(rf'(?m)^(\s*){var}:\s*.*$', replacement, text)
        if count:
            text = new_text
    yaml_path.write_text(text)
    ok, detail = test_config()
    if not ok:
        yaml_path.write_text(previous)
        raise IdsConfigError(f"Rejected — the configuration test failed:\n{detail}")


# ── Summary ───────────────────────────────────────────────────────────────────

def rules_summary() -> dict:
    rules_file = _CONFIG_LIB / "rules" / "suricata.rules"
    enabled_count = 0
    total = 0
    try:
        for line in rules_file.read_text(errors="ignore").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                total += 1 if stripped.startswith("#") and " sid:" in stripped else 0
                continue
            if " sid:" in stripped or "sid:" in stripped:
                enabled_count += 1
                total += 1
    except OSError:
        pass
    local_file = _FILES["local_rules"]
    custom = 0
    if local_file.is_file():
        custom = sum(1 for ln in local_file.read_text(errors="ignore").splitlines()
                     if ln.strip() and not ln.strip().startswith("#"))
    return {
        "enabled_rules": enabled_count,
        "total_rules": total,
        "custom_rules": custom,
        "enabled_sources": _enabled_source_names(),
        "running": is_running(),
        "provisioned": _FILES["suricata_yaml"].is_file(),
    }


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text or "")

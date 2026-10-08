import hashlib
import json
import logging
import re
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from collections import Counter
from typing import Any

from .config import PROJECT_ROOT
from .database import get_db, get_network_ids_db, get_network_traffic_db, now_iso

logger = logging.getLogger(__name__)

INGEST_LOCK = threading.Lock()

# Where the bundled ("native") Suricata container writes its eve.json —
# inside the project tree, so this process can read it directly through the
# host-parity bind mount. Defined here (not network_ids.py, which imports
# this module) so BOTH the API-facing config in network_ids.ids_config()
# and the ingestion engine's shared_config() below resolve the native
# source identically. They previously didn't: ids_config() resolved
# native → this path, but shared_config() read the raw (empty)
# eve_json_path key, so with eve_source=native the UI showed
# "configured/readable" while every actual ingest run skipped with
# "path not configured" — the exact default-install pipeline failure
# observed on a default install.
NATIVE_SURICATA_EVE_PATH = PROJECT_ROOT / "containers" / "run" / "suricata" / "volumes" / "data" / "log" / "eve.json"


def resolve_eve_json_path(ids_module_config: dict[str, Any]) -> str:
    """Resolve the effective eve.json path from the raw Network IDS module
    config: the native Suricata container's path when eve_source=native,
    the user-provided external path otherwise."""
    source = str(ids_module_config.get("eve_source", "external")).strip().lower()
    if source == "native":
        return str(NATIVE_SURICATA_EVE_PATH)
    return str(ids_module_config.get("eve_json_path", ""))
_ALERT_NEEDLE = '"event_type":"alert"'
EVENT_TYPE_RE = re.compile(r'"event_type"\s*:\s*"([^"]+)"')

NETWORK_EVENT_TYPES = {
    "anomaly",
    "dcerpc",
    "dhcp",
    "dns",
    "dnp3",
    "ftp",
    "http",
    "http2",
    "ikev2",
    "imap",
    "krb5",
    "modbus",
    "mqtt",
    "netflow",
    "nfs",
    "ntp",
    "quic",
    "rdp",
    "sip",
    "smtp",
    "snmp",
    "ssh",
    "tftp",
    "tls",
    "fileinfo",
    "flow",
    "smb",
}

NETWORK_CONFIG_TO_EVENT_TYPES = {
    "index_dns": {"dns"},
    "index_http": {"http", "http2"},
    "index_tls": {"tls"},
    "index_flow": {"flow", "netflow"},
    "index_fileinfo": {"fileinfo"},
    "index_smb": {"smb"},
    "index_other_app_layer": NETWORK_EVENT_TYPES - {"dns", "http", "http2", "tls", "flow", "netflow", "fileinfo", "smb"},
}


def compute_event_hash(serialized_event: str) -> str:
    """SHA-256 of the deterministic JSON serialization of an EVE event."""
    return hashlib.sha256(serialized_event.encode("utf-8", errors="replace")).hexdigest()


def module_config(name: str) -> tuple[bool, dict[str, Any]]:
    with get_db() as db:
        row = db.execute("SELECT enabled, config FROM opensmart_modules WHERE name = ?", (name,)).fetchone()
    if not row:
        return False, {}
    try:
        config = json.loads(row["config"] or "{}")
    except json.JSONDecodeError:
        config = {}
    return bool(row["enabled"]), config


_DEFAULT_EXCLUDE: frozenset[str] = frozenset({"stats", "drop", "internal", "pcap"})


def _parse_exclude_types(raw: str) -> frozenset[str]:
    if not raw:
        return _DEFAULT_EXCLUDE
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return frozenset(str(t).strip() for t in parsed if t)
    except (json.JSONDecodeError, TypeError):
        pass
    return _DEFAULT_EXCLUDE


def shared_config() -> dict[str, Any]:
    ids_enabled, ids = module_config("Network IDS")
    network_enabled, network = module_config("Network Traffic Monitoring")
    network_source = str(network.get("log_source", "eve_json") or "eve_json")
    network_uses_eve = network_source == "eve_json"
    return {
        "eve_json_path": resolve_eve_json_path(ids),
        "summary_refresh_minutes": int(ids.get("summary_refresh_minutes", 5) or 5),
        "initial_ingestion_gb": _float(ids.get("initial_ingestion_gb", 2), 2),
        "ids_enabled": ids_enabled,
        "network_enabled": network_enabled and network_uses_eve,
        "network_config_enabled": network_enabled,
        "network_source": network_source,
        "zeek_json_path": str(network.get("zeek_json_path", "")),
        "keep_empty_alerts": str(ids.get("keep_empty_alerts", "false")).strip().lower() in ("1", "true", "yes", "on"),
        "index_payload_printable": str(ids.get("index_payload_printable", "true")).strip().lower() not in ("0", "false", "no", "off"),
        "fast_alert_prefilter": str(ids.get("fast_alert_prefilter", "true")).strip().lower() not in ("0", "false", "no", "off"),
        "network_all_protocols": _enabled(network, "index_all_suricata_protocols", False),
        "network_event_types": selected_network_event_types(network_enabled and network_uses_eve, network),
        "network_exclude_event_types": _parse_exclude_types(network.get("exclude_event_types", "")),
        "ids_retention_enabled": str(ids.get("retention_enabled", "true")).strip().lower() not in ("0", "false", "no", "off"),
        "ids_retention_days": int(ids.get("retention_days", 90) or 90),
        "ids_retention_time": str(ids.get("retention_time", "02:00")),
        "network_retention_enabled": str(network.get("retention_enabled", "true")).strip().lower() not in ("0", "false", "no", "off"),
        "network_retention_days": int(network.get("retention_days", 90) or 90),
        "network_retention_time": str(network.get("retention_time", "02:00")),
    }


def ingest_profile(config: dict[str, Any]) -> str:
    return json.dumps({"network_enabled": config["network_enabled"], "network_all_protocols": config.get("network_all_protocols", False), "network_event_types": sorted(config["network_event_types"])}, sort_keys=True)


def selected_network_event_types(enabled: bool, config: dict[str, Any]) -> set[str]:
    if not enabled:
        return set()
    if _enabled(config, "index_all_suricata_protocols", False):
        return set(NETWORK_EVENT_TYPES)
    selected: set[str] = set()
    for key, event_types in NETWORK_CONFIG_TO_EVENT_TYPES.items():
        if _enabled(config, key, key in {"index_dns", "index_http", "index_tls", "index_flow"}):
            selected.update(event_types)
    return selected


def _enabled(config: dict[str, Any], key: str, default: bool) -> bool:
    value = str(config.get(key, "true" if default else "false")).strip().lower()
    return value in ("1", "true", "yes", "on")


def _float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def default_state(status: str) -> dict[str, Any]:
    return {
        "refresh_status": status,
        "progress_percent": 0,
        "current_action": "Idle" if status == "idle" else "Not configured",
        "last_check_started_at": "",
        "last_check_finished_at": "",
        "last_check_bytes_total": 0,
        "last_check_bytes_read": 0,
        "last_check_lines_read": 0,
        "last_check_alerts_read": 0,
        "last_check_network_read": 0,
        "last_check_non_alerts": 0,
        "last_updated": "",
        "error": "",
    }


def _read_state(path: str, db_factory, table: str) -> dict[str, Any]:
    if not path:
        return default_state("not_configured")
    with db_factory() as db:
        row = db.execute(
            f"""
            SELECT refresh_status, progress_percent, current_action, last_check_started_at, last_check_finished_at,
                last_check_bytes_total, last_check_bytes_read, last_check_lines_read, last_check_alerts_read,
                last_check_network_read, last_check_non_alerts, ingest_profile, last_updated, error
            FROM {table} WHERE eve_json_path = ?
            """,
            (path,),
        ).fetchone()
    if not row:
        return default_state("idle")
    return dict(row)


def read_ids_state(path: str) -> dict[str, Any]:
    return _read_state(path, get_network_ids_db, "network_ids_ingest_state")


def read_network_state(path: str) -> dict[str, Any]:
    return _read_state(path, get_network_traffic_db, "network_traffic_ingest_state")


def read_state(path: str) -> dict[str, Any]:
    return read_network_state(path)


def _network_event_count(path: str) -> int:
    if not path:
        return 0
    with get_network_traffic_db() as db:
        row = db.execute(
            "SELECT COUNT(*) AS c FROM eve_network_events WHERE eve_json_path = ?", (str(path),)
        ).fetchone()
        return int(row["c"] if row else 0)


def ids_event_count(path: str) -> int:
    if not path:
        return 0
    with get_network_ids_db() as db:
        row = db.execute(
            "SELECT COUNT(*) AS c FROM network_ids_alerts WHERE eve_json_path = ?", (str(path),)
        ).fetchone()
        return int(row["c"] if row else 0)


def ids_first_ingestion_required(path: str, config: dict[str, Any] | None = None) -> bool:
    if not path:
        return False
    config = config or shared_config()
    if not config.get("ids_enabled"):
        return False
    state = read_ids_state(path)
    return not state.get("last_updated")


def _active_state(path: str, config: dict[str, Any]) -> dict[str, Any]:
    if config["network_enabled"]:
        return read_network_state(path)
    if config["ids_enabled"]:
        return read_ids_state(path)
    return default_state("idle")


def _update_state(db_factory, table: str, path: str, sql_tail: str, params: tuple[Any, ...]) -> None:
    with db_factory() as db:
        db.execute(
            f"""
            INSERT INTO {table} (eve_json_path)
            VALUES (?)
            ON CONFLICT(eve_json_path) DO NOTHING
            """,
            (path,),
        )
        db.execute(f"UPDATE {table} SET {sql_tail} WHERE eve_json_path = ?", (*params, path))
        db.commit()


def _set_running(path: str, config: dict[str, Any], include_ids: bool = True) -> None:
    if include_ids and config["ids_enabled"]:
        _update_state(get_network_ids_db, "network_ids_ingest_state", path, "refresh_status = 'running', current_action = 'Starting'", ())
    if config["network_enabled"]:
        _update_state(get_network_traffic_db, "network_traffic_ingest_state", path, "refresh_status = 'running', current_action = 'Starting'", ())


def _set_recovered(path: str, config: dict[str, Any]) -> None:
    if config["ids_enabled"]:
        _update_state(get_network_ids_db, "network_ids_ingest_state", path, "refresh_status = 'idle', error = 'recovered'", ())
    if config["network_enabled"]:
        _update_state(get_network_traffic_db, "network_traffic_ingest_state", path, "refresh_status = 'idle', error = 'recovered'", ())


def _byte_offset(db_factory, table: str, path: str) -> int:
    with db_factory() as db:
        row = db.execute(f"SELECT byte_offset FROM {table} WHERE eve_json_path = ?", (path,)).fetchone()
    return int(row["byte_offset"] if row else 0)


def _initial_offset(path: Path, file_size: int, limit_gb: float) -> tuple[int, bool]:
    if limit_gb <= 0:
        return 0, False
    limit_bytes = int(limit_gb * 1024 * 1024 * 1024)
    if limit_bytes <= 0 or file_size <= limit_bytes:
        return 0, False
    with path.open("rb") as handle:
        handle.seek(max(0, file_size - limit_bytes))
        handle.readline()
        return handle.tell(), True


def maybe_start_refresh(force: bool = False, force_network_reindex: bool = False) -> None:
    config = shared_config()
    path = config["eve_json_path"]
    if not path or not Path(path).is_file():
        logger.info("eve ingest skipped: path not configured/readable path=%s", path)
        return
    state = _active_state(path, config)
    if state["refresh_status"] == "running":
        if INGEST_LOCK.locked():
            logger.info("eve ingest skipped: already running path=%s", path)
            return
        logger.warning("eve ingest: stale running state detected, recovering path=%s", path)
        _set_recovered(path, config)
        state = _active_state(path, config)
    profile = ingest_profile(config)
    if ids_first_ingestion_required(path, config):
        force_network_reindex = False
    first_ingestion_required = ids_first_ingestion_required(path, config)
    if first_ingestion_required:
        force_network_reindex = False
        logger.info("eve ingest first ingestion required before pull/update path=%s", path)
    if not first_ingestion_required and config["network_enabled"] and state.get("ingest_profile") and state.get("ingest_profile") != profile:
        force_network_reindex = True
        logger.info("eve ingest network reindex requested: profile changed old=%s new=%s", state.get("ingest_profile"), profile)
    if (not first_ingestion_required and not force_network_reindex and config["network_enabled"] and config["network_event_types"]
            and not _network_event_count(path)):
        force_network_reindex = True
        logger.info("eve ingest network reindex requested: network enabled but DB has no events path=%s", path)
    if not force and state["last_updated"]:
        parsed = _parse_time(state["last_updated"])
        if parsed and datetime.now(timezone.utc) - parsed < timedelta(minutes=config["summary_refresh_minutes"]):
            logger.info("eve ingest skipped: within TTL path=%s last_updated=%s ttl_min=%s", path, state["last_updated"], config["summary_refresh_minutes"])
            return
    _set_running(path, config, include_ids=not force_network_reindex)
    if config.get("ids_enabled") and not force_network_reindex:
        from . import notifications

        notifications.notify_ids_system_event("ingest_started", "Network IDS eve.json ingestion started")
    threading.Thread(target=ingest_eve_json, args=(path, force_network_reindex), daemon=True).start()


def ingest_eve_json(path_value: str, force_network_reindex: bool = False) -> None:
    if not INGEST_LOCK.acquire(blocking=False):
        return
    path = Path(path_value)
    t_start = time.monotonic()
    try:
        from . import network_ids

        config = shared_config()
        profile = ingest_profile(config)
        stat = path.stat()
        active_offsets: list[int] = []
        if config["ids_enabled"] and not force_network_reindex:
            active_offsets.append(_byte_offset(get_network_ids_db, "network_ids_ingest_state", str(path)))
        if config["network_enabled"]:
            network_offset = _byte_offset(get_network_traffic_db, "network_traffic_ingest_state", str(path))
            active_offsets.append(0 if force_network_reindex else network_offset)
        offset = min(active_offsets) if active_offsets else 0
        limited_initial = False
        if offset == 0 and config["ids_enabled"] and not force_network_reindex:
            offset, limited_initial = _initial_offset(path, stat.st_size, float(config.get("initial_ingestion_gb") or 0))
        if force_network_reindex:
            with get_network_traffic_db() as db:
                db.execute("DELETE FROM eve_network_events WHERE eve_json_path = ?", (str(path),))
                db.commit()
        if offset > stat.st_size or len(set(active_offsets)) > 1:
            if len(set(active_offsets)) > 1:
                logger.info("eve ingest offset mismatch detected, rebuilding active module data path=%s offsets=%s", path, active_offsets)
            offset = 0
            if config["ids_enabled"] and not force_network_reindex:
                with get_network_ids_db() as db:
                    db.execute("DELETE FROM network_ids_alerts WHERE eve_json_path = ?", (str(path),))
                    db.execute("DELETE FROM network_ids_alerts_fts WHERE eve_json_path = ?", (str(path),))
                    db.execute("DELETE FROM network_ids_artifacts WHERE eve_json_path = ?", (str(path),))
                    db.commit()
            if config["network_enabled"]:
                with get_network_traffic_db() as db:
                    db.execute("DELETE FROM eve_network_events WHERE eve_json_path = ?", (str(path),))
                    db.commit()
        delta_bytes = max(0, stat.st_size - offset)
        started_at = now_iso()
        if config["ids_enabled"] and not force_network_reindex:
            _update_state(
                get_network_ids_db,
                "network_ids_ingest_state",
                str(path),
                "file_size = ?, file_mtime = ?, byte_offset = ?, refresh_status = 'running', progress_percent = 0, current_action = 'Loading eve.json delta', last_check_started_at = ?, last_check_bytes_total = ?, last_check_bytes_read = 0, last_check_lines_read = 0, last_check_alerts_read = 0, last_check_network_read = 0, last_check_non_alerts = 0, ingest_profile = ?, error = ''",
                (stat.st_size, stat.st_mtime, offset, started_at, delta_bytes, profile),
            )
        if config["network_enabled"]:
            _update_state(
                get_network_traffic_db,
                "network_traffic_ingest_state",
                str(path),
                "file_size = ?, file_mtime = ?, byte_offset = ?, refresh_status = 'running', progress_percent = 0, current_action = 'Loading eve.json delta', last_check_started_at = ?, last_check_bytes_total = ?, last_check_bytes_read = 0, last_check_lines_read = 0, last_check_alerts_read = 0, last_check_network_read = 0, last_check_non_alerts = 0, ingest_profile = ?, error = ''",
                (stat.st_size, stat.st_mtime, offset, started_at, delta_bytes, profile),
            )

        lines = alerts_read = network_read = skipped = malformed = 0
        seen_types: Counter[str] = Counter()
        indexed_types: Counter[str] = Counter()
        skipped_types: Counter[str] = Counter()
        alert_batch: list[dict[str, Any]] = []
        network_batch: list[dict[str, Any]] = []
        network_types = set(config["network_event_types"])
        network_exclude = frozenset(config.get("network_exclude_event_types") or _DEFAULT_EXCLUDE)
        ingest_alerts = config["ids_enabled"] and not force_network_reindex
        ids_only_prefilter = ingest_alerts and not network_types and config["fast_alert_prefilter"]
        network_all = bool(config.get("network_all_protocols"))
        needles = set() if network_all else {f'"event_type":"{event_type}"' for event_type in ({"alert"} if config["ids_enabled"] else set()) | network_types}
        logger.info(
            "eve ingest started: path=%s file_size=%d offset=%d delta_bytes=%d limited_initial=%s force=%s force_network_reindex=%s ids_enabled=%s network_enabled=%s network_event_types=%s ids_fast_prefilter=%s shared_filter=%s",
            path, stat.st_size, offset, delta_bytes, limited_initial, not force_network_reindex, force_network_reindex, config["ids_enabled"], config["network_enabled"], sorted(network_types), ids_only_prefilter, bool(needles),
        )

        with path.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(offset)
            while line := handle.readline():
                lines += 1
                compact_event_type = EVENT_TYPE_RE.search(line)
                hinted_type = compact_event_type.group(1) if compact_event_type else ""
                if hinted_type:
                    seen_types[hinted_type] += 1
                if ids_only_prefilter and hinted_type != "alert":
                    skipped += 1
                    skipped_types[hinted_type or "unknown"] += 1
                    continue
                if needles and hinted_type and hinted_type not in ({"alert"} if ingest_alerts else set()) | network_types:
                    skipped += 1
                    skipped_types[hinted_type] += 1
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    malformed += 1
                    continue
                event_type = str(event.get("event_type", ""))
                seen_types[event_type or "unknown"] += 1 if not hinted_type else 0
                if ingest_alerts and event_type == "alert":
                    record = network_ids.normalize_alert(event, keep_empty=config["keep_empty_alerts"], index_pp=config["index_payload_printable"])
                    if record:
                        alert_batch.append(record)
                        alerts_read += 1
                        indexed_types[event_type] += 1
                    else:
                        skipped += 1
                        skipped_types[event_type or "unknown"] += 1
                elif event_type in network_types or (network_all and event_type and event_type != "alert"):
                    if event_type in network_exclude:
                        skipped += 1
                        skipped_types[event_type] += 1
                        continue
                    network_batch.append(normalize_network_event(event))
                    network_read += 1
                    indexed_types[event_type] += 1
                else:
                    skipped += 1
                    skipped_types[event_type or "unknown"] += 1
                if len(alert_batch) + len(network_batch) >= 500:
                    flush_batches(str(path), alert_batch, network_batch)
                    alert_batch.clear()
                    network_batch.clear()
                    update_progress(str(path), handle.tell() - offset, delta_bytes, lines, alerts_read, network_read, skipped)
            if alert_batch or network_batch:
                flush_batches(str(path), alert_batch, network_batch)
            final_offset = handle.tell()
        finished_at = now_iso()
        error_text = f"malformed lines: {malformed}" if malformed else ""
        final_params = (stat.st_size, stat.st_mtime, final_offset, lines, finished_at, max(0, final_offset - offset), lines, alerts_read, network_read, skipped, finished_at, error_text)
        final_sql = "file_size = ?, file_mtime = ?, byte_offset = ?, lines_read = lines_read + ?, refresh_status = 'idle', progress_percent = 100, current_action = 'Idle', last_check_finished_at = ?, last_check_bytes_read = ?, last_check_lines_read = ?, last_check_alerts_read = ?, last_check_network_read = ?, last_check_non_alerts = ?, last_updated = ?, error = ?"
        if config["ids_enabled"] and not force_network_reindex:
            _update_state(get_network_ids_db, "network_ids_ingest_state", str(path), final_sql, final_params)
        if config["network_enabled"]:
            _update_state(get_network_traffic_db, "network_traffic_ingest_state", str(path), final_sql, final_params)
        network_ids.SUMMARY_CACHE.clear()
        if config.get("ids_enabled") and not force_network_reindex:
            from . import notifications

            notifications.notify_ids_system_event("ingest_completed", f"Network IDS ingestion completed: {alerts_read} alerts read")
        logger.info(
            "eve ingest completed: path=%s lines=%d alerts=%d network=%d skipped=%d malformed=%d event_types=%s seen_types=%s indexed_types=%s skipped_types=%s elapsed=%.2fs",
            path, lines, alerts_read, network_read, skipped, malformed, sorted(network_types), seen_types.most_common(20), indexed_types.most_common(20), skipped_types.most_common(20), time.monotonic() - t_start,
        )
    except Exception as error:
        logger.exception("eve ingest error: path=%s", path_value)
        try:
            config = shared_config()
            if config["ids_enabled"]:
                _update_state(get_network_ids_db, "network_ids_ingest_state", str(path), "refresh_status = 'error', current_action = 'Error', error = ?", (str(error),))
                from . import notifications

                notifications.notify_ids_system_event("ingest_error", "Network IDS ingestion error")
            if config["network_enabled"]:
                _update_state(get_network_traffic_db, "network_traffic_ingest_state", str(path), "refresh_status = 'error', current_action = 'Error', error = ?", (str(error),))
        except sqlite3.Error:
            logger.exception("failed to write eve ingest error state")
    finally:
        INGEST_LOCK.release()


def flush_batches(path: str, alert_batch: list[dict[str, Any]], network_batch: list[dict[str, Any]]) -> None:
    if alert_batch:
        from . import network_ids

        network_ids.write_alerts(path, alert_batch)
    if network_batch:
        write_network_events(path, network_batch)


def write_network_events(path: str, rows: list[dict[str, Any]]) -> None:
    columns = ["eve_json_path", "timestamp", "event_type", "src_ip", "src_port", "dest_ip", "dest_port", "proto", "app_proto", "flow_id", "in_iface", "community_id", "host", "tx_id", "domain", "url", "method", "status", "user_agent", "tls_sni", "file_name", "file_hash", "bytes_toserver", "bytes_toclient", "pkts_toserver", "pkts_toclient", "flow_state", "summary", "event_json", "ingested_at", "event_hash"]
    placeholders = ",".join("?" for _ in columns)
    with get_network_traffic_db() as db:
        db.executemany(
            f"INSERT OR IGNORE INTO eve_network_events ({','.join(columns)}) VALUES ({placeholders})",
            [
                (path, *(str(row.get(field, "")) for field in columns[1:-2]), now_iso(),
                 compute_event_hash(str(row.get("event_json", ""))))
                for row in rows
            ],
        )
        db.commit()


def normalize_network_event(event: dict[str, Any]) -> dict[str, Any]:
    event_type = str(event.get("event_type", ""))
    dns = event.get("dns") or {}
    http = event.get("http") or {}
    tls = event.get("tls") or {}
    flow = event.get("flow") or {}
    fileinfo = event.get("fileinfo") or {}
    smb = event.get("smb") or {}
    domain = str(dns.get("rrname") or http.get("hostname") or tls.get("sni") or event.get("host") or "")
    file_hash = str(fileinfo.get("sha256") or fileinfo.get("sha1") or fileinfo.get("md5") or "")
    return {
        "timestamp": str(event.get("timestamp", "")),
        "event_type": event_type,
        "src_ip": str(event.get("src_ip", "")),
        "src_port": event.get("src_port", ""),
        "dest_ip": str(event.get("dest_ip", "")),
        "dest_port": event.get("dest_port", ""),
        "proto": str(event.get("proto", "")),
        "app_proto": str(event.get("app_proto", "")),
        "flow_id": str(event.get("flow_id", "")),
        "in_iface": str(event.get("in_iface", "")),
        "community_id": str(event.get("community_id", "")),
        "host": str(event.get("host", "")),
        "tx_id": str(event.get("tx_id", "")),
        "domain": domain,
        "url": str(http.get("url", "")),
        "method": str(http.get("http_method", "")),
        "status": str(http.get("status") or smb.get("status") or ""),
        "user_agent": str(http.get("http_user_agent", "")),
        "tls_sni": str(tls.get("sni", "")),
        "file_name": str(fileinfo.get("filename") or smb.get("filename") or ""),
        "file_hash": file_hash,
        "bytes_toserver": _int(flow.get("bytes_toserver")),
        "bytes_toclient": _int(flow.get("bytes_toclient")),
        "pkts_toserver": _int(flow.get("pkts_toserver")),
        "pkts_toclient": _int(flow.get("pkts_toclient")),
        "flow_state": str(flow.get("state", "")),
        "summary": network_summary(event_type, event),
        "event_json": json.dumps(event, separators=(",", ":"), sort_keys=True),
    }


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def network_summary(event_type: str, event: dict[str, Any]) -> str:
    data = event.get(event_type) or {}
    if event_type == "dns":
        return str(data.get("rrname") or data.get("query") or "")
    if event_type == "http":
        return " ".join(str(data.get(key, "")) for key in ("hostname", "http_method", "url") if data.get(key))
    if event_type == "tls":
        return str(data.get("sni") or data.get("subject") or "")
    if event_type == "fileinfo":
        return str(data.get("filename") or data.get("sha256") or data.get("md5") or "")
    if event_type == "flow":
        return " ".join(str(data.get(key, "")) for key in ("state", "reason") if data.get(key))
    return str(data.get("command") or data.get("filename") or data.get("status") or "")


def update_progress(path: str, bytes_read: int, bytes_total: int, lines: int, alerts_read: int, network_read: int, skipped: int) -> None:
    percent = 100 if bytes_total <= 0 else min(99, int((bytes_read / bytes_total) * 100))
    config = shared_config()
    progress_sql = "progress_percent = ?, last_check_bytes_read = ?, last_check_lines_read = ?, last_check_alerts_read = ?, last_check_network_read = ?, last_check_non_alerts = ?"
    params = (percent, bytes_read, lines, alerts_read, network_read, skipped)
    if config["ids_enabled"]:
        _update_state(get_network_ids_db, "network_ids_ingest_state", path, progress_sql, params)
    if config["network_enabled"]:
        _update_state(get_network_traffic_db, "network_traffic_ingest_state", path, progress_sql, params)


def _parse_time(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

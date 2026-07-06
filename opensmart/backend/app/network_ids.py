import base64
import binascii
import json
import logging
import re
import sqlite3
import threading
import time
import ipaddress
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import eve_ingest
from .config import PROJECT_ROOT
from .database import get_db, get_network_ids_db, now_iso
from .eve_ingest import compute_event_hash

logger = logging.getLogger(__name__)

# Host-side path to the eve.json produced by the native (in-container) Suricata
# stack at opensmart/containers/run/suricata, whose docker-compose.yml
# bind-mounts ./volumes/data -> /data, with Suricata's entrypoint logging to
# /data/log. containers/run/ lives inside PROJECT_ROOT (opensmart/), not
# beside it — see opensmart/containers/run/opensmart/docker-compose.yml.
NATIVE_SURICATA_EVE_PATH = PROJECT_ROOT / "containers" / "run" / "suricata" / "volumes" / "data" / "log" / "eve.json"

TIMEFRAMES = {
    "1h": timedelta(hours=1),
    "4h": timedelta(hours=4),
    "1d": timedelta(days=1),
    "3d": timedelta(days=3),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
    "60d": timedelta(days=60),
    "90d": timedelta(days=90),
}

SUMMARY_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
# ARTIFACT_CACHE: keyed (path, timeframe, top_n) → (created_ts, rows). TTL = summary_refresh_minutes.
ARTIFACT_CACHE: dict[tuple[str, str, int], tuple[float, list[dict[str, Any]]]] = {}
INGEST_LOCK = threading.Lock()
ARTIFACT_REBUILD_LOCK = threading.Lock()
FTS_READY_PATHS: set[str] = set()
ARTIFACT_READY_PATHS: set[str] = set()
QUERY_CANCEL_EVENTS: dict[str, threading.Event] = {}
QUERY_CANCEL_LOCK = threading.Lock()

# Payload buffer: populated during ingest, cleared at ingest start.
# Maps eve_json_path → {match_key → {"payload": str, "payload_printable": str}}.
# Capped at PAYLOAD_BUFFER_MAX entries per path to bound memory use.
PAYLOAD_BUFFER: dict[str, dict[tuple, dict[str, str]]] = {}
PAYLOAD_BUFFER_MAX = 100_000

# Substring used by the Fast Alert Prefilter (per-module config option).
# Suricata emits compact JSON without whitespace around colons, so this
# literal reliably identifies alert lines and lets ingest skip the much
# more expensive json.loads for non-alert lines (flow/dns/http/stats).
_ALERT_NEEDLE = '"event_type":"alert"'

ALERT_FIELDS = [
    "timestamp", "src_ip", "src_port", "dest_ip", "dest_port", "proto", "severity", "category", "signature",
    "signature_id", "signature_source", "confidence", "payload_printable", "payload", "gid", "action", "metadata",
    "flow_id", "app_proto", "in_iface", "host", "community_id", "tx_id", "packet_info_linktype", "flow_direction", "mitre", "cve",
]

PAYLOAD_MATCH_FIELDS = (
    "timestamp", "src_ip", "src_port", "dest_ip", "dest_port", "proto", "signature_id", "signature", "flow_id",
)

FTS_FIELDS = [
    "timestamp", "src_ip", "src_port", "dest_ip", "dest_port", "proto", "severity", "category", "signature",
    "signature_id", "signature_source", "confidence", "payload_printable", "payload", "metadata", "flow_id",
    "app_proto", "host", "community_id", "mitre", "cve",
]

URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")
HASH_RE = re.compile(r"\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b")
FILENAME_RE = re.compile(r"(?<![\w.-])(?:[A-Za-z]:\\[^\s\"'<>]+|/[\w./-]+|[\w.-]+\.(?:exe|dll|ps1|bat|cmd|sh|py|pl|js|jar|zip|rar|7z|tar|gz|pdf|docx?|xlsx?|txt|conf|ini|log))(?![\w.-])", re.IGNORECASE)
COMMAND_RE = re.compile(r"\b(?:cmd\.exe|powershell(?:\.exe)?|pwsh|bash|/bin/sh|sh\s+-c|curl|wget|python(?:3)?|perl|nc|ncat|certutil|rundll32|regsvr32)\b[^\r\n]*", re.IGNORECASE)
FILE_EXTENSIONS = {"exe", "dll", "ps1", "bat", "cmd", "sh", "py", "pl", "js", "jar", "zip", "rar", "7z", "tar", "gz", "pdf", "doc", "docx", "xls", "xlsx", "txt", "conf", "ini", "log"}


def ids_config() -> dict[str, Any]:
    with get_db() as db:
        row = db.execute("SELECT config FROM opensmart_modules WHERE name = 'Network IDS'").fetchone()
    config = json.loads(row["config"] or "{}") if row else {}
    eve_source = str(config.get("eve_source", "external")).strip().lower()
    if eve_source not in ("external", "native"):
        eve_source = "external"
    eve_json_path = str(NATIVE_SURICATA_EVE_PATH) if eve_source == "native" else str(config.get("eve_json_path", ""))
    return {
        "eve_source": eve_source,
        "eve_json_path": eve_json_path,
        "summary_refresh_minutes": int(config.get("summary_refresh_minutes", 5) or 5),
        "initial_ingestion_gb": str(config.get("initial_ingestion_gb", "2")),
        "default_top_n": int(config.get("default_top_n", 10) or 10),
        "analysis_page_size": int(config.get("analysis_page_size", 30) or 30),
        "details_max_rows": int(config.get("details_max_rows", 500) or 500),
        "details_page_size": int(config.get("details_page_size", 100) or 100),
        "geoip_db_path": str(config.get("geoip_db_path", "")),
        "keep_empty_alerts": str(config.get("keep_empty_alerts", "false")).strip().lower() in ("1", "true", "yes", "on"),
        "index_payload_printable": str(config.get("index_payload_printable", "true")).strip().lower() not in ("0", "false", "no", "off"),
        "fast_alert_prefilter": str(config.get("fast_alert_prefilter", "true")).strip().lower() not in ("0", "false", "no", "off"),
        "track_critical_alerts": str(config.get("track_critical_alerts", "off")).strip().lower(),
    }


def keep_empty_alerts() -> bool:
    """Read the per-module config that controls whether eve.json events with
    event_type='alert' but no signature_id/signature are kept. Default false:
    only true IDS detections are stored."""
    return ids_config()["keep_empty_alerts"]


def index_payload_printable() -> bool:
    """Read the per-module config controlling whether decoded payload is
    indexed at ingest. Default true: payload_printable is stored and
    searchable. When false, only payload (base64) is stored and decoding
    happens on-the-fly when results are returned."""
    return ids_config()["index_payload_printable"]


def config_status() -> dict[str, Any]:
    config = ids_config()
    path = Path(config["eve_json_path"]) if config["eve_json_path"] else None
    ok = bool(path and path.is_file())
    state = read_state(config["eve_json_path"])
    first_ingestion_required = eve_ingest.ids_first_ingestion_required(config["eve_json_path"], eve_ingest.shared_config())
    if ok:
        detail = "eve.json is readable"
    elif config["eve_source"] == "native":
        detail = "Native Suricata container is not running yet, so eve.json does not exist."
    else:
        detail = "Configure a readable local eve.json path for Network IDS."
    return {
        **config,
        "configured": bool(config["eve_json_path"]),
        "readable": ok,
        "detail": detail,
        "first_ingestion_required": first_ingestion_required,
        **state,
    }


def read_state(path: str) -> dict[str, Any]:
    return eve_ingest.read_ids_state(path)


def default_state(status: str) -> dict[str, Any]:
    return eve_ingest.default_state(status)


def maybe_start_refresh(force: bool = False) -> None:
    from . import network_traffic
    shared = eve_ingest.shared_config()
    path = shared.get("eve_json_path", "")
    force_network_reindex = bool(
        force
        and shared.get("network_enabled")
        and shared.get("network_event_types")
        and not eve_ingest.ids_first_ingestion_required(path, shared)
        and not network_traffic.network_event_count(path)
    )
    eve_ingest.maybe_start_refresh(force, force_network_reindex=force_network_reindex)


def ingest_eve_json(path_value: str) -> None:
    if not INGEST_LOCK.acquire(blocking=False):
        logger.info("IDS ingest skipped: another ingest already running for %s", path_value)
        return
    path = Path(path_value)
    t_start = time.monotonic()
    # Clear per-path payload buffer and artifact readiness so they are rebuilt fresh.
    PAYLOAD_BUFFER.pop(path_value, None)
    ARTIFACT_READY_PATHS.discard(path_value)
    try:
        stat = path.stat()
        with get_network_ids_db() as db:
            row = db.execute("SELECT byte_offset, file_size FROM network_ids_ingest_state WHERE eve_json_path = ?", (str(path),)).fetchone()
            offset = int(row["byte_offset"] if row else 0)
            if offset > stat.st_size:
                logger.info("IDS ingest: file truncated (offset=%d > size=%d), resetting state", offset, stat.st_size)
                offset = 0
                db.execute("DELETE FROM network_ids_alerts WHERE eve_json_path = ?", (str(path),))
                db.execute("DELETE FROM network_ids_alerts_fts WHERE eve_json_path = ?", (str(path),))
            delta_bytes = max(0, stat.st_size - offset)
            logger.info("IDS ingest started: path=%s offset=%d delta_bytes=%d file_size=%d", path, offset, delta_bytes, stat.st_size)
            db.execute(
                """
                INSERT INTO network_ids_ingest_state (eve_json_path, file_size, file_mtime, byte_offset, refresh_status, progress_percent,
                    current_action, last_check_started_at, last_check_bytes_total, last_check_bytes_read, last_check_lines_read, last_check_alerts_read, error)
                VALUES (?, ?, ?, ?, 'running', 0, 'Loading 5 min delta', ?, ?, 0, 0, 0, '')
                ON CONFLICT(eve_json_path) DO UPDATE SET file_size = excluded.file_size, file_mtime = excluded.file_mtime,
                    refresh_status = 'running', progress_percent = 0, current_action = 'Loading 5 min delta',
                    last_check_started_at = excluded.last_check_started_at, last_check_bytes_total = excluded.last_check_bytes_total,
                    last_check_bytes_read = 0, last_check_lines_read = 0, last_check_alerts_read = 0, error = ''
                """,
                (str(path), stat.st_size, stat.st_mtime, offset, now_iso(), delta_bytes),
            )
            db.commit()

        malformed = 0
        lines = 0
        alerts_read = 0
        non_alerts = 0
        keep_empty = keep_empty_alerts()
        index_pp = index_payload_printable()
        prefilter = ids_config()["fast_alert_prefilter"]
        batch: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(offset)
            while line := handle.readline():
                lines += 1
                if prefilter and _ALERT_NEEDLE not in line:
                    # Cheap fast-path: skip flow/dns/http/stats/etc. without
                    # paying the json.loads cost. Anything that could be an
                    # alert still flows through the full path below.
                    non_alerts += 1
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    malformed += 1
                    continue
                record = normalize_alert(event, keep_empty=keep_empty, index_pp=index_pp)
                if record:
                    batch.append(record)
                    alerts_read += 1
                else:
                    # Includes flow/dns/http/fileinfo/stats/etc. (event_type != 'alert')
                    # and, when keep_empty is False, alert events with no signature_id.
                    non_alerts += 1
                if len(batch) >= 2000:
                    write_alerts(str(path), batch)
                    batch.clear()
                    bytes_read = handle.tell() - offset
                    update_progress(str(path), bytes_read, max(0, stat.st_size - offset), lines, alerts_read, non_alerts)
                    logger.debug("IDS ingest progress: lines=%d alerts=%d non_alerts=%d bytes_read=%d", lines, alerts_read, non_alerts, bytes_read)
            if batch:
                write_alerts(str(path), batch)
            final_offset = handle.tell()
        elapsed = time.monotonic() - t_start
        logger.info(
            "IDS ingest completed: path=%s lines=%d alerts=%d non_alerts=%d malformed=%d bytes_read=%d elapsed=%.2fs",
            path, lines, alerts_read, non_alerts, malformed, max(0, final_offset - offset), elapsed,
        )
        # Bulk artifact extraction — single post-ingest pass, much faster than per-alert inline.
        logger.info("IDS artifact rebuild starting: path=%s", path)
        with get_network_ids_db() as db:
            db.execute(
                "UPDATE network_ids_ingest_state SET current_action = 'Rebuilding artifact index' WHERE eve_json_path = ?",
                (str(path),),
            )
            db.commit()
        with get_network_ids_db() as db:
            rebuild_artifact_index(db, str(path))
        ARTIFACT_READY_PATHS.add(path_value)
        logger.info("IDS artifact rebuild complete: path=%s", path)
        with get_network_ids_db() as db:
            db.execute(
                """
                UPDATE network_ids_ingest_state SET file_size = ?, file_mtime = ?, byte_offset = ?, lines_read = lines_read + ?,
                    refresh_status = 'idle', progress_percent = 100, current_action = 'Idle', last_check_finished_at = ?,
                    last_check_bytes_read = ?, last_check_lines_read = ?, last_check_alerts_read = ?, last_check_non_alerts = ?,
                    last_updated = ?, error = ? WHERE eve_json_path = ?
                """,
                (stat.st_size, stat.st_mtime, final_offset, lines, now_iso(), max(0, final_offset - offset), lines, alerts_read, non_alerts, now_iso(), f"malformed lines: {malformed}" if malformed else "", str(path)),
            )
            db.commit()
        SUMMARY_CACHE.clear()
    except OSError as error:
        logger.error("IDS ingest error: path=%s error=%s", path_value, error)
        with get_network_ids_db() as db:
            db.execute(
                "INSERT INTO network_ids_ingest_state (eve_json_path, refresh_status, current_action, error) VALUES (?, 'error', 'Error', ?) ON CONFLICT(eve_json_path) DO UPDATE SET refresh_status = 'error', current_action = 'Error', error = excluded.error",
                (str(path), str(error)),
            )
            db.commit()
    finally:
        INGEST_LOCK.release()


def _alert_event_hash(row: dict[str, Any]) -> str:
    key = "|".join(
        str(row.get(f, ""))
        for f in ("timestamp", "flow_id", "signature_id", "src_ip", "dest_ip", "src_port", "dest_port")
    )
    return compute_event_hash(key)


def write_alerts(path: str, rows: list[dict[str, Any]]) -> None:
    columns = ",".join(["eve_json_path", *ALERT_FIELDS, "ingested_at", "event_hash"])
    placeholders = ",".join("?" for _ in ["eve_json_path", *ALERT_FIELDS, "ingested_at", "event_hash"])
    buf = PAYLOAD_BUFFER.setdefault(path, {})
    buf_full = len(buf) >= PAYLOAD_BUFFER_MAX
    has_critical_alerts = False
    with get_network_ids_db() as db:
        for row in rows:
            cursor = db.execute(
                f"INSERT OR IGNORE INTO network_ids_alerts ({columns}) VALUES ({placeholders})",
                (path, *(str(row.get(field, "")) for field in ALERT_FIELDS), now_iso(), _alert_event_hash(row)),
            )
            if cursor.rowcount == 0:
                # Duplicate event — FTS and artifacts already written on original insert.
                continue
            alert_id = int(cursor.lastrowid)
            if str(row.get("severity", "")).lower() in ("1", "critical"):
                has_critical_alerts = True
            write_alert_fts(db, alert_id, path, row)
            artifact_text = str(row.get("payload_printable", "")) or decode_payload(row.get("payload", ""))
            write_alert_artifacts(db, alert_id, path, artifact_text, str(row.get("timestamp", "")))
            # Populate payload buffer (bounded) for O(1) enrichment lookups later.
            if not buf_full:
                p = str(row.get("payload", ""))
                pp = str(row.get("payload_printable", ""))
                if p or pp:
                    buf[payload_match_key(row)] = {"payload": p, "payload_printable": pp}
                    buf_full = len(buf) >= PAYLOAD_BUFFER_MAX
        db.commit()
    if has_critical_alerts:
        from . import notifications

        notifications.notify_ids_critical_alerts(path)


def write_alert_fts(db: sqlite3.Connection, alert_id: int, path: str, row: dict[str, Any]) -> None:
    columns = ["alert_id", "eve_json_path", *FTS_FIELDS]
    placeholders = ",".join("?" for _ in columns)
    db.execute(
        f"INSERT INTO network_ids_alerts_fts ({','.join(columns)}) VALUES ({placeholders})",
        (alert_id, path, *(str(row.get(field, "")) for field in FTS_FIELDS)),
    )


def write_alert_artifacts(db: sqlite3.Connection, alert_id: int, path: str, payload_printable: str, timestamp: str = "") -> None:
    for artifact_type, artifact_value in extract_artifacts(payload_printable):
        db.execute(
            """
            INSERT OR IGNORE INTO network_ids_artifacts (eve_json_path, alert_id, artifact_type, artifact_value, timestamp, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (path, alert_id, artifact_type, artifact_value, timestamp, now_iso()),
        )


def extract_artifacts(value: str) -> set[tuple[str, str]]:
    if not value:
        return set()
    artifacts: set[tuple[str, str]] = set()
    urls = {clean_artifact(item) for item in URL_RE.findall(value)}
    for item in urls:
        if item:
            artifacts.add(("url", item))
            host = re.sub(r"^[a-z]+://", "", item, flags=re.IGNORECASE).split("/", 1)[0].split(":", 1)[0]
            if host and not IP_RE.fullmatch(host):
                artifacts.add(("domain", host.lower()))
    for item in EMAIL_RE.findall(value):
        artifacts.add(("email", item.lower()))
    for item in IP_RE.findall(value):
        parts = item.split(".")
        if all(0 <= int(part) <= 255 for part in parts):
            artifacts.add(("ip", item))
    for item in DOMAIN_RE.findall(value):
        cleaned = clean_artifact(item).lower()
        suffix = cleaned.rsplit(".", 1)[-1] if "." in cleaned else ""
        if cleaned and suffix not in FILE_EXTENSIONS and not EMAIL_RE.search(cleaned) and not IP_RE.fullmatch(cleaned):
            artifacts.add(("domain", cleaned))
    for item in HASH_RE.findall(value):
        artifacts.add(("hash", item.lower()))
    for item in FILENAME_RE.findall(value):
        cleaned = clean_artifact(item)
        basename = cleaned.replace("\\", "/").rsplit("/", 1)[-1]
        if cleaned and not cleaned.startswith("//") and "." in basename:
            artifacts.add(("filename", cleaned))
    for item in COMMAND_RE.findall(value):
        cleaned = clean_artifact(item)
        if cleaned:
            artifacts.add(("command_line", cleaned[:500]))
    return artifacts


def clean_artifact(value: str) -> str:
    return value.strip(" \t\r\n\"'()[]{}<>,;")


def update_progress(path: str, bytes_read: int, bytes_total: int, lines: int, alerts_read: int, non_alerts: int = 0) -> None:
    percent = 100 if bytes_total <= 0 else min(99, int((bytes_read / bytes_total) * 100))
    with get_network_ids_db() as db:
        db.execute(
            """
            UPDATE network_ids_ingest_state SET progress_percent = ?, last_check_bytes_read = ?,
                last_check_lines_read = ?, last_check_alerts_read = ?, last_check_non_alerts = ? WHERE eve_json_path = ?
            """,
            (percent, bytes_read, lines, alerts_read, non_alerts, path),
        )
        db.commit()
    SUMMARY_CACHE.clear()


def parse_time(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def normalize_alert(event: dict[str, Any], keep_empty: bool = False, index_pp: bool = True) -> dict[str, Any] | None:
    """Convert a raw eve.json event into a normalized IDS alert row.

    eve.json is a multiplexed Suricata log: it contains many event_type
    streams (flow, dns, http, fileinfo, stats, netflow, anomaly, tls, ssh,
    smtp, etc.) plus the IDS alert stream. Only event_type='alert' lines are
    candidate IDS hits.

    Suricata occasionally emits alert-typed records with an empty alert
    sub-object (no signature_id, no signature) — typically internal/stats
    or rule-engine bookkeeping events. Those are dropped by default; set
    the Network IDS module config `keep_empty_alerts` to `true` to keep
    them.

    When `index_pp` is False, the decoded `payload_printable` is NOT
    computed at ingest. It is left as an empty string and decoded
    on-the-fly at query time.

    Returns None for any line that should not be ingested as an IDS alert.
    """
    if event.get("event_type") != "alert":
        return None
    alert = event.get("alert") or {}
    if not keep_empty and not alert.get("signature_id") and not alert.get("signature"):
        return None
    metadata = alert.get("metadata") or {}
    packet_info = event.get("packet_info") or {}
    signature = str(alert.get("signature", ""))
    payload = str(event.get("payload", ""))
    payload_printable = str(event.get("payload_printable", ""))
    if index_pp and not payload_printable and payload:
        payload_printable = decode_payload(payload)
    elif not index_pp:
        payload_printable = ""
    return {
        "timestamp": str(event.get("timestamp", "")),
        "src_ip": str(event.get("src_ip", "")),
        "src_port": event.get("src_port", ""),
        "dest_ip": str(event.get("dest_ip", "")),
        "dest_port": event.get("dest_port", ""),
        "proto": str(event.get("proto", "")),
        "severity": str(alert.get("severity", "")),
        "category": str(alert.get("category", "")),
        "signature": signature,
        "signature_id": str(alert.get("signature_id", "")),
        "signature_source": signature_source(signature, metadata),
        "confidence": confidence(metadata),
        "payload_printable": payload_printable,
        "payload": payload,
        "gid": str(alert.get("gid", "")),
        "action": str(alert.get("action", "")),
        "metadata": json.dumps(metadata, sort_keys=True) if metadata else "",
        "flow_id": str(event.get("flow_id", "")),
        "app_proto": str(event.get("app_proto", "")),
        "in_iface": str(event.get("in_iface", "")),
        "host": str(event.get("host", "")),
        "community_id": str(event.get("community_id", "")),
        "tx_id": str(event.get("tx_id", "")),
        "packet_info_linktype": str(packet_info.get("linktype", "")),
        "flow_direction": str(event.get("flow", {}).get("direction", "")),
        "mitre": metadata_value(metadata, ("mitre_tactic_id", "mitre_technique_id", "attack_target")),
        "cve": metadata_value(metadata, ("cve", "cve_id")),
    }


def signature_source(signature: str, metadata: dict[str, Any]) -> str:
    source = metadata_value(metadata, ("signature_severity", "deployment", "source"))
    upper = f"{signature} {source}".upper()
    if "ET " in upper or upper.startswith("ET"):
        return "ET"
    if "GPL" in upper:
        return "GPL"
    if "SNORT" in upper or "VRT" in upper or "THIRD" in upper:
        return "third-party"
    return "unknown"


def confidence(metadata: dict[str, Any]) -> str:
    return metadata_value(metadata, ("confidence", "signature_severity", "severity")) or "unknown"


def metadata_value(metadata: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = metadata.get(key)
        if isinstance(value, list):
            return ", ".join(str(item) for item in value)
        if value:
            return str(value)
    return ""


def decode_payload(payload: Any) -> str:
    if not payload:
        return ""
    value = "".join(str(payload).split())
    if not value:
        return ""
    padding = (-len(value)) % 4
    value = f"{value}{'=' * padding}"
    try:
        decoded = base64.b64decode(value, validate=False)
    except (binascii.Error, ValueError):
        return ""
    # Apply strings-like filter: keep only printable ASCII (0x20-0x7e) + tab/LF/CR
    text = "".join(chr(b) for b in decoded if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D))
    # Collapse whitespace runs to single space
    return " ".join(text.split()).strip()


def decode_rows_payload(rows: list[dict[str, Any]], index_pp: bool) -> None:
    """When `index_pp` is False, populate `payload_printable` on each row
    on-the-fly from the stored `payload` (base64). Mutates rows in place.
    No-op when `index_pp` is True. No DB writeback."""
    if index_pp:
        return
    for row in rows:
        if not row.get("payload_printable") and row.get("payload"):
            row["payload_printable"] = decode_payload(row["payload"])


def where_clause(filters: dict[str, str]) -> tuple[str, list[Any]]:
    config = ids_config()
    path = config["eve_json_path"]
    clauses = ["eve_json_path = ?"]
    params: list[Any] = [path]
    start_time = filters.get("start_time", "")
    end_time = filters.get("end_time", "")
    if start_time:
        clauses.append("timestamp >= ?")
        params.append(start_time)
    if end_time:
        clauses.append("timestamp <= ?")
        params.append(end_time)
    if not start_time and not end_time:
        cutoff = cutoff_for(filters.get("timeframe", "1d"))
        if cutoff:
            clauses.append("timestamp >= ?")
            params.append(cutoff.isoformat())
    q = filters.get("q", "")
    if q:
        fts = fts_query(q)
        if fts:
            ensure_fts_index(path)
            clauses.append("id IN (SELECT alert_id FROM network_ids_alerts_fts WHERE network_ids_alerts_fts MATCH ?)")
            params.append(fts)
    for key, value in filters.items():
        if key in ALERT_FIELDS and value:
            clauses.append(f"{key} LIKE ?")
            params.append(f"%{value}%")
    return " WHERE " + " AND ".join(clauses), params


def alerts_query_parts(filters: dict[str, str]) -> tuple[str, str, list[Any]]:
    config = ids_config()
    path = config["eve_json_path"]
    clauses = ["network_ids_alerts.eve_json_path = ?"]
    params: list[Any] = [path]
    fts = fts_query(filters.get("q", ""))
    if fts:
        ensure_fts_index(path)
        clauses.append("network_ids_alerts_fts MATCH ?")
        params.append(fts)
        from_sql = "network_ids_alerts JOIN network_ids_alerts_fts ON network_ids_alerts_fts.alert_id = network_ids_alerts.id"
    else:
        from_sql = "network_ids_alerts"
    if filters.get("tracking_status") == "new":
        from_sql += " LEFT JOIN network_ids_alert_tracking ON network_ids_alert_tracking.alert_id = network_ids_alerts.id"
        clauses.append("network_ids_alerts.severity IN ('1', 'critical')")
        clauses.append("COALESCE(network_ids_alert_tracking.status, 'new') != 'acknowledged'")
    start_time = filters.get("start_time", "")
    end_time = filters.get("end_time", "")
    if start_time:
        clauses.append("network_ids_alerts.timestamp >= ?")
        params.append(start_time)
    if end_time:
        clauses.append("network_ids_alerts.timestamp <= ?")
        params.append(end_time)
    if not start_time and not end_time:
        cutoff = cutoff_for(filters.get("timeframe", "1d"))
        if cutoff:
            clauses.append("network_ids_alerts.timestamp >= ?")
            params.append(cutoff.isoformat())
    for key, value in filters.items():
        if key in ALERT_FIELDS and value:
            clauses.append(f"network_ids_alerts.{key} LIKE ?")
            params.append(f"%{value}%")
    return from_sql, " WHERE " + " AND ".join(clauses), params


def fts_query(value: str) -> str:
    tokens = re.findall(r"[A-Za-z0-9_]+", value)
    if not tokens:
        return ""
    return " AND ".join(f'"{token}"' for token in tokens[:12])


def ensure_fts_index(path: str) -> None:
    if not path or path in FTS_READY_PATHS:
        return
    with get_network_ids_db() as db:
        alerts_count = db.execute("SELECT COUNT(*) AS count FROM network_ids_alerts WHERE eve_json_path = ?", (path,)).fetchone()["count"]
        fts_count = db.execute("SELECT COUNT(*) AS count FROM network_ids_alerts_fts WHERE eve_json_path = ?", (path,)).fetchone()["count"]
        if alerts_count and fts_count < alerts_count:
            logger.info("IDS FTS index rebuild needed: alerts=%d fts=%d path=%s", alerts_count, fts_count, path)
            rebuild_fts_index(db, path)
            logger.info("IDS FTS index rebuild complete: path=%s", path)
        FTS_READY_PATHS.add(path)


def rebuild_fts_index(db: sqlite3.Connection, path: str) -> None:
    db.execute("DELETE FROM network_ids_alerts_fts WHERE eve_json_path = ?", (path,))
    rows = db.execute(
        f"SELECT id,{','.join(FTS_FIELDS)} FROM network_ids_alerts WHERE eve_json_path = ?",
        (path,),
    ).fetchall()
    for row in rows:
        data = dict(row)
        alert_id = int(data.pop("id"))
        write_alert_fts(db, alert_id, path, data)
    db.commit()


def ensure_artifact_index(path: str) -> None:
    if not path or path in ARTIFACT_READY_PATHS:
        return
    try:
        with get_network_ids_db() as db:
            db.execute("SELECT 1 FROM network_ids_artifacts WHERE eve_json_path = ? LIMIT 1", (path,)).fetchone()
        ARTIFACT_READY_PATHS.add(path)
    except sqlite3.OperationalError:
        logger.warning("IDS ensure_artifact_index: DB locked, will retry on next request")


def rebuild_artifact_index(db: sqlite3.Connection, path: str) -> None:
    with ARTIFACT_REBUILD_LOCK:
        index_pp = ids_config()["index_payload_printable"]
        db.execute("DELETE FROM network_ids_artifacts WHERE eve_json_path = ?", (path,))
        if index_pp:
            rows = db.execute("SELECT id, payload_printable, timestamp FROM network_ids_alerts WHERE eve_json_path = ? AND payload_printable != ''", (path,)).fetchall()
            for row in rows:
                write_alert_artifacts(db, int(row["id"]), path, str(row["payload_printable"]), str(row["timestamp"] or ""))
        else:
            rows = db.execute("SELECT id, payload, timestamp FROM network_ids_alerts WHERE eve_json_path = ? AND payload != ''", (path,)).fetchall()
            for row in rows:
                decoded = decode_payload(row["payload"])
                if decoded:
                    write_alert_artifacts(db, int(row["id"]), path, decoded, str(row["timestamp"] or ""))
        db.commit()
        # Invalidate cached artifact summaries for this path.
        for key in [k for k in ARTIFACT_CACHE if k[0] == path]:
            ARTIFACT_CACHE.pop(key, None)
        logger.info("IDS artifact index rebuilt: %d rows processed for path=%s index_pp=%s", len(rows), path, index_pp)


def cutoff_for(timeframe: str) -> datetime | None:
    if timeframe == "all":
        return None
    return datetime.now(timezone.utc) - TIMEFRAMES.get(timeframe, TIMEFRAMES["1d"])


def cancel_alert_query(query_id: str) -> None:
    if not query_id:
        return
    with QUERY_CANCEL_LOCK:
        event = QUERY_CANCEL_EVENTS.get(query_id)
    if event:
        logger.info("IDS alert query cancel requested: query_id=%s", query_id)
        event.set()


def cancel_details_query(query_id: str) -> None:
    if not query_id:
        return
    with QUERY_CANCEL_LOCK:
        event = QUERY_CANCEL_EVENTS.get(query_id)
    if event:
        logger.info("IDS details query cancel requested: query_id=%s", query_id)
        event.set()


def query_cancel_event(query_id: str) -> threading.Event | None:
    if not query_id:
        return None
    with QUERY_CANCEL_LOCK:
        event = QUERY_CANCEL_EVENTS.setdefault(query_id, threading.Event())
    return event


def release_query_cancel_event(query_id: str) -> None:
    if not query_id:
        return
    with QUERY_CANCEL_LOCK:
        QUERY_CANCEL_EVENTS.pop(query_id, None)


def alerts(filters: dict[str, str]) -> dict[str, Any]:
    maybe_start_refresh(False)
    query_id = filters.get("query_id", "")
    cancel_event = query_cancel_event(query_id)
    from_sql, where, params = alerts_query_parts(filters)
    sort = filters.get("sort") if filters.get("sort") in ALERT_FIELDS else "timestamp"
    direction = "ASC" if filters.get("direction") == "asc" else "DESC"
    offset = max(0, int(filters.get("offset") or 0))
    limit = min(1000, max(1, int(filters.get("limit") or ids_config()["analysis_page_size"])))
    logger.info("IDS alert query: query_id=%s sort=%s direction=%s offset=%d limit=%d", query_id, sort, direction, offset, limit)
    selected_fields = "network_ids_alerts.id AS _alert_id," + ",".join(f"network_ids_alerts.{field} AS {field}" for field in ALERT_FIELDS)
    try:
        with get_network_ids_db() as db:
            if cancel_event:
                db.set_progress_handler(lambda: 1 if cancel_event.is_set() else 0, 1000)
            rows = db.execute(f"SELECT {selected_fields} FROM {from_sql}{where} ORDER BY network_ids_alerts.{sort} {direction} LIMIT ? OFFSET ?", (*params, limit + 1, offset)).fetchall()
            if cancel_event:
                db.set_progress_handler(None, 0)
        has_more = len(rows) > limit
        alert_rows = [dict(row) for row in rows[:limit]]
        enrich_payloads_from_eve(alert_rows, cancel_event)
        decode_rows_payload(alert_rows, ids_config()["index_payload_printable"])
        apply_tracking_status(alert_rows)
        for row in alert_rows:
            row["alert_id"] = row.pop("_alert_id", "")
        estimated_total = offset + len(alert_rows) + (1 if has_more else 0)
        logger.info("IDS alert query complete: query_id=%s returned=%d has_more=%s", query_id, len(alert_rows), has_more)
        return {"alerts": alert_rows, "total": estimated_total, "has_more": has_more, **read_state(ids_config()["eve_json_path"])}
    except sqlite3.OperationalError as error:
        if cancel_event and cancel_event.is_set():
            logger.info("IDS alert query cancelled: query_id=%s", query_id)
            return {"alerts": [], "total": 0, "has_more": False, "cancelled": True, **read_state(ids_config()["eve_json_path"])}
        raise error
    finally:
        release_query_cancel_event(query_id)


def enrich_payloads_from_eve(rows: list[dict[str, Any]], cancel_event: threading.Event | None = None) -> None:
    targets = [row for row in rows if missing_payload(row)]
    if not targets:
        return
    path_value = ids_config()["eve_json_path"]
    if not path_value:
        return
    buf = PAYLOAD_BUFFER.get(path_value)
    if not buf:
        logger.debug("IDS payload enrichment: buffer empty for path=%s, skipping %d rows", path_value, len(targets))
        return
    changed: list[dict[str, Any]] = []
    resolved = 0
    for row in targets:
        if cancel_event and cancel_event.is_set():
            break
        entry = buf.get(payload_match_key(row))
        if not entry:
            continue
        before = (row.get("payload"), row.get("payload_printable"))
        if not row.get("payload") and entry["payload"]:
            row["payload"] = entry["payload"]
        if not row.get("payload_printable") and entry["payload_printable"]:
            row["payload_printable"] = entry["payload_printable"]
        if row.get("_alert_id") and before != (row.get("payload"), row.get("payload_printable")):
            changed.append(row)
        resolved += 1
    logger.debug("IDS payload enrichment: resolved=%d skipped=%d changed=%d", resolved, len(targets) - resolved, len(changed))
    if changed:
        persist_payload_enrichment(path_value, changed)


def persist_payload_enrichment(path: str, rows: list[dict[str, Any]]) -> None:
    with get_network_ids_db() as db:
        for row in rows:
            alert_id = int(row["_alert_id"])
            db.execute(
                "UPDATE network_ids_alerts SET payload = ?, payload_printable = ? WHERE id = ?",
                (str(row.get("payload", "")), str(row.get("payload_printable", "")), alert_id),
            )
            db.execute("DELETE FROM network_ids_alerts_fts WHERE alert_id = ?", (alert_id,))
            db.execute("DELETE FROM network_ids_artifacts WHERE alert_id = ?", (alert_id,))
            write_alert_fts(db, alert_id, path, row)
            write_alert_artifacts(db, alert_id, path, str(row.get("payload_printable", "")), str(row.get("timestamp", "")))
        db.commit()


def missing_payload(row: dict[str, Any]) -> bool:
    return not row.get("payload") or not row.get("payload_printable")


def payload_match_key(row: dict[str, Any]) -> tuple[str, ...]:
    return tuple(str(row.get(field, "")) for field in PAYLOAD_MATCH_FIELDS)


def apply_tracking_status(rows: list[dict[str, Any]]) -> None:
    ids = [int(row["_alert_id"]) for row in rows if row.get("_alert_id")]
    if not ids:
        return
    placeholders = ",".join("?" for _ in ids)
    with get_network_ids_db() as db:
        tracked = {int(row["alert_id"]): row["status"] for row in db.execute(f"SELECT alert_id, status FROM network_ids_alert_tracking WHERE alert_id IN ({placeholders})", ids).fetchall()}
    for row in rows:
        alert_id = int(row.get("_alert_id") or 0)
        is_critical = str(row.get("severity", "")).lower() in ("1", "critical")
        row["tracking_status"] = tracked.get(alert_id, "new" if is_critical else "")


def acknowledge_alert(alert_id: int, username: str, mode: str = "full") -> None:
    with get_network_ids_db() as db:
        db.execute(
            """
            INSERT INTO network_ids_alert_tracking (alert_id, status, acknowledged_at, acknowledged_by, mode)
            VALUES (?, 'acknowledged', ?, ?, ?)
            ON CONFLICT(alert_id) DO UPDATE SET status = 'acknowledged', acknowledged_at = excluded.acknowledged_at,
                acknowledged_by = excluded.acknowledged_by, mode = excluded.mode
            """,
            (alert_id, now_iso(), username, mode),
        )
        db.commit()
    SUMMARY_CACHE.clear()


def acknowledge_critical(filters: dict[str, str], username: str) -> int:
    critical_filters = {**filters, "severity": "1"}
    where, params = where_clause(critical_filters)
    with get_network_ids_db() as db:
        ids = [int(row["id"]) for row in db.execute(f"SELECT id FROM network_ids_alerts{where}", params).fetchall()]
        for alert_id in ids:
            db.execute(
                """
                INSERT INTO network_ids_alert_tracking (alert_id, status, acknowledged_at, acknowledged_by, mode)
                VALUES (?, 'acknowledged', ?, ?, 'simple')
                ON CONFLICT(alert_id) DO UPDATE SET status = 'acknowledged', acknowledged_at = excluded.acknowledged_at,
                    acknowledged_by = excluded.acknowledged_by, mode = 'simple'
                """,
                (alert_id, now_iso(), username),
            )
        db.commit()
    SUMMARY_CACHE.clear()
    return len(ids)


def critical_new_alert_count(filters: dict[str, str]) -> int:
    critical_filters = {k: v for k, v in filters.items() if k not in ("refresh", "query_id", "top_n")}
    critical_filters["severity"] = "1"
    where, params = where_clause(critical_filters)
    with get_network_ids_db() as db:
        row = db.execute(
            f"""
            SELECT COUNT(*) AS count
            FROM network_ids_alerts
            LEFT JOIN network_ids_alert_tracking ON network_ids_alert_tracking.alert_id = network_ids_alerts.id
            {where} AND COALESCE(network_ids_alert_tracking.status, 'new') != 'acknowledged'
            """,
            params,
        ).fetchone()
    return int(row["count"] if row else 0)


def summary(filters: dict[str, str]) -> dict[str, Any]:
    maybe_start_refresh(filters.get("refresh") == "true")
    config = ids_config()
    query_id = filters.get("query_id", "")
    cancel_event = query_cancel_event(query_id)
    top_n = min(500, max(1, int(filters.get("top_n") or config["default_top_n"])))
    cache_key = json.dumps({**filters, "top_n": top_n}, sort_keys=True)
    ttl = max(1, config["summary_refresh_minutes"]) * 60
    if cache_key in SUMMARY_CACHE:
        created, data = SUMMARY_CACHE[cache_key]
        if time.time() - created < ttl or read_state(config["eve_json_path"])["refresh_status"] == "running":
            logger.debug("IDS summary cache hit: timeframe=%s top_n=%d", filters.get("timeframe"), top_n)
            state = read_state(config["eve_json_path"])
            first_ingestion_required = eve_ingest.ids_first_ingestion_required(config["eve_json_path"], eve_ingest.shared_config())
            return {**data, "cached": True, **state, "initial_ingestion_gb": config["initial_ingestion_gb"], "first_ingestion_required": first_ingestion_required, "is_first_run": state["last_updated"] == "" and state["refresh_status"] == "running"}
    logger.info("IDS summary building: timeframe=%s top_n=%d refresh=%s", filters.get("timeframe"), top_n, filters.get("refresh"))
    where, params = where_clause(filters)
    ensure_artifact_index(config["eve_json_path"])
    try:
        with get_network_ids_db() as db:
            if cancel_event:
                db.set_progress_handler(lambda: 1 if cancel_event.is_set() else 0, 1000)
            rows = [dict(row) for row in db.execute(f"SELECT {','.join(ALERT_FIELDS)} FROM network_ids_alerts{where}", params).fetchall()]
            artifact_rows = artifact_summary_rows(db, config["eve_json_path"], filters, top_n)
            if cancel_event:
                db.set_progress_handler(None, 0)
    except sqlite3.OperationalError as error:
        if cancel_event and cancel_event.is_set():
            return {"cancelled": True, **read_state(config["eve_json_path"])}
        raise error
    finally:
        release_query_cancel_event(query_id)
    logger.info("IDS summary built: total_alerts=%d artifacts=%d", len(rows), len(artifact_rows))
    data = build_summary(rows, top_n)
    data["tables"]["top_artifacts"] = artifact_rows
    data["critical_new_alerts"] = critical_new_alert_count(filters) if config.get("track_critical_alerts") != "off" else 0
    SUMMARY_CACHE[cache_key] = (time.time(), data)
    state = read_state(config["eve_json_path"])
    first_ingestion_required = eve_ingest.ids_first_ingestion_required(config["eve_json_path"], eve_ingest.shared_config())
    return {**data, "cached": False, **state, "initial_ingestion_gb": config["initial_ingestion_gb"], "first_ingestion_required": first_ingestion_required, "is_first_run": state["last_updated"] == "" and state["refresh_status"] == "running"}


def artifact_summary_rows(db: sqlite3.Connection, path: str, filters: dict[str, str], top_n: int) -> list[dict[str, Any]]:
    # Single-table query against network_ids_artifacts using the embedded
    # timestamp column (populated at write/rebuild time). No JOIN to
    # network_ids_alerts — avoids the per-summary scan that previously dominated
    # latency on large artifact tables. Cached per (path, timeframe, top_n)
    # with a TTL = summary_refresh_minutes (invalidated on artifact rebuild).
    timeframe = filters.get("timeframe", "1d")
    cache_key = (path, timeframe, top_n)
    ttl = max(1, ids_config()["summary_refresh_minutes"]) * 60
    cached = ARTIFACT_CACHE.get(cache_key)
    if cached and time.time() - cached[0] < ttl:
        return list(cached[1])

    clauses = ["eve_json_path = ?"]
    params: list[Any] = [path]
    cutoff = cutoff_for(timeframe)
    if cutoff:
        # NOTE: rows ingested before the timestamp column existed have ''.
        # They are excluded from time-windowed queries until the operator runs
        # --reset-data, which rebuilds the artifact index with timestamps.
        clauses.append("timestamp >= ?")
        params.append(cutoff.isoformat())
    rows = db.execute(
        f"""
        SELECT artifact_type, artifact_value, COUNT(DISTINCT alert_id) AS alerts
        FROM network_ids_artifacts
        WHERE {' AND '.join(clauses)}
        GROUP BY artifact_type, artifact_value
        ORDER BY alerts DESC
        LIMIT ?
        """,
        (*params, top_n),
    ).fetchall()
    result = [dict(row) for row in rows]
    ARTIFACT_CACHE[cache_key] = (time.time(), result)
    return result


# Table name → (field_name, label) for Details endpoint
DETAIL_TABLE_FIELDS: dict[str, str] = {
    "top_categories": "category",
    "top_protocols": "proto",
    "top_ports": "port",
    "top_src_ips": "src_ip",
    "top_dest_ips": "dest_ip",
    "interfaces": "in_iface",
    "flow_direction": "flow_direction",
    "mitre": "mitre",
    "cves": "cve",
}


def details_table(filters: dict[str, str]) -> dict[str, Any]:
    """Return full rows for a single named summary table up to details_max_rows."""
    maybe_start_refresh(False)
    config = ids_config()
    table_name = filters.get("table", "")
    top_n = min(int(config["details_max_rows"]), max(1, int(filters.get("top_n") or config["details_max_rows"])))
    timeframe_filter = {k: v for k, v in filters.items() if k in ("timeframe", "q")}
    query_id = filters.get("query_id", "")
    cancel_event = query_cancel_event(query_id)
    logger.info("IDS details_table request: table=%s top_n=%d timeframe=%s query_id=%s", table_name, top_n, timeframe_filter.get("timeframe"), query_id)

    def _install_cancel(db: sqlite3.Connection) -> None:
        if cancel_event:
            db.set_progress_handler(lambda: 1 if cancel_event.is_set() else 0, 1000)

    def _cancelled() -> dict[str, Any]:
        logger.info("IDS details_table cancelled: table=%s query_id=%s", table_name, query_id)
        return {"table": table_name, "rows": [], "total": 0, "cancelled": True}

    try:
        if table_name == "top_artifacts":
            ensure_artifact_index(config["eve_json_path"])
            with get_network_ids_db() as db:
                _install_cancel(db)
                rows = artifact_summary_rows(db, config["eve_json_path"], timeframe_filter, top_n)
            logger.info("IDS details_table result: table=%s rows=%d", table_name, len(rows))
            return {"table": table_name, "rows": rows, "total": len(rows)}

        if table_name in ("top_by_count", "top_by_severity"):
            sort_severity = table_name == "top_by_severity"
            where, params = where_clause(timeframe_filter)
            with get_network_ids_db() as db:
                _install_cancel(db)
                all_rows = [dict(row) for row in db.execute(f"SELECT {','.join(ALERT_FIELDS)} FROM network_ids_alerts{where}", params).fetchall()]
            # top_signature_rows aggregates in Python; check cancel periodically.
            if cancel_event and cancel_event.is_set():
                return _cancelled()
            rows = top_signature_rows(all_rows, top_n, sort_severity, cancel_event)
            if cancel_event and cancel_event.is_set():
                return _cancelled()
            logger.info("IDS details_table result: table=%s rows=%d", table_name, len(rows))
            return {"table": table_name, "rows": rows, "total": len(rows)}

        if table_name in DETAIL_TABLE_FIELDS:
            field = DETAIL_TABLE_FIELDS[table_name]
            if field == "port":
                col_expr = "COALESCE(NULLIF(dest_port,''),src_port,'unknown') AS port"
            else:
                col_expr = f"COALESCE(NULLIF({field},''),'unknown') AS {field}"
            where, params = where_clause(timeframe_filter)
            with get_network_ids_db() as db:
                _install_cancel(db)
                rows = [dict(row) for row in db.execute(
                    f"SELECT {col_expr}, COUNT(*) AS alerts FROM network_ids_alerts{where} GROUP BY {field} ORDER BY alerts DESC LIMIT ?",
                    (*params, top_n),
                ).fetchall()]
            logger.info("IDS details_table result: table=%s rows=%d", table_name, len(rows))
            return {"table": table_name, "rows": rows, "total": len(rows)}

        logger.warning("IDS details_table: unknown table name=%s", table_name)
        return {"table": table_name, "rows": [], "total": 0, "error": "unknown table"}
    except sqlite3.OperationalError as error:
        if cancel_event and cancel_event.is_set():
            return _cancelled()
        raise error
    finally:
        release_query_cancel_event(query_id)


def attack_map(filters: dict[str, str]) -> dict[str, Any]:
    maybe_start_refresh(False)
    config = ids_config()
    mode = filters.get("mode", "src_ip")
    if mode not in {"src_ip", "signature", "severity"}:
        mode = "src_ip"
    top_n = min(200, max(1, int(filters.get("top_n") or config["default_top_n"])))
    query_id = filters.get("query_id", "")
    cancel_event = query_cancel_event(query_id)
    where, params = where_clause({k: v for k, v in filters.items() if k in ("timeframe", "start_time", "end_time", "q")})
    try:
        with get_network_ids_db() as db:
            if cancel_event:
                db.set_progress_handler(lambda: 1 if cancel_event.is_set() else 0, 1000)
            rows = [dict(row) for row in db.execute(
                f"SELECT src_ip, timestamp, signature, severity FROM network_ids_alerts{where}",
                params,
            ).fetchall()]
            if cancel_event:
                db.set_progress_handler(None, 0)
    except sqlite3.OperationalError as error:
        if cancel_event and cancel_event.is_set():
            return {"cancelled": True, "mode": mode, "geo_points": [], "tables": {}, "total_alerts": 0}
        raise error
    finally:
        release_query_cancel_event(query_id)

    db_path = config.get("geoip_db_path", "").strip()
    reader, geoip_detail = _open_geoip_reader(db_path)
    configured = reader is not None
    ip_cache: dict[str, dict[str, Any] | None] = {}
    private_count = 0
    unknown_count = 0
    no_coordinate_count = 0
    by_location: dict[tuple[str, str, float, float], dict[str, Any]] = {}
    src_counter = Counter(row["src_ip"] or "unknown" for row in rows)
    signature_sources: dict[str, set[str]] = defaultdict(set)
    signature_alerts = Counter()
    severity_sources: dict[str, set[str]] = defaultdict(set)
    severity_alerts = Counter()
    src_country: dict[str, str] = {}

    try:
        for index, row in enumerate(rows):
            if cancel_event and (index & 0x3FF) == 0 and cancel_event.is_set():
                return {"cancelled": True, "mode": mode, "geo_points": [], "tables": {}, "total_alerts": len(rows)}
            src_ip = str(row.get("src_ip") or "unknown")
            signature = str(row.get("signature") or "unknown")
            severity = str(row.get("severity") or "unknown")
            signature_sources[signature].add(src_ip)
            signature_alerts[signature] += 1
            severity_sources[severity].add(src_ip)
            severity_alerts[severity] += 1
            lookup = ip_cache.get(src_ip)
            if src_ip not in ip_cache:
                lookup = _lookup_geoip(reader, src_ip) if reader else None
                ip_cache[src_ip] = lookup
                if lookup is None:
                    if _is_private_or_invalid_ip(src_ip):
                        private_count += 1
                    else:
                        unknown_count += 1
            if not lookup:
                continue
            src_country[src_ip] = str(lookup.get("country") or "Unknown")
            lat = lookup.get("lat")
            lon = lookup.get("lon")
            if lat is None or lon is None:
                no_coordinate_count += 1
                continue
            key = (str(lookup.get("country") or "Unknown"), str(lookup.get("city") or ""), float(lat), float(lon))
            point = by_location.setdefault(key, {
                "country": key[0], "city": key[1], "lat": key[2], "lon": key[3],
                "src_ip_count": 0, "alert_count": 0, "signatures": Counter(), "severities": Counter(), "src_ips": set(),
            })
            point["src_ips"].add(src_ip)
            point["src_ip_count"] = len(point["src_ips"])
            point["alert_count"] += 1
            point["signatures"][signature] += 1
            point["severities"][severity] += 1
    finally:
        if reader:
            reader.close()

    geo_points = []
    for point in by_location.values():
        geo_points.append({
            "country": point["country"], "city": point["city"], "lat": point["lat"], "lon": point["lon"],
            "src_ip_count": point["src_ip_count"], "alert_count": point["alert_count"],
            "signatures": dict(point["signatures"]), "severities": dict(point["severities"]),
        })
    geo_points.sort(key=lambda item: (int(item["alert_count"]), int(item["src_ip_count"])), reverse=True)
    return {
        "configured": configured,
        "detail": geoip_detail,
        "mode": mode,
        "total_alerts": len(rows),
        "mapped_alerts": sum(int(point["alert_count"]) for point in geo_points),
        "unmapped_alerts": max(0, len(rows) - sum(int(point["alert_count"]) for point in geo_points)),
        "geo_points": geo_points[:top_n],
        "tables": {
            "top_src_ips": [{"src_ip": ip, "alerts": count, "country": src_country.get(ip, "")} for ip, count in src_counter.most_common(top_n)],
            "top_signatures": [{"signature": signature, "sources": len(signature_sources[signature]), "alerts": count} for signature, count in signature_alerts.most_common(top_n)],
            "severity_by_source": [{"severity": severity, "sources": len(severity_sources[severity]), "alerts": count} for severity, count in severity_alerts.most_common(top_n)],
        },
        "unmapped_reasons": {"private_or_invalid_sources": private_count, "unknown_geoip_sources": unknown_count, "country_without_coordinates": no_coordinate_count},
    }


def _open_geoip_reader(path: str):
    if not path:
        return None, "Configure a local MaxMind GeoLite2 City MMDB path in Network IDS settings."
    if not Path(path).is_file():
        return None, f"GeoIP database is not readable: {path}"
    try:
        import maxminddb  # type: ignore
    except ImportError:
        return None, "The optional maxminddb package is not installed."
    try:
        return maxminddb.open_database(path), "GeoIP database is configured."
    except Exception as error:
        return None, f"Could not open GeoIP database: {error}"


def _lookup_geoip(reader, ip_value: str) -> dict[str, Any] | None:
    if _is_private_or_invalid_ip(ip_value) or reader is None:
        return None
    try:
        data = reader.get(ip_value) or {}
    except Exception:
        return None
    location = data.get("location") or {}
    country = data.get("country") or data.get("registered_country") or {}
    city = data.get("city") or {}
    return {
        "country": (country.get("names") or {}).get("en") or country.get("iso_code") or "Unknown",
        "city": (city.get("names") or {}).get("en") or "",
        "lat": location.get("latitude"),
        "lon": location.get("longitude"),
    }


def _is_private_or_invalid_ip(ip_value: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_value)
    except ValueError:
        return True
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified


def build_summary(rows: list[dict[str, Any]], top_n: int) -> dict[str, Any]:
    severity = Counter(row["severity"] or "unknown" for row in rows)
    category = Counter(row["category"] or "unknown" for row in rows)
    source = Counter(row["signature_source"] or "unknown" for row in rows)
    src_ips = Counter(row["src_ip"] or "unknown" for row in rows)
    dest_ips = Counter(row["dest_ip"] or "unknown" for row in rows)
    protocols = Counter(row["proto"] or "unknown" for row in rows)
    ports = Counter(str(row["dest_port"] or row["src_port"] or "unknown") for row in rows)
    flow = Counter(row["flow_direction"] or "unknown" for row in rows)
    mitre = Counter(row["mitre"] or "unknown" for row in rows if row["mitre"])
    cve = Counter(row["cve"] or "unknown" for row in rows if row["cve"])
    iface = Counter(row["in_iface"] or "unknown" for row in rows)
    trend = Counter((row["timestamp"] or "unknown")[:13] for row in rows)
    trend_by_severity: dict[str, Counter] = defaultdict(Counter)
    for row in rows:
        trend_by_severity[(row["timestamp"] or "unknown")[:13]][row["severity"] or "unknown"] += 1
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counters": {"total_alerts": len(rows), "severity": dict(severity), "total_categories": len(category), "total_signature_sources": len(source)},
        "tables": {
            "top_by_severity": top_signature_rows(rows, top_n, True),
            "top_by_count": top_signature_rows(rows, top_n),
            "top_categories": counter_rows(category, top_n, "category"),
            "top_src_ips": counter_rows(src_ips, top_n, "src_ip"),
            "top_dest_ips": counter_rows(dest_ips, top_n, "dest_ip"),
            "top_ports": counter_rows(ports, top_n, "port"),
            "top_protocols": counter_rows(protocols, top_n, "proto"),
            "flow_direction": counter_rows(flow, top_n, "flow_direction"),
            "mitre": counter_rows(mitre, top_n, "mitre"),
            "cves": counter_rows(cve, top_n, "cve"),
            "interfaces": counter_rows(iface, top_n, "in_iface"),
            "trend": [{"bucket": key, "alerts": value} for key, value in sorted(trend.items())[-top_n:]],
            "trend_by_severity": [
                {"bucket": key, **dict(value)} for key, value in sorted(trend_by_severity.items())[-top_n:]
            ],
        },
    }


def top_signature_rows(rows: list[dict[str, Any]], top_n: int, sort_severity: bool = False, cancel_event: threading.Event | None = None) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for index, row in enumerate(rows):
        if cancel_event and (index & 0x3FF) == 0 and cancel_event.is_set():
            return []
        grouped[row["signature"] or "unknown"].append(row)
    result = []
    for signature, items in grouped.items():
        sample = items[0]
        result.append({"alerts": len(items), "category": sample["category"], "severity": sample["severity"], "confidence": sample["confidence"], "signature_id": sample["signature_id"], "proto": sample["proto"], "signature": signature})
    key = (lambda row: (int(row["severity"] or 999), -row["alerts"])) if sort_severity else (lambda row: row["alerts"])
    return sorted(result, key=key, reverse=not sort_severity)[:top_n]


def counter_rows(counter: Counter, top_n: int, field: str) -> list[dict[str, Any]]:
    return [{field: key, "alerts": value} for key, value in counter.most_common(top_n)]

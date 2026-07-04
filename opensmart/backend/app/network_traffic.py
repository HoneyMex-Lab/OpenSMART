import json
import sqlite3
import threading
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import eve_ingest
from .database import get_network_traffic_db

QUERY_CANCEL_EVENTS: dict[str, threading.Event] = {}
QUERY_CANCEL_LOCK = threading.Lock()

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

DETAIL_FIELDS = {
    "all_events": "event_type",
    "events": "event_type",
    "event_counts": "event_type",
    "protocols": "event_type",
    "flows": "flow_id",
    "flow": "flow_id",
    "sources": "src_ip",
    "destinations": "dest_ip",
    "dns": "domain",
    "http": "domain",
    "tls": "tls_sni",
    "fileinfo": "file_hash",
    "files": "file_hash",
    "smb": "file_name",
}

DETAIL_TYPE_FAMILIES: dict[str, tuple[str, ...]] = {
    "dns": ("dns",),
    "http": ("http", "http2"),
    "tls": ("tls",),
    "fileinfo": ("fileinfo",),
    "files": ("fileinfo",),
    "smb": ("smb",),
    "flow": ("flow", "netflow"),
    "flows": ("flow", "netflow"),
    "ssh": ("ssh",),
    "smtp": ("smtp",),
    "ftp": ("ftp",),
    "dhcp": ("dhcp",),
    "ntp": ("ntp",),
    "rdp": ("rdp",),
    "sip": ("sip",),
    "mqtt": ("mqtt",),
    "krb5": ("krb5",),
}

NORMALIZED_FILTER_FIELDS = {"event_type", "src_ip", "dest_ip", "domain", "url", "tls_sni", "file_hash", "file_name", "flow_id", "user_agent", "app_proto", "proto"}


def traffic_source() -> tuple[str, str]:
    _enabled, config = eve_ingest.module_config("Network Traffic Monitoring")
    source = str(config.get("log_source", "eve_json") or "eve_json")
    if source == "zeek_json":
        return source, str(config.get("zeek_json_path", ""))
    return source, eve_ingest.shared_config()["eve_json_path"]


def config_status() -> dict[str, Any]:
    enabled, config = eve_ingest.module_config("Network Traffic Monitoring")
    ids_enabled, _ids_config = eve_ingest.module_config("Network IDS")
    shared = eve_ingest.shared_config()
    source = str(config.get("log_source", "eve_json") or "eve_json")
    if source == "zeek_json":
        path = str(config.get("zeek_json_path", ""))
        configured = bool(path)
        readable = bool(path and Path(path).is_file())
        detail = "Zeek JSON source is configured. Zeek ingestion is not implemented yet."
    else:
        path = shared["eve_json_path"]
        configured = bool(path and ids_enabled)
        readable = bool(path and Path(path).is_file() and ids_enabled)
        detail = "Using Network IDS eve.json source." if ids_enabled else "Enable Network IDS and configure eve.json to use this source."
    first_ingestion_required = source == "eve_json" and eve_ingest.ids_first_ingestion_required(path, shared)
    return {
        "enabled": enabled,
        "configured": configured,
        "readable": readable,
        "detail": detail,
        "initial_ingestion_gb": shared["initial_ingestion_gb"],
        "first_ingestion_required": first_ingestion_required,
        "log_source": source,
        "zeek_json_path": str(config.get("zeek_json_path", "")),
        "eve_json_path": path,
        "enabled_protocols": sorted(eve_ingest.selected_network_event_types(enabled, config)),
        **eve_ingest.read_network_state(path),
    }


def summary(filters: dict[str, str]) -> dict[str, Any]:
    shared = eve_ingest.shared_config()
    source, path = traffic_source()
    query_id = filters.get("query_id", "")
    cancel_event = query_cancel_event(query_id)
    force = filters.get("refresh") == "true"
    if source == "eve_json":
        first_ingestion_required = eve_ingest.ids_first_ingestion_required(path, shared)
        force_network_reindex = (not first_ingestion_required) and force and network_event_count(path) == 0 and bool(shared["network_event_types"])
        eve_ingest.maybe_start_refresh(force, force_network_reindex=force_network_reindex)
    top_n = min(100, max(1, int(filters.get("top_n") or 10)))
    where, params = where_clause(path, filters)
    try:
        with get_network_traffic_db() as db:
            if cancel_event:
                db.set_progress_handler(lambda: 1 if cancel_event.is_set() else 0, 1000)
            rows = [dict(row) for row in db.execute(
                f"""
                SELECT timestamp,event_type,src_ip,dest_ip,dest_port,proto,app_proto,flow_id,domain,url,method,status,
                    user_agent,tls_sni,file_name,file_hash,bytes_toserver,bytes_toclient,pkts_toserver,pkts_toclient,flow_state,summary
                FROM eve_network_events{where}
                """,
                params,
            ).fetchall()]
            if cancel_event:
                db.set_progress_handler(None, 0)
    except sqlite3.OperationalError as error:
        if cancel_event and cancel_event.is_set():
            return {"cancelled": True, **eve_ingest.read_network_state(path)}
        raise error
    finally:
        release_query_cancel_event(query_id)
    data = build_summary(rows, top_n)
    first_ingestion_required = source == "eve_json" and eve_ingest.ids_first_ingestion_required(path, shared)
    return {**data, **eve_ingest.read_network_state(path), "initial_ingestion_gb": shared["initial_ingestion_gb"], "first_ingestion_required": first_ingestion_required}


def network_event_count(path: str) -> int:
    if not path:
        return 0
    with get_network_traffic_db() as db:
        row = db.execute("SELECT COUNT(*) AS count FROM eve_network_events WHERE eve_json_path = ?", (path,)).fetchone()
    return int(row["count"] if row else 0)


def details(filters: dict[str, str]) -> dict[str, Any]:
    source, path = traffic_source()
    if source == "eve_json":
        eve_ingest.maybe_start_refresh(False)
    table = filters.get("table", "all_events")
    query_id = filters.get("query_id", "")
    cancel_event = query_cancel_event(query_id)
    limit = min(10000, max(1, int(filters.get("limit") or filters.get("top_n") or 500)))
    where, params = where_clause(path, filters)
    if table in DETAIL_TYPE_FAMILIES:
        family = DETAIL_TYPE_FAMILIES[table]
        placeholders = ",".join("?" * len(family))
        where += f" AND event_type IN ({placeholders})"
        params.extend(family)
    elif table not in {"all_events", "events", "event_counts", "protocols", "sources", "destinations"}:
        where += " AND event_type = ?"
        params.append(table)
    field = filters.get("field") or DETAIL_FIELDS.get(table, "")
    value = filters.get("value", "")
    if field and value and field in NORMALIZED_FILTER_FIELDS:
        where += f" AND {field} LIKE ?"
        params.append(f"%{value}%")
    try:
        with get_network_traffic_db() as db:
            if cancel_event:
                db.set_progress_handler(lambda: 1 if cancel_event.is_set() else 0, 1000)
            rows = [dict(row) for row in db.execute(
                f"""
                SELECT timestamp,event_type,src_ip,src_port,dest_ip,dest_port,proto,app_proto,flow_id,community_id,domain,url,method,status,
                    user_agent,tls_sni,file_name,file_hash,bytes_toserver,bytes_toclient,pkts_toserver,pkts_toclient,flow_state,summary,event_json
                FROM eve_network_events{where}
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (*params, limit),
            ).fetchall()]
            if cancel_event:
                db.set_progress_handler(None, 0)
    except sqlite3.OperationalError as error:
        if cancel_event and cancel_event.is_set():
            return {"cancelled": True, "table": table, "rows": [], "total": 0, **eve_ingest.read_network_state(path)}
        raise error
    finally:
        release_query_cancel_event(query_id)
    detail_rows = [detail_row(table, row) for row in rows]
    return {"table": table, "rows": detail_rows, "total": len(detail_rows), **eve_ingest.read_network_state(path)}


def detail_row(table: str, row: dict[str, Any]) -> dict[str, Any]:
    try:
        event = json.loads(row.get("event_json") or "{}")
    except json.JSONDecodeError:
        event = {}
    event_type = row.get("event_type") or ""
    data = event.get(event_type) or {}
    base = {
        "timestamp": row.get("timestamp", ""),
        "event_type": event_type,
        "src_ip": row.get("src_ip", ""),
        "src_port": row.get("src_port", ""),
        "dest_ip": row.get("dest_ip", ""),
        "dest_port": row.get("dest_port", ""),
        "proto": row.get("proto", ""),
        "app_proto": row.get("app_proto", ""),
        "domain": row.get("domain", ""),
        "domain_source": extracted_source(event, [("dns", "rrname"), ("http", "hostname"), ("tls", "sni"), ("", "host")]),
        "url": row.get("url", ""),
        "url_source": extracted_source(event, [("http", "url")]),
        "user_agent": row.get("user_agent", ""),
        "user_agent_source": extracted_source(event, [("http", "http_user_agent")]),
        "tls_sni": row.get("tls_sni", ""),
        "file_name": row.get("file_name", ""),
        "file_name_source": extracted_source(event, [("fileinfo", "filename"), ("smb", "filename")]),
        "file_hash": row.get("file_hash", ""),
        "file_hash_source": extracted_source(event, [("fileinfo", "sha256"), ("fileinfo", "sha1"), ("fileinfo", "md5")]),
        "dns_rrname": nested_value(event, "dns", "rrname"),
        "http_hostname": nested_value(event, "http", "hostname"),
        "http_url": nested_value(event, "http", "url"),
        "http_user_agent": nested_value(event, "http", "http_user_agent"),
        "tls_sni_raw": nested_value(event, "tls", "sni"),
        "file_md5": nested_value(event, "fileinfo", "md5"),
        "file_sha1": nested_value(event, "fileinfo", "sha1"),
        "file_sha256": nested_value(event, "fileinfo", "sha256"),
        "summary": row.get("summary", ""),
    }
    if event_type == "dns":
        answers = data.get("answers") or []
        return {**base, "rrname": data.get("rrname") or row.get("domain", ""), "rrtype": data.get("rrtype", ""), "rcode": data.get("rcode", ""), "answers": json.dumps(answers, separators=(",", ":")) if answers else "", "community_id": row.get("community_id", "")}
    if event_type in {"http", "http2"}:
        return {**base, "hostname": data.get("hostname") or row.get("domain", ""), "method": row.get("method", ""), "url": row.get("url", ""), "status": row.get("status", ""), "user_agent": row.get("user_agent", ""), "content_type": data.get("http_content_type", ""), "length": data.get("length", "")}
    if event_type == "tls":
        return {**base, "sni": row.get("tls_sni", ""), "version": data.get("version", ""), "subject": data.get("subject", ""), "issuer": data.get("issuerdn", ""), "fingerprint": data.get("fingerprint", ""), "ja3": data.get("ja3", {}).get("hash", "") if isinstance(data.get("ja3"), dict) else data.get("ja3", ""), "ja3s": data.get("ja3s", {}).get("hash", "") if isinstance(data.get("ja3s"), dict) else data.get("ja3s", "")}
    if event_type in {"flow", "netflow"}:
        return {**base, "flow_id": row.get("flow_id", ""), "state": row.get("flow_state", ""), "reason": data.get("reason", ""), "bytes_toserver": row.get("bytes_toserver", 0), "bytes_toclient": row.get("bytes_toclient", 0), "pkts_toserver": row.get("pkts_toserver", 0), "pkts_toclient": row.get("pkts_toclient", 0), "age": data.get("age", "")}
    if event_type == "fileinfo":
        fileinfo = event.get("fileinfo") or {}
        return {**base, "filename": row.get("file_name", ""), "size": fileinfo.get("size", ""), "state": fileinfo.get("state", ""), "md5": fileinfo.get("md5", ""), "sha1": fileinfo.get("sha1", ""), "sha256": fileinfo.get("sha256", ""), "magic": fileinfo.get("magic", "")}
    if event_type == "smb":
        return {**base, "command": data.get("command", ""), "status": row.get("status", ""), "filename": row.get("file_name", ""), "share": data.get("share", ""), "disposition": data.get("disposition", "")}
    common = {"summary": row.get("summary", "")}
    for key in ("command", "filename", "status", "query", "rrname", "hostname", "url", "user_agent", "client", "server"):
        if key in data:
            common[key] = data.get(key, "")
    return {**base, **common}


def nested_value(event: dict[str, Any], section: str, key: str) -> str:
    data = event if not section else event.get(section)
    value = data.get(key) if isinstance(data, dict) else ""
    return str(value or "")


def extracted_source(event: dict[str, Any], candidates: list[tuple[str, str]]) -> str:
    for section, key in candidates:
        if nested_value(event, section, key):
            return f"{section + '.' if section else ''}{key}"
    return ""


def where_clause(path: str, filters: dict[str, str]) -> tuple[str, list[Any]]:
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
        like = f"%{q}%"
        clauses.append("(event_type LIKE ? OR src_ip LIKE ? OR dest_ip LIKE ? OR proto LIKE ? OR app_proto LIKE ? OR flow_id LIKE ? OR domain LIKE ? OR url LIKE ? OR method LIKE ? OR status LIKE ? OR tls_sni LIKE ? OR user_agent LIKE ? OR file_name LIKE ? OR file_hash LIKE ? OR summary LIKE ? OR event_json LIKE ?)")
        params.extend([like] * 16)
    return " WHERE " + " AND ".join(clauses), params


def cutoff_for(timeframe: str) -> datetime | None:
    if timeframe == "all":
        return None
    return datetime.now(timezone.utc) - TIMEFRAMES.get(timeframe, TIMEFRAMES["1d"])


def build_summary(rows: list[dict[str, Any]], top_n: int) -> dict[str, Any]:
    event_types = Counter(row["event_type"] or "unknown" for row in rows)
    protocols: Counter[str] = Counter()
    protocol_fields: dict[str, str] = {}
    src = Counter(row["src_ip"] or "unknown" for row in rows)
    dest = Counter(row["dest_ip"] or "unknown" for row in rows)
    domains = Counter(row["domain"] for row in rows if row["domain"])
    urls = Counter(row["url"] for row in rows if row["url"])
    sni = Counter(row["tls_sni"] for row in rows if row["tls_sni"])
    user_agents = Counter(row["user_agent"] for row in rows if row["user_agent"])
    files = Counter(row["file_hash"] or row["file_name"] for row in rows if row["file_hash"] or row["file_name"])
    trend: dict[str, Counter] = defaultdict(Counter)
    volume: dict[str, dict[str, int]] = defaultdict(lambda: {"inbound": 0, "outbound": 0, "events": 0})
    for row in rows:
        bucket = (row["timestamp"] or "unknown")[:13]
        protocol = row["event_type"] or "unknown"
        protocol_value = str(row.get("app_proto") or row.get("proto") or "")
        if protocol_value:
            protocols[protocol_value] += 1
            protocol_fields.setdefault(protocol_value, "app_proto" if row.get("app_proto") else "proto")
        trend[bucket][protocol] += 1
        volume[bucket]["events"] += 1
        volume[bucket]["outbound"] += int(row.get("bytes_toserver") or 0)
        volume[bucket]["inbound"] += int(row.get("bytes_toclient") or 0)
    top_talkers = []
    for ip, count in src.most_common(top_n):
        byte_total = sum(int(row.get("bytes_toserver") or 0) + int(row.get("bytes_toclient") or 0) for row in rows if row["src_ip"] == ip)
        top_talkers.append({"src_ip": ip, "events": count, "bytes": byte_total})
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counters": {
            "total_events": len(rows),
            "protocols": len(protocols),
            "sources": len(src),
            "destinations": len(dest),
            "dns_queries": event_types.get("dns", 0),
            "http_requests": event_types.get("http", 0) + event_types.get("http2", 0),
            "tls_sessions": event_types.get("tls", 0),
            "file_events": event_types.get("fileinfo", 0),
        },
        "tables": {
            "event_counts": counter_rows(event_types, top_n, "event_type"),
            "protocols": [{"protocol": key, "field": protocol_fields.get(key, "app_proto"), "events": value} for key, value in protocols.most_common(top_n)],
            "sources": counter_rows(src, top_n, "src_ip"),
            "destinations": counter_rows(dest, top_n, "dest_ip"),
            "domains": counter_rows(domains, top_n, "domain"),
            "urls": counter_rows(urls, top_n, "url"),
            "tls_sni": counter_rows(sni, top_n, "tls_sni"),
            "user_agents": counter_rows(user_agents, top_n, "user_agent"),
            "files": file_rows(files, rows, top_n),
            "top_talkers": top_talkers,
            "trend": [{"bucket": bucket, **dict(counter)} for bucket, counter in sorted(trend.items())[-48:]],
            "volume": [{"bucket": bucket, **values} for bucket, values in sorted(volume.items())[-48:]],
        },
    }


def counter_rows(counter: Counter, top_n: int, field: str) -> list[dict[str, Any]]:
    return [{field: key, "events": value} for key, value in counter.most_common(top_n)]


def file_rows(counter: Counter, rows: list[dict[str, Any]], top_n: int) -> list[dict[str, Any]]:
    result = []
    for value, count in counter.most_common(top_n):
        field = "file_hash" if any(row.get("file_hash") == value for row in rows) else "file_name"
        result.append({"file_artifact": value, "field": field, "events": count})
    return result


def cancel_query(query_id: str) -> None:
    if not query_id:
        return
    with QUERY_CANCEL_LOCK:
        event = QUERY_CANCEL_EVENTS.get(query_id)
    if event:
        event.set()


def query_cancel_event(query_id: str) -> threading.Event | None:
    if not query_id:
        return None
    with QUERY_CANCEL_LOCK:
        return QUERY_CANCEL_EVENTS.setdefault(query_id, threading.Event())


def release_query_cancel_event(query_id: str) -> None:
    if not query_id:
        return
    with QUERY_CANCEL_LOCK:
        QUERY_CANCEL_EVENTS.pop(query_id, None)

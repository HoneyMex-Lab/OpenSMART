import json
import time
from datetime import datetime, timedelta, timezone
from typing import Annotated

import psutil
from fastapi import APIRouter, Depends

from ..database import get_db, get_network_ids_db, get_network_traffic_db
from .. import eve_ingest
from ..security import get_current_user
from ..shell import run_script

router = APIRouter(prefix="/api/status", tags=["status"])


@router.get("")
def get_status(_: Annotated[dict, Depends(get_current_user)]) -> dict:
    output = run_script("module_status.sh")
    return {"modules": json.loads(output)}


@router.get("/resources")
def get_resources(_: Annotated[dict, Depends(get_current_user)]) -> dict:
    cpu = psutil.cpu_percent(interval=0.2)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    uptime_seconds = int(time.time() - psutil.boot_time())
    return {
        "cpu_percent": round(cpu, 1),
        "cpu_count": psutil.cpu_count(logical=True),
        "memory_total_gb": round(mem.total / 1024 ** 3, 1),
        "memory_used_gb": round(mem.used / 1024 ** 3, 1),
        "memory_percent": round(mem.percent, 1),
        "disk_total_gb": round(disk.total / 1024 ** 3, 1),
        "disk_used_gb": round(disk.used / 1024 ** 3, 1),
        "disk_percent": round(disk.percent, 1),
        "uptime_seconds": uptime_seconds,
    }


@router.get("/resources/history")
def get_resources_history(_: Annotated[dict, Depends(get_current_user)], timeframe: str = "1h") -> dict:
    windows: dict[str, timedelta] = {
        "1h": timedelta(hours=1),
        "8h": timedelta(hours=8),
        "1d": timedelta(days=1),
        "3d": timedelta(days=3),
        "7d": timedelta(days=7),
        "1w": timedelta(weeks=1),
        "1m": timedelta(days=31),
    }
    delta = windows.get(timeframe, timedelta(hours=1))
    since = (datetime.now(timezone.utc) - delta).isoformat()
    with get_db() as db:
        rows = db.execute(
            "SELECT sampled_at, cpu_percent, memory_percent, disk_percent FROM resource_snapshots WHERE sampled_at >= ? ORDER BY sampled_at",
            (since,),
        ).fetchall()
    points = [
        {"t": row["sampled_at"], "cpu": row["cpu_percent"], "memory": row["memory_percent"], "disk": row["disk_percent"]}
        for row in rows
    ]
    if len(points) > 300:
        step = len(points) / 300
        points = [points[int(i * step)] for i in range(300)]
    return {"points": points, "timeframe": timeframe}


_EXPECTED_MAIN_TABLES = {
    "audit_events", "login_attempts", "modules",
    "opensmart_modules", "resource_snapshots", "sessions", "settings", "users",
}


@router.get("/schema-check")
def get_schema_check(_: Annotated[dict, Depends(get_current_user)]) -> dict:
    with get_db() as db:
        actual = {r["name"] for r in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
    missing = sorted(_EXPECTED_MAIN_TABLES - actual)
    legacy_module_tables = {"network_ids_alerts", "network_ids_alerts_fts", "network_ids_artifacts", "network_ids_ingest_state"}
    extra = sorted(
        table for table in actual - _EXPECTED_MAIN_TABLES - legacy_module_tables - {"sqlite_sequence"}
        if not table.startswith("network_ids_alerts_fts")
    )
    return {"ok": not missing, "missing_tables": missing, "extra_tables": extra}


@router.get("/data-info")
def get_data_info(_: Annotated[dict, Depends(get_current_user)]) -> dict:
    shared = eve_ingest.shared_config()
    eve_path = shared.get("eve_json_path", "")
    with get_network_ids_db() as db:
        ids_row = db.execute(
            "SELECT MIN(timestamp) AS earliest, COUNT(*) AS total FROM network_ids_alerts WHERE eve_json_path = ? AND timestamp != ''",
            (eve_path,),
        ).fetchone()
    with get_network_traffic_db() as db:
        net_row = db.execute(
            "SELECT MIN(timestamp) AS earliest, COUNT(*) AS total FROM eve_network_events WHERE eve_json_path = ? AND timestamp != ''",
            (eve_path,),
        ).fetchone()
    return {
        "ids": {
            "retention_enabled": shared.get("ids_retention_enabled", True),
            "retention_days": shared.get("ids_retention_days", 90),
            "retention_time": shared.get("ids_retention_time", "02:00"),
            "earliest_event": ids_row["earliest"] if ids_row else None,
            "total": ids_row["total"] if ids_row else 0,
        },
        "network": {
            "retention_enabled": shared.get("network_retention_enabled", True),
            "retention_days": shared.get("network_retention_days", 90),
            "retention_time": shared.get("network_retention_time", "02:00"),
            "earliest_event": net_row["earliest"] if net_row else None,
            "total": net_row["total"] if net_row else 0,
        },
    }

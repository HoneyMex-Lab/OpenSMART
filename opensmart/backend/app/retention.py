import logging
import time
from datetime import datetime, timedelta, timezone

from .database import get_network_ids_db, get_network_traffic_db
from . import eve_ingest

logger = logging.getLogger(__name__)


def _cutoff_iso(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def apply_ids_retention(eve_path: str, days: int) -> int:
    cutoff = _cutoff_iso(days)
    with get_network_ids_db() as db:
        r1 = db.execute(
            "DELETE FROM network_ids_artifacts WHERE eve_json_path = ? AND timestamp < ? AND timestamp != ''",
            (eve_path, cutoff),
        ).rowcount
        r2 = db.execute(
            "DELETE FROM network_ids_alerts WHERE eve_json_path = ? AND timestamp < ? AND timestamp != ''",
            (eve_path, cutoff),
        ).rowcount
        db.commit()
    return r1 + r2


def apply_network_retention(eve_path: str, days: int) -> int:
    cutoff = _cutoff_iso(days)
    with get_network_traffic_db() as db:
        count = db.execute(
            "DELETE FROM eve_network_events WHERE eve_json_path = ? AND timestamp < ? AND timestamp != ''",
            (eve_path, cutoff),
        ).rowcount
        db.commit()
    return count


def run_retention_job() -> None:
    shared = eve_ingest.shared_config()
    eve_path = shared.get("eve_json_path", "")

    ids_enabled = str(shared.get("ids_retention_enabled", "true")).lower() not in ("0", "false", "no", "off")
    ids_days = int(shared.get("ids_retention_days", 90) or 90)

    net_enabled = str(shared.get("network_retention_enabled", "true")).lower() not in ("0", "false", "no", "off")
    net_days = int(shared.get("network_retention_days", 90) or 90)

    if ids_enabled and eve_path:
        t0 = time.monotonic()
        deleted = apply_ids_retention(eve_path, ids_days)
        elapsed = time.monotonic() - t0
        logger.info(
            "retention: module=ids path=%s days=%d deleted=%d elapsed=%.2fs",
            eve_path, ids_days, deleted, elapsed,
        )

    if net_enabled and eve_path:
        t0 = time.monotonic()
        deleted = apply_network_retention(eve_path, net_days)
        elapsed = time.monotonic() - t0
        logger.info(
            "retention: module=network path=%s days=%d deleted=%d elapsed=%.2fs",
            eve_path, net_days, deleted, elapsed,
        )

import json
import urllib.error
import urllib.request
from collections import Counter
from typing import Any

from .database import get_db, get_network_ids_db, now_iso


def _settings() -> dict[str, str]:
    with get_db() as db:
        rows = db.execute("SELECT key, value FROM settings").fetchall()
    return {row["key"]: row["value"] for row in rows}


def _enabled(value: str | None) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def _post_json(url: str, payload: dict[str, Any], timeout: float = 3.0) -> tuple[bool, str]:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", "User-Agent": "OpenSMART/notifications"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            code = int(response.status)
            return 200 <= code < 400, f"HTTP {code}"
    except urllib.error.HTTPError as error:
        return False, f"HTTP {error.code}"
    except (urllib.error.URLError, TimeoutError, ValueError) as error:
        return False, str(error)


def validate_webhook(url: str, label: str) -> tuple[bool, str]:
    return send_test_webhook(url, label)


def send_test_webhook(url: str, label: str) -> tuple[bool, str]:
    return _post_json(url, {"content": f"OpenSMART {label} webhook test message."})


def send_webhook(url: str, payload: dict[str, Any]) -> tuple[bool, str]:
    return _post_json(url, payload)


def notify_ids_system_event(event_type: str, detail: str) -> None:
    settings = _settings()
    if not _enabled(settings.get("notification_ids_event_system_events")):
        return
    url = settings.get("notification_ids_webhook", "").strip()
    if not url:
        return
    send_webhook(url, {"content": f"OpenSMART IDS: {detail}"})


def notify_ids_critical_alerts(path: str) -> None:
    settings = _settings()
    if not _enabled(settings.get("notification_ids_event_critical_alerts")):
        return
    url = settings.get("notification_ids_webhook", "").strip()
    if not url:
        return
    with get_network_ids_db() as db:
        alerts = [dict(row) for row in db.execute(
            """
            SELECT network_ids_alerts.id AS alert_id, timestamp, signature
            FROM network_ids_alerts
            LEFT JOIN network_ids_alert_tracking ON network_ids_alert_tracking.alert_id = network_ids_alerts.id
            WHERE eve_json_path = ?
              AND LOWER(severity) IN ('1', 'critical')
              AND COALESCE(network_ids_alert_tracking.critical_notification_status, '') != 'sent'
            ORDER BY timestamp ASC
            """,
            (path,),
        ).fetchall()]
    if not alerts:
        return
    alert_ids = [int(alert["alert_id"]) for alert in alerts]
    earliest = str(alerts[0].get("timestamp", ""))
    latest = str(alerts[-1].get("timestamp", ""))
    counts = Counter(str(alert.get("signature") or "Unknown alert") for alert in alerts)
    lines = [
        "**OpenSMART IDS Alerts**",
        f"Sensor Name: {settings.get('sensor_name') or 'OpenSMART Sensor'}",
        f"Time Window: {earliest} - {latest}",
        "",
        "Alerts:",
    ]
    for signature, count in counts.most_common(20):
        lines.append(f"- {signature}: {count}")
    if len(counts) > 20:
        lines.append(f"- ...and {len(counts) - 20} more alert types")
    payload = {"content": "\n".join(lines)[:1900]}
    ok, error = send_webhook(url, payload)
    status = "sent" if ok else "warning"
    with get_network_ids_db() as db:
        for alert_id in alert_ids:
            db.execute(
                """
                INSERT INTO network_ids_alert_tracking (alert_id, critical_notified_at, critical_notification_status, critical_notification_error)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(alert_id) DO UPDATE SET critical_notified_at = excluded.critical_notified_at,
                    critical_notification_status = excluded.critical_notification_status,
                    critical_notification_error = excluded.critical_notification_error
                """,
                (alert_id, now_iso(), status, "" if ok else error[:300]),
            )
        db.commit()

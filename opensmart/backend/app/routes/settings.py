from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from .. import notifications
from ..database import get_db, write_audit_event
from ..security import get_current_user, require_admin

router = APIRouter(prefix="/api/settings", tags=["settings"])


class SettingsPayload(BaseModel):
    settings: dict[str, str]


class WebhookTestPayload(BaseModel):
    url: str
    label: str = "Notifications"


PUBLIC_KEYS = {
    "platform_title",
    "platform_version",
    "platform_build",
    "sensor_name",
    "platform_language",
    "logo_url",
    "favicon_url",
    "footer_logo_primary",
    "footer_logo_secondary",
    "developed_by",
    "failed_login_limit",
    "lockout_minutes",
    "password_policy",
    "wizard_completed",
    "monitor_interfaces",
    "theme",
    "tool_base_path",
    "tool_url_opnsense",
    "tool_url_ntop",
    "tool_url_arkime",
    "tool_url_proxmox",
    "tool_url_wazuh",
    "tool_url_graylog",
    "dashboard_ids_alerts_critical",
    "dashboard_ids_alerts_high",
    "dashboard_ids_alerts_medium",
    "dashboard_ids_alerts_low",
    "dashboard_fw_blocked_packets_24h",
    "dashboard_fw_blocked_ips_24h",
    "dashboard_endpoints_total",
    "dashboard_vulnerabilities_critical",
    "dashboard_vulnerabilities_high",
    "dashboard_vulnerabilities_medium",
    "dashboard_vulnerabilities_open",
    "dashboard_vpn_users",
    "dashboard_lxc_assets",
    "dashboard_feed_json",
    "dashboard_use_demo_for_disabled",
    "dashboard_ids_severity_critical",
    "dashboard_ids_severity_high",
    "dashboard_ids_severity_medium",
    "dashboard_ids_severity_low",
    "dashboard_fw_allowed_packets_24h",
    "notification_ids_webhook",
    "notification_ids_webhook_status",
    "notification_ids_webhook_error",
    "notification_ids_event_critical_alerts",
    "notification_ids_event_system_events",
    "notification_network_webhook",
    "notification_network_webhook_status",
    "notification_network_webhook_error",
    "notification_network_event_anomalies",
    "notification_network_event_system_events",
    "notification_platform_webhook",
    "notification_platform_webhook_status",
    "notification_platform_webhook_error",
    "notification_platform_event_health_alerts",
    "notification_platform_event_internal_feeds",
}

WEBHOOK_KEYS = {
    "notification_ids_webhook": ("notification_ids_webhook_status", "notification_ids_webhook_error", "IDS"),
    "notification_network_webhook": ("notification_network_webhook_status", "notification_network_webhook_error", "Network"),
    "notification_platform_webhook": ("notification_platform_webhook_status", "notification_platform_webhook_error", "OpenSMART Platform"),
}

BRANDING_KEYS = {
    "platform_title",
    "platform_version",
    "platform_build",
    "platform_language",
    "theme",
    "logo_url",
    "favicon_url",
    "footer_logo_primary",
    "footer_logo_secondary",
    "developed_by",
}


def read_settings(keys: set[str] | None = None) -> dict[str, str]:
    query = "SELECT key, value FROM settings"
    params: tuple = ()
    if keys:
        placeholders = ",".join("?" for _ in keys)
        query += f" WHERE key IN ({placeholders})"
        params = tuple(keys)
    with get_db() as db:
        rows = db.execute(query, params).fetchall()
    return {row["key"]: row["value"] for row in rows}


@router.get("/public")
def get_public_settings() -> dict:
    return {"settings": read_settings(BRANDING_KEYS)}


@router.get("")
def get_settings(_: Annotated[dict, Depends(get_current_user)]) -> dict:
    return {"settings": read_settings()}


@router.put("")
def update_settings(payload: SettingsPayload, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    existing = read_settings()
    settings = {key: str(value) for key, value in payload.settings.items() if key in PUBLIC_KEYS}
    for key, (status_key, error_key, label) in WEBHOOK_KEYS.items():
        if key not in settings:
            continue
        value = settings[key].strip()
        if not value:
            settings[status_key] = "not_configured"
            settings[error_key] = ""
        elif value != existing.get(key, ""):
            ok, error = notifications.validate_webhook(value, label)
            settings[status_key] = "ok" if ok else "warning"
            settings[error_key] = "" if ok else error[:300]
    with get_db() as db:
        for key, value in settings.items():
            db.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
        db.commit()
    write_audit_event("settings_update", admin["id"], admin["username"], "settings", "", "web console settings updated")
    return get_settings(admin)


@router.post("/webhook-test")
def test_webhook(payload: WebhookTestPayload, _: Annotated[dict, Depends(require_admin)]) -> dict:
    ok, detail = notifications.send_test_webhook(payload.url.strip(), payload.label.strip() or "Notifications")
    return {"ok": ok, "detail": detail}

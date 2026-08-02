import json
import logging
import secrets
import socket
import sqlite3
import string
from datetime import datetime, timezone
from pathlib import Path

from argon2 import PasswordHasher

from .config import APP_VERSION, BUILD_VERSION, DB_PATH, NETWORK_IDS_DB_PATH, NETWORK_TRAFFIC_DB_PATH, TELEMETRY_DB_PATH

logger = logging.getLogger(__name__)
ph = PasswordHasher()


def default_sensor_name() -> str:
    try:
        return socket.gethostname().strip() or "OpenSMART Sensor"
    except OSError:
        return "OpenSMART Sensor"


DEFAULT_TOOLS = [
    ("Arkime", "Traffic capture/search", 0, "{}"),
    ("OPNsense", "Firewall management", 0, "{}"),
    ("Proxmox", "Cluster assets", 0, "{}"),
    ("Wazuh", "SIEM endpoint monitoring", 0, "{}"),
    ("Graylog", "Log management", 0, "{}"),
]

DEFAULT_OPENSMART_MODULES = [
    ("Threat Detection Alerts", "Threat alert summary and triage", 0, "{}"),
    ("Network Traffic Monitoring", "Network traffic visibility", 0, "{}"),
    ("Network IDS", "Network intrusion detection", 0, "{}"),
    ("Endpoint", "Endpoint monitoring", 0, "{}"),
    ("Vulnerability Management", "Vulnerability tracking", 0, "{}"),
    ("Honeypot", "Honeypot telemetry", 0, "{}"),
    ("Access VPN", "Remote access module", 0, "{}"),
    ("LXC Manager", "Container management module", 0, "{}"),
    ("Firewall", "nftables firewall management", 0, "{}"),
]

DEFAULT_SETTINGS = {
    "platform_title": "OpenSMART",
    "platform_version": APP_VERSION,
    "platform_build": BUILD_VERSION,
    "sensor_name": default_sensor_name(),
    "platform_language": "en",
    "theme": "honeynet",
    "logo_url": "",
    "favicon_url": "/assets/branding/favicon.svg",
    "footer_logo_primary": "",
    "footer_logo_secondary": "",
    "developed_by": "Developed by",
    "failed_login_limit": "5",
    "lockout_minutes": "15",
    "tool_base_path": "/opt/opensmart/tools",
    "tool_url_opnsense": "",
    "tool_url_ntop": "",
    "tool_url_arkime": "",
    "tool_url_proxmox": "",
    "tool_url_wazuh": "",
    "tool_url_graylog": "",
    "log_file_path": "logs/opensmart.log",
    "worker_threads": "8",
    "notification_ids_webhook": "",
    "notification_ids_webhook_status": "not_configured",
    "notification_ids_webhook_error": "",
    "notification_ids_event_critical_alerts": "false",
    "notification_ids_event_system_events": "false",
    "notification_network_webhook": "",
    "notification_network_webhook_status": "not_configured",
    "notification_network_webhook_error": "",
    "notification_network_event_anomalies": "false",
    "notification_network_event_system_events": "false",
    "notification_platform_webhook": "",
    "notification_platform_webhook_status": "not_configured",
    "notification_platform_webhook_error": "",
    "notification_platform_event_health_alerts": "false",
    "notification_platform_event_internal_feeds": "false",
    "password_policy": "strict",
    # Existing/upgraded installs default to "true" (already set up); only a
    # genuinely fresh install (bootstrap_admin() below) sets this to "false"
    # so the first-run Wizard doesn't retroactively appear after an upgrade.
    "wizard_completed": "true",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    # Allow up to 5 s of retry when another connection holds a write lock
    # (e.g. the IDS ingest thread). Prevents OperationalError: database is locked
    # during concurrent auth/session writes.
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def get_telemetry_db() -> sqlite3.Connection:
    conn = sqlite3.connect(TELEMETRY_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def _get_module_db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def get_network_ids_db() -> sqlite3.Connection:
    return _get_module_db(NETWORK_IDS_DB_PATH)


def get_network_traffic_db() -> sqlite3.Connection:
    return _get_module_db(NETWORK_TRAFFIC_DB_PATH)


def init_network_ids_db() -> None:
    Path(NETWORK_IDS_DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with get_network_ids_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS network_ids_ingest_state (
                eve_json_path TEXT PRIMARY KEY,
                file_size INTEGER NOT NULL DEFAULT 0,
                file_mtime REAL NOT NULL DEFAULT 0,
                byte_offset INTEGER NOT NULL DEFAULT 0,
                lines_read INTEGER NOT NULL DEFAULT 0,
                refresh_status TEXT NOT NULL DEFAULT 'idle',
                progress_percent INTEGER NOT NULL DEFAULT 0,
                current_action TEXT NOT NULL DEFAULT 'Idle',
                last_check_started_at TEXT NOT NULL DEFAULT '',
                last_check_finished_at TEXT NOT NULL DEFAULT '',
                last_check_bytes_total INTEGER NOT NULL DEFAULT 0,
                last_check_bytes_read INTEGER NOT NULL DEFAULT 0,
                last_check_lines_read INTEGER NOT NULL DEFAULT 0,
                last_check_alerts_read INTEGER NOT NULL DEFAULT 0,
                last_check_network_read INTEGER NOT NULL DEFAULT 0,
                last_check_non_alerts INTEGER NOT NULL DEFAULT 0,
                ingest_profile TEXT NOT NULL DEFAULT '',
                last_updated TEXT NOT NULL DEFAULT '',
                error TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS network_ids_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                eve_json_path TEXT NOT NULL,
                timestamp TEXT NOT NULL DEFAULT '',
                src_ip TEXT NOT NULL DEFAULT '',
                src_port TEXT NOT NULL DEFAULT '',
                dest_ip TEXT NOT NULL DEFAULT '',
                dest_port TEXT NOT NULL DEFAULT '',
                proto TEXT NOT NULL DEFAULT '',
                severity TEXT NOT NULL DEFAULT '',
                category TEXT NOT NULL DEFAULT '',
                signature TEXT NOT NULL DEFAULT '',
                signature_id TEXT NOT NULL DEFAULT '',
                signature_source TEXT NOT NULL DEFAULT '',
                confidence TEXT NOT NULL DEFAULT '',
                payload_printable TEXT NOT NULL DEFAULT '',
                payload TEXT NOT NULL DEFAULT '',
                gid TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL DEFAULT '',
                metadata TEXT NOT NULL DEFAULT '',
                flow_id TEXT NOT NULL DEFAULT '',
                app_proto TEXT NOT NULL DEFAULT '',
                in_iface TEXT NOT NULL DEFAULT '',
                host TEXT NOT NULL DEFAULT '',
                community_id TEXT NOT NULL DEFAULT '',
                tx_id TEXT NOT NULL DEFAULT '',
                packet_info_linktype TEXT NOT NULL DEFAULT '',
                flow_direction TEXT NOT NULL DEFAULT '',
                mitre TEXT NOT NULL DEFAULT '',
                cve TEXT NOT NULL DEFAULT '',
                ingested_at TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_network_ids_alerts_path_time ON network_ids_alerts (eve_json_path, timestamp);
            CREATE INDEX IF NOT EXISTS idx_network_ids_alerts_path_severity_time ON network_ids_alerts (eve_json_path, severity, timestamp);
            CREATE INDEX IF NOT EXISTS idx_network_ids_alerts_path_category_time ON network_ids_alerts (eve_json_path, category, timestamp);
            CREATE INDEX IF NOT EXISTS idx_network_ids_alerts_path_proto_time ON network_ids_alerts (eve_json_path, proto, timestamp);
            CREATE INDEX IF NOT EXISTS idx_network_ids_alerts_path_src_time ON network_ids_alerts (eve_json_path, src_ip, timestamp);
            CREATE INDEX IF NOT EXISTS idx_network_ids_alerts_path_dest_time ON network_ids_alerts (eve_json_path, dest_ip, timestamp);
            CREATE INDEX IF NOT EXISTS idx_network_ids_alerts_src ON network_ids_alerts (src_ip);
            CREATE INDEX IF NOT EXISTS idx_network_ids_alerts_dest ON network_ids_alerts (dest_ip);
            CREATE INDEX IF NOT EXISTS idx_network_ids_alerts_signature ON network_ids_alerts (signature);
            CREATE INDEX IF NOT EXISTS idx_network_ids_alerts_category ON network_ids_alerts (category);
            CREATE INDEX IF NOT EXISTS idx_network_ids_alerts_severity ON network_ids_alerts (severity);

            CREATE VIRTUAL TABLE IF NOT EXISTS network_ids_alerts_fts USING fts5(
                alert_id UNINDEXED,
                eve_json_path UNINDEXED,
                timestamp,
                src_ip,
                src_port,
                dest_ip,
                dest_port,
                proto,
                severity,
                category,
                signature,
                signature_id,
                signature_source,
                confidence,
                payload_printable,
                payload,
                metadata,
                flow_id,
                app_proto,
                host,
                community_id,
                mitre,
                cve
            );

            CREATE TABLE IF NOT EXISTS network_ids_artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                eve_json_path TEXT NOT NULL,
                alert_id INTEGER NOT NULL,
                artifact_type TEXT NOT NULL,
                artifact_value TEXT NOT NULL,
                timestamp TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                UNIQUE(alert_id, artifact_type, artifact_value)
            );
            CREATE INDEX IF NOT EXISTS idx_network_ids_artifacts_path_type_value ON network_ids_artifacts (eve_json_path, artifact_type, artifact_value);
            CREATE INDEX IF NOT EXISTS idx_network_ids_artifacts_path_value ON network_ids_artifacts (eve_json_path, artifact_value);
            CREATE INDEX IF NOT EXISTS idx_network_ids_artifacts_alert ON network_ids_artifacts (alert_id);
            CREATE INDEX IF NOT EXISTS idx_network_ids_artifacts_path_time ON network_ids_artifacts (eve_json_path, timestamp);

            CREATE TABLE IF NOT EXISTS network_ids_alert_tracking (
                alert_id INTEGER PRIMARY KEY,
                status TEXT NOT NULL DEFAULT 'new',
                acknowledged_at TEXT NOT NULL DEFAULT '',
                acknowledged_by TEXT NOT NULL DEFAULT '',
                mode TEXT NOT NULL DEFAULT '',
                critical_notified_at TEXT NOT NULL DEFAULT '',
                critical_notification_status TEXT NOT NULL DEFAULT '',
                critical_notification_error TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_network_ids_alert_tracking_status ON network_ids_alert_tracking (status);
            """
        )
        db.execute("PRAGMA journal_mode = WAL")
        for column, definition in {
            "critical_notified_at": "TEXT NOT NULL DEFAULT ''",
            "critical_notification_status": "TEXT NOT NULL DEFAULT ''",
            "critical_notification_error": "TEXT NOT NULL DEFAULT ''",
        }.items():
            try:
                db.execute(f"ALTER TABLE network_ids_alert_tracking ADD COLUMN {column} {definition}")
            except sqlite3.OperationalError:
                pass
        for column, definition in {
            "file_inode": "INTEGER NOT NULL DEFAULT 0",
        }.items():
            try:
                db.execute(f"ALTER TABLE network_ids_ingest_state ADD COLUMN {column} {definition}")
            except sqlite3.OperationalError:
                pass
        try:
            db.execute("ALTER TABLE network_ids_alerts ADD COLUMN event_hash TEXT")
        except sqlite3.OperationalError:
            pass
        db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_network_ids_alerts_event_hash "
            "ON network_ids_alerts (eve_json_path, event_hash) WHERE event_hash IS NOT NULL"
        )
        db.commit()


def init_network_traffic_db() -> None:
    Path(NETWORK_TRAFFIC_DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with get_network_traffic_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS network_traffic_ingest_state (
                eve_json_path TEXT PRIMARY KEY,
                file_size INTEGER NOT NULL DEFAULT 0,
                file_mtime REAL NOT NULL DEFAULT 0,
                byte_offset INTEGER NOT NULL DEFAULT 0,
                lines_read INTEGER NOT NULL DEFAULT 0,
                refresh_status TEXT NOT NULL DEFAULT 'idle',
                progress_percent INTEGER NOT NULL DEFAULT 0,
                current_action TEXT NOT NULL DEFAULT 'Idle',
                last_check_started_at TEXT NOT NULL DEFAULT '',
                last_check_finished_at TEXT NOT NULL DEFAULT '',
                last_check_bytes_total INTEGER NOT NULL DEFAULT 0,
                last_check_bytes_read INTEGER NOT NULL DEFAULT 0,
                last_check_lines_read INTEGER NOT NULL DEFAULT 0,
                last_check_alerts_read INTEGER NOT NULL DEFAULT 0,
                last_check_network_read INTEGER NOT NULL DEFAULT 0,
                last_check_non_alerts INTEGER NOT NULL DEFAULT 0,
                ingest_profile TEXT NOT NULL DEFAULT '',
                last_updated TEXT NOT NULL DEFAULT '',
                error TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS eve_network_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                eve_json_path TEXT NOT NULL,
                timestamp TEXT NOT NULL DEFAULT '',
                event_type TEXT NOT NULL DEFAULT '',
                src_ip TEXT NOT NULL DEFAULT '',
                src_port TEXT NOT NULL DEFAULT '',
                dest_ip TEXT NOT NULL DEFAULT '',
                dest_port TEXT NOT NULL DEFAULT '',
                proto TEXT NOT NULL DEFAULT '',
                app_proto TEXT NOT NULL DEFAULT '',
                flow_id TEXT NOT NULL DEFAULT '',
                in_iface TEXT NOT NULL DEFAULT '',
                community_id TEXT NOT NULL DEFAULT '',
                host TEXT NOT NULL DEFAULT '',
                tx_id TEXT NOT NULL DEFAULT '',
                domain TEXT NOT NULL DEFAULT '',
                url TEXT NOT NULL DEFAULT '',
                method TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT '',
                user_agent TEXT NOT NULL DEFAULT '',
                tls_sni TEXT NOT NULL DEFAULT '',
                file_name TEXT NOT NULL DEFAULT '',
                file_hash TEXT NOT NULL DEFAULT '',
                bytes_toserver INTEGER NOT NULL DEFAULT 0,
                bytes_toclient INTEGER NOT NULL DEFAULT 0,
                pkts_toserver INTEGER NOT NULL DEFAULT 0,
                pkts_toclient INTEGER NOT NULL DEFAULT 0,
                flow_state TEXT NOT NULL DEFAULT '',
                summary TEXT NOT NULL DEFAULT '',
                event_json TEXT NOT NULL DEFAULT '',
                ingested_at TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_eve_network_events_path_time ON eve_network_events (eve_json_path, timestamp);
            CREATE INDEX IF NOT EXISTS idx_eve_network_events_path_type_time ON eve_network_events (eve_json_path, event_type, timestamp);
            CREATE INDEX IF NOT EXISTS idx_eve_network_events_path_src_time ON eve_network_events (eve_json_path, src_ip, timestamp);
            CREATE INDEX IF NOT EXISTS idx_eve_network_events_path_dest_time ON eve_network_events (eve_json_path, dest_ip, timestamp);
            CREATE INDEX IF NOT EXISTS idx_eve_network_events_path_domain_time ON eve_network_events (eve_json_path, domain, timestamp);
            CREATE INDEX IF NOT EXISTS idx_eve_network_events_path_sni_time ON eve_network_events (eve_json_path, tls_sni, timestamp);
            """
        )
        db.execute("PRAGMA journal_mode = WAL")
        try:
            db.execute("ALTER TABLE network_traffic_ingest_state ADD COLUMN file_inode INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError:
            pass
        try:
            db.execute("ALTER TABLE eve_network_events ADD COLUMN event_hash TEXT")
        except sqlite3.OperationalError:
            pass
        db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_eve_network_events_event_hash "
            "ON eve_network_events (eve_json_path, event_hash) WHERE event_hash IS NOT NULL"
        )
        db.commit()


def init_telemetry_db() -> None:
    Path(TELEMETRY_DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with get_telemetry_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS eve_ingest_state (
                eve_json_path TEXT PRIMARY KEY,
                file_size INTEGER NOT NULL DEFAULT 0,
                file_mtime REAL NOT NULL DEFAULT 0,
                byte_offset INTEGER NOT NULL DEFAULT 0,
                lines_read INTEGER NOT NULL DEFAULT 0,
                refresh_status TEXT NOT NULL DEFAULT 'idle',
                progress_percent INTEGER NOT NULL DEFAULT 0,
                current_action TEXT NOT NULL DEFAULT 'Idle',
                last_check_started_at TEXT NOT NULL DEFAULT '',
                last_check_finished_at TEXT NOT NULL DEFAULT '',
                last_check_bytes_total INTEGER NOT NULL DEFAULT 0,
                last_check_bytes_read INTEGER NOT NULL DEFAULT 0,
                last_check_lines_read INTEGER NOT NULL DEFAULT 0,
                last_check_alerts_read INTEGER NOT NULL DEFAULT 0,
                last_check_network_read INTEGER NOT NULL DEFAULT 0,
                last_check_non_alerts INTEGER NOT NULL DEFAULT 0,
                ingest_profile TEXT NOT NULL DEFAULT '',
                last_updated TEXT NOT NULL DEFAULT '',
                error TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS network_ids_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                eve_json_path TEXT NOT NULL,
                timestamp TEXT NOT NULL DEFAULT '',
                src_ip TEXT NOT NULL DEFAULT '',
                src_port TEXT NOT NULL DEFAULT '',
                dest_ip TEXT NOT NULL DEFAULT '',
                dest_port TEXT NOT NULL DEFAULT '',
                proto TEXT NOT NULL DEFAULT '',
                severity TEXT NOT NULL DEFAULT '',
                category TEXT NOT NULL DEFAULT '',
                signature TEXT NOT NULL DEFAULT '',
                signature_id TEXT NOT NULL DEFAULT '',
                signature_source TEXT NOT NULL DEFAULT '',
                confidence TEXT NOT NULL DEFAULT '',
                payload_printable TEXT NOT NULL DEFAULT '',
                payload TEXT NOT NULL DEFAULT '',
                gid TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL DEFAULT '',
                metadata TEXT NOT NULL DEFAULT '',
                flow_id TEXT NOT NULL DEFAULT '',
                app_proto TEXT NOT NULL DEFAULT '',
                in_iface TEXT NOT NULL DEFAULT '',
                host TEXT NOT NULL DEFAULT '',
                community_id TEXT NOT NULL DEFAULT '',
                tx_id TEXT NOT NULL DEFAULT '',
                packet_info_linktype TEXT NOT NULL DEFAULT '',
                flow_direction TEXT NOT NULL DEFAULT '',
                mitre TEXT NOT NULL DEFAULT '',
                cve TEXT NOT NULL DEFAULT '',
                ingested_at TEXT NOT NULL DEFAULT ''
            );

            CREATE INDEX IF NOT EXISTS idx_network_ids_alerts_path_time ON network_ids_alerts (eve_json_path, timestamp);
            CREATE INDEX IF NOT EXISTS idx_network_ids_alerts_path_severity_time ON network_ids_alerts (eve_json_path, severity, timestamp);
            CREATE INDEX IF NOT EXISTS idx_network_ids_alerts_path_category_time ON network_ids_alerts (eve_json_path, category, timestamp);
            CREATE INDEX IF NOT EXISTS idx_network_ids_alerts_path_proto_time ON network_ids_alerts (eve_json_path, proto, timestamp);
            CREATE INDEX IF NOT EXISTS idx_network_ids_alerts_path_src_time ON network_ids_alerts (eve_json_path, src_ip, timestamp);
            CREATE INDEX IF NOT EXISTS idx_network_ids_alerts_path_dest_time ON network_ids_alerts (eve_json_path, dest_ip, timestamp);
            CREATE INDEX IF NOT EXISTS idx_network_ids_alerts_src ON network_ids_alerts (src_ip);
            CREATE INDEX IF NOT EXISTS idx_network_ids_alerts_dest ON network_ids_alerts (dest_ip);
            CREATE INDEX IF NOT EXISTS idx_network_ids_alerts_signature ON network_ids_alerts (signature);
            CREATE INDEX IF NOT EXISTS idx_network_ids_alerts_category ON network_ids_alerts (category);
            CREATE INDEX IF NOT EXISTS idx_network_ids_alerts_severity ON network_ids_alerts (severity);

            CREATE VIRTUAL TABLE IF NOT EXISTS network_ids_alerts_fts USING fts5(
                alert_id UNINDEXED,
                eve_json_path UNINDEXED,
                timestamp,
                src_ip,
                src_port,
                dest_ip,
                dest_port,
                proto,
                severity,
                category,
                signature,
                signature_id,
                signature_source,
                confidence,
                payload_printable,
                payload,
                metadata,
                flow_id,
                app_proto,
                host,
                community_id,
                mitre,
                cve
            );

            CREATE TABLE IF NOT EXISTS network_ids_artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                eve_json_path TEXT NOT NULL,
                alert_id INTEGER NOT NULL,
                artifact_type TEXT NOT NULL,
                artifact_value TEXT NOT NULL,
                timestamp TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                UNIQUE(alert_id, artifact_type, artifact_value)
            );
            CREATE INDEX IF NOT EXISTS idx_network_ids_artifacts_path_type_value ON network_ids_artifacts (eve_json_path, artifact_type, artifact_value);
            CREATE INDEX IF NOT EXISTS idx_network_ids_artifacts_path_value ON network_ids_artifacts (eve_json_path, artifact_value);
            CREATE INDEX IF NOT EXISTS idx_network_ids_artifacts_alert ON network_ids_artifacts (alert_id);
            CREATE INDEX IF NOT EXISTS idx_network_ids_artifacts_path_time ON network_ids_artifacts (eve_json_path, timestamp);

            CREATE TABLE IF NOT EXISTS network_ids_alert_tracking (
                alert_id INTEGER PRIMARY KEY,
                status TEXT NOT NULL DEFAULT 'new',
                acknowledged_at TEXT NOT NULL DEFAULT '',
                acknowledged_by TEXT NOT NULL DEFAULT '',
                mode TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_network_ids_alert_tracking_status ON network_ids_alert_tracking (status);

            CREATE TABLE IF NOT EXISTS eve_network_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                eve_json_path TEXT NOT NULL,
                timestamp TEXT NOT NULL DEFAULT '',
                event_type TEXT NOT NULL DEFAULT '',
                src_ip TEXT NOT NULL DEFAULT '',
                src_port TEXT NOT NULL DEFAULT '',
                dest_ip TEXT NOT NULL DEFAULT '',
                dest_port TEXT NOT NULL DEFAULT '',
                proto TEXT NOT NULL DEFAULT '',
                app_proto TEXT NOT NULL DEFAULT '',
                flow_id TEXT NOT NULL DEFAULT '',
                in_iface TEXT NOT NULL DEFAULT '',
                community_id TEXT NOT NULL DEFAULT '',
                host TEXT NOT NULL DEFAULT '',
                tx_id TEXT NOT NULL DEFAULT '',
                domain TEXT NOT NULL DEFAULT '',
                url TEXT NOT NULL DEFAULT '',
                method TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT '',
                user_agent TEXT NOT NULL DEFAULT '',
                tls_sni TEXT NOT NULL DEFAULT '',
                file_name TEXT NOT NULL DEFAULT '',
                file_hash TEXT NOT NULL DEFAULT '',
                bytes_toserver INTEGER NOT NULL DEFAULT 0,
                bytes_toclient INTEGER NOT NULL DEFAULT 0,
                pkts_toserver INTEGER NOT NULL DEFAULT 0,
                pkts_toclient INTEGER NOT NULL DEFAULT 0,
                flow_state TEXT NOT NULL DEFAULT '',
                summary TEXT NOT NULL DEFAULT '',
                event_json TEXT NOT NULL DEFAULT '',
                ingested_at TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_eve_network_events_path_time ON eve_network_events (eve_json_path, timestamp);
            CREATE INDEX IF NOT EXISTS idx_eve_network_events_path_type_time ON eve_network_events (eve_json_path, event_type, timestamp);
            CREATE INDEX IF NOT EXISTS idx_eve_network_events_path_src_time ON eve_network_events (eve_json_path, src_ip, timestamp);
            CREATE INDEX IF NOT EXISTS idx_eve_network_events_path_dest_time ON eve_network_events (eve_json_path, dest_ip, timestamp);
            """
        )
        db.execute("PRAGMA journal_mode = WAL")
        for column, definition in {
            "last_check_network_read": "INTEGER NOT NULL DEFAULT 0",
            "ingest_profile": "TEXT NOT NULL DEFAULT ''",
        }.items():
            try:
                db.execute(f"ALTER TABLE eve_ingest_state ADD COLUMN {column} {definition}")
            except sqlite3.OperationalError:
                pass
        network_columns = {
            "domain": "TEXT NOT NULL DEFAULT ''",
            "url": "TEXT NOT NULL DEFAULT ''",
            "method": "TEXT NOT NULL DEFAULT ''",
            "status": "TEXT NOT NULL DEFAULT ''",
            "user_agent": "TEXT NOT NULL DEFAULT ''",
            "tls_sni": "TEXT NOT NULL DEFAULT ''",
            "file_name": "TEXT NOT NULL DEFAULT ''",
            "file_hash": "TEXT NOT NULL DEFAULT ''",
            "bytes_toserver": "INTEGER NOT NULL DEFAULT 0",
            "bytes_toclient": "INTEGER NOT NULL DEFAULT 0",
            "pkts_toserver": "INTEGER NOT NULL DEFAULT 0",
            "pkts_toclient": "INTEGER NOT NULL DEFAULT 0",
            "flow_state": "TEXT NOT NULL DEFAULT ''",
        }
        for column, definition in network_columns.items():
            try:
                db.execute(f"ALTER TABLE eve_network_events ADD COLUMN {column} {definition}")
            except sqlite3.OperationalError:
                pass
        db.execute("CREATE INDEX IF NOT EXISTS idx_eve_network_events_path_domain_time ON eve_network_events (eve_json_path, domain, timestamp)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_eve_network_events_path_sni_time ON eve_network_events (eve_json_path, tls_sni, timestamp)")
        db.execute("CREATE TABLE IF NOT EXISTS network_ids_alert_tracking (alert_id INTEGER PRIMARY KEY, status TEXT NOT NULL DEFAULT 'new', acknowledged_at TEXT NOT NULL DEFAULT '', acknowledged_by TEXT NOT NULL DEFAULT '', mode TEXT NOT NULL DEFAULT '')")
        db.execute("CREATE INDEX IF NOT EXISTS idx_network_ids_alert_tracking_status ON network_ids_alert_tracking (status)")
        db.commit()


def init_db(bootstrap_admin_user: bool = True) -> None:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with get_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
                full_name TEXT NOT NULL DEFAULT '',
                email TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                csrf_token TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                ip_address TEXT NOT NULL DEFAULT '',
                user_agent TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS modules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                config TEXT NOT NULL DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS opensmart_modules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                config TEXT NOT NULL DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                actor_user_id INTEGER,
                actor_username TEXT NOT NULL DEFAULT '',
                event_type TEXT NOT NULL,
                target TEXT NOT NULL DEFAULT '',
                ip_address TEXT NOT NULL DEFAULT '',
                detail TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS login_attempts (
                username TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                failed_count INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (username, ip_address)
            );

            CREATE TABLE IF NOT EXISTS resource_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sampled_at TEXT NOT NULL,
                cpu_percent REAL NOT NULL DEFAULT 0,
                memory_percent REAL NOT NULL DEFAULT 0,
                disk_percent REAL NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_resource_snapshots_time ON resource_snapshots (sampled_at);

            CREATE TABLE IF NOT EXISTS vpn_instances (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                vpn_type TEXT NOT NULL CHECK(vpn_type IN ('openvpn', 'wireguard')),
                port INTEGER NOT NULL UNIQUE,
                subnet TEXT NOT NULL,
                auth_mode TEXT NOT NULL DEFAULT 'certs' CHECK(auth_mode IN ('certs', 'ldap')),
                ldap_config TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS network_interfaces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                mac TEXT NOT NULL DEFAULT '',
                alias TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                role TEXT NOT NULL DEFAULT '' CHECK(role IN ('', 'wan', 'lan', 'dmz', 'mgmt', 'monitor')),
                mtu_override INTEGER,
                monitor INTEGER NOT NULL DEFAULT 0,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS network_interface_applies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                token TEXT NOT NULL UNIQUE,
                old_mtu INTEGER NOT NULL,
                new_mtu INTEGER NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('pending', 'confirmed', 'reverted', 'failed')),
                actor TEXT NOT NULL DEFAULT '',
                applied_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS firewall_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL DEFAULT '',
                active INTEGER NOT NULL DEFAULT 0,
                engine TEXT NOT NULL DEFAULT 'nftables',
                policies TEXT NOT NULL DEFAULT '{"input":"drop","forward":"drop","output":"accept"}',
                custom_nft TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS firewall_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id INTEGER NOT NULL REFERENCES firewall_profiles(id) ON DELETE CASCADE,
                chain TEXT NOT NULL CHECK(chain IN ('input', 'forward', 'output')),
                position INTEGER NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                system_rule INTEGER NOT NULL DEFAULT 0,
                action TEXT NOT NULL DEFAULT 'accept' CHECK(action IN ('accept', 'drop', 'reject')),
                reject_with TEXT NOT NULL DEFAULT '',
                family TEXT NOT NULL DEFAULT 'inet' CHECK(family IN ('inet', 'ip', 'ip6')),
                protocol TEXT NOT NULL DEFAULT 'any',
                iif TEXT NOT NULL DEFAULT '',
                oif TEXT NOT NULL DEFAULT '',
                src TEXT NOT NULL DEFAULT '',
                src_negate INTEGER NOT NULL DEFAULT 0,
                dst TEXT NOT NULL DEFAULT '',
                dst_negate INTEGER NOT NULL DEFAULT 0,
                sport TEXT NOT NULL DEFAULT '',
                dport TEXT NOT NULL DEFAULT '',
                ct_state TEXT NOT NULL DEFAULT '',
                icmp_type TEXT NOT NULL DEFAULT '',
                log INTEGER NOT NULL DEFAULT 0,
                log_prefix TEXT NOT NULL DEFAULT '',
                rate_limit TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_firewall_rules_order ON firewall_rules (profile_id, chain, position);

            CREATE TABLE IF NOT EXISTS firewall_applies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id INTEGER NOT NULL,
                token TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL CHECK(state IN ('pending', 'confirmed', 'reverted', 'failed')),
                actor TEXT NOT NULL DEFAULT '',
                applied_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS firewall_aliases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL CHECK(kind IN ('address', 'port')),
                values_csv TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS vpn_cas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                cn TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            """
        )
        db.execute("PRAGMA journal_mode = WAL")
        for column in ("ip_address", "user_agent"):
            try:
                db.execute(f"ALTER TABLE sessions ADD COLUMN {column} TEXT NOT NULL DEFAULT ''")
            except sqlite3.OperationalError:
                pass
        try:
            db.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError:
            pass
        # Per-user theme override ('' = inherit the admin-set default theme).
        try:
            db.execute("ALTER TABLE users ADD COLUMN theme TEXT NOT NULL DEFAULT ''")
        except sqlite3.OperationalError:
            pass
        # Editable per-instance VPN server settings (dns, tunnel mode, routes).
        try:
            db.execute("ALTER TABLE vpn_instances ADD COLUMN settings TEXT NOT NULL DEFAULT '{}'")
        except sqlite3.OperationalError:
            pass
        # Shared CA an OpenVPN instance's certs are signed by ('' = legacy
        # per-instance PKI, still supported).
        try:
            db.execute("ALTER TABLE vpn_instances ADD COLUMN ca TEXT NOT NULL DEFAULT ''")
        except sqlite3.OperationalError:
            pass
        # A profile renders to exactly one engine's ruleset syntax; existing
        # profiles predate the iptables engine and backfill to 'nftables',
        # the only engine that has ever existed.
        try:
            db.execute("ALTER TABLE firewall_profiles ADD COLUMN engine TEXT NOT NULL DEFAULT 'nftables'")
        except sqlite3.OperationalError:
            pass
        for key, value in DEFAULT_SETTINGS.items():
            db.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, value))
        # The demo dashboard-metrics feature (fake counters + "fill disabled
        # panels with demo data" toggle) was removed; drop any rows older
        # installs seeded so they don't linger as orphaned config.
        db.execute(
            "DELETE FROM settings WHERE key IN ("
            "'dashboard_ids_alerts_critical','dashboard_ids_alerts_high','dashboard_ids_alerts_medium','dashboard_ids_alerts_low',"
            "'dashboard_ids_severity_critical','dashboard_ids_severity_high','dashboard_ids_severity_medium','dashboard_ids_severity_low',"
            "'dashboard_fw_blocked_packets_24h','dashboard_fw_blocked_ips_24h','dashboard_fw_allowed_packets_24h',"
            "'dashboard_endpoints_total','dashboard_vulnerabilities_critical','dashboard_vulnerabilities_high',"
            "'dashboard_vulnerabilities_medium','dashboard_vulnerabilities_open','dashboard_vpn_users','dashboard_lxc_assets',"
            "'dashboard_feed_json','dashboard_use_demo_for_disabled')"
        )
        # Honeynet is the new default theme; flip installs still on the old
        # 'dark' default (leaves an explicitly-chosen non-dark theme alone).
        db.execute("UPDATE settings SET value = 'honeynet' WHERE key = 'theme' AND value = 'dark'")
        db.execute("UPDATE settings SET value = ? WHERE key = 'platform_version' AND value = 'v0.2'", (APP_VERSION,))
        db.execute(
            "INSERT INTO settings (key, value) VALUES ('platform_build', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (BUILD_VERSION,),
        )
        for module in DEFAULT_TOOLS:
            db.execute(
                "INSERT OR IGNORE INTO modules (name, description, enabled, config) VALUES (?, ?, ?, ?)",
                module,
            )
        db.execute("DELETE FROM modules WHERE name IN ('Suricata', 'Zeek', 'VPN', 'LXC manager', 'LXC Manager', 'OpenSense')")
        for module in DEFAULT_OPENSMART_MODULES:
            db.execute(
                "INSERT OR IGNORE INTO opensmart_modules (name, description, enabled, config) VALUES (?, ?, ?, ?)",
                module,
            )
        db.execute(
            """
            UPDATE opensmart_modules
            SET config = '{"eve_json_path":"","summary_refresh_minutes":"5","initial_ingestion_gb":"2","default_top_n":"10","analysis_page_size":"30","details_max_rows":"500","details_page_size":"100"}'
            WHERE name = 'Network IDS' AND config = '{}'
            """
        )
        db.execute(
            """
            UPDATE opensmart_modules
            SET config = '{"log_source":"eve_json","zeek_json_path":"","index_dns":"true","index_http":"true","index_tls":"true","index_flow":"true","index_fileinfo":"false","index_smb":"false","index_other_app_layer":"false","index_all_suricata_protocols":"false","exclude_event_types":"[\"stats\",\"drop\",\"internal\",\"pcap\"]"}'
            WHERE name = 'Network Traffic Monitoring' AND config = '{}'
            """
        )
        db.execute(
            """
            UPDATE opensmart_modules
            SET config = '{"confirm_seconds":"60","safety_rules":"true","reapply_on_start":"true","ssh_port":"22","management_cidr":""}'
            WHERE name = 'Firewall' AND config = '{}'
            """
        )
        # Seed one active "Default" firewall profile with drop policies on
        # input/forward — safe only because the safety rules below (pinned
        # first, system_rule=1) are evaluated before that terminal drop, so a
        # fresh install is locked-down-by-default without locking itself out.
        # See design notes "Decisions" for why.
        if db.execute("SELECT 1 FROM firewall_profiles LIMIT 1").fetchone() is None:
            fw_now = datetime.now(timezone.utc).isoformat()
            cur = db.execute(
                "INSERT INTO firewall_profiles (name, description, active, policies, created_at, updated_at) "
                "VALUES ('Default', 'Seeded on install — safe defaults with management/SSH access preserved.', 1, "
                "'{\"input\":\"drop\",\"forward\":\"drop\",\"output\":\"accept\"}', ?, ?)",
                (fw_now, fw_now),
            )
            profile_id = cur.lastrowid
            # system_rule tiers: 1 = fully pinned (position/fields locked,
            # enable/disable only); 2 = allowlist-managed (src/src_negate
            # also editable, subject to firewall._validate_allowlist_src —
            # see earlier revision's Wizard allowlist step and rule manager).
            safety_rules = [
                # chain, position, system_rule, action, protocol, iif, oif, dport, ct_state, description
                ("input", 1, 1, "accept", "any", "lo", "", "", "", "Loopback"),
                ("input", 2, 1, "accept", "any", "", "", "", "established,related", "Existing/related connections"),
                # These two are the ones the initial-Wizard allowlist step and
                # the rule manager's "Allowlist management" edit both target —
                # renaming or duplicating them would break that link (see
                # firewall.update_rule()'s system_rule=2 handling).
                ("input", 3, 2, "accept", "tcp", "", "", "22", "", "Allowlist management SSH"),
                ("input", 4, 2, "accept", "tcp", "", "", "443", "", "Allowlist management Web"),
                ("input", 5, 1, "accept", "tcp", "", "", "80,8000", "", "HTTP / direct-access web console"),
                ("forward", 1, 1, "accept", "any", "docker0,br-*", "", "", "", "Docker bridge traffic (inbound)"),
                ("forward", 2, 1, "accept", "any", "", "docker0,br-*", "", "", "Docker bridge traffic (outbound)"),
                ("forward", 3, 1, "accept", "any", "", "", "", "established,related", "Existing/related connections"),
            ]
            for chain, position, system_rule, action, protocol, iif, oif, dport, ct_state, description in safety_rules:
                db.execute(
                    "INSERT INTO firewall_rules (profile_id, chain, position, system_rule, action, protocol, iif, oif, dport, ct_state, description, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (profile_id, chain, position, system_rule, action, protocol, iif, oif, dport, ct_state, description, fw_now, fw_now),
                )
        # earlier revision: promote the dedicated SSH/443 safety rules seeded by
        # earlier revision (system_rule=1, always-open) to the new "allowlist-
        # managed" tier and rename them to the exact strings the Wizard
        # allowlist step and rule manager key off of. Repurposing these rules
        # — rather than adding new, separate ones — is what makes "adding a
        # custom network makes the allowlist effective" true: a second,
        # still-always-open accept rule would keep matching everyone
        # regardless of what a new rule restricts. Idempotent: only matches
        # rows still at the pre-migration description, so re-running this
        # (or an admin renaming their own copy back) doesn't re-fire.
        db.execute(
            "UPDATE firewall_rules SET system_rule = 2, description = 'Allowlist management SSH' "
            "WHERE system_rule = 1 AND description = 'SSH management access'"
        )
        db.execute(
            "UPDATE firewall_rules SET system_rule = 2, description = 'Allowlist management Web' "
            "WHERE system_rule = 1 AND description = 'HTTPS web console (always allowed — prevents lockout)'"
        )
        # Backfill network_interfaces rows from the legacy monitor_interfaces
        # setting (comma-separated interface names chosen in the Wizard), so
        # existing installs' capture interfaces carry over as monitor=1 rows
        # instead of starting with an empty registry.
        legacy_monitor_row = db.execute("SELECT value FROM settings WHERE key = 'monitor_interfaces'").fetchone()
        if legacy_monitor_row and legacy_monitor_row["value"].strip(","):
            now = datetime.now(timezone.utc).isoformat()
            for iface_name in legacy_monitor_row["value"].strip(",").split(","):
                iface_name = iface_name.strip()
                if not iface_name:
                    continue
                db.execute(
                    "INSERT INTO network_interfaces (name, monitor, first_seen_at, last_seen_at, updated_at) "
                    "VALUES (?, 1, ?, ?, ?) "
                    "ON CONFLICT(name) DO UPDATE SET monitor = 1, updated_at = excluded.updated_at",
                    (iface_name, now, now, now),
                )
        # One-time migration: previously `network_ids_keep_empty_alerts` was a
        # global setting; it is now part of the Network IDS module config.
        # Move any existing value into the module config (only if the module
        # config does not already define it), then delete the orphan setting.
        try:
            legacy_row = db.execute(
                "SELECT value FROM settings WHERE key = 'network_ids_keep_empty_alerts'"
            ).fetchone()
            if legacy_row is not None:
                module_row = db.execute(
                    "SELECT config FROM opensmart_modules WHERE name = 'Network IDS'"
                ).fetchone()
                if module_row is not None:
                    try:
                        module_cfg = json.loads(module_row["config"] or "{}")
                    except json.JSONDecodeError:
                        module_cfg = {}
                    if "keep_empty_alerts" not in module_cfg:
                        legacy_value = str(legacy_row["value"]).strip().lower()
                        normalized = "true" if legacy_value in ("1", "true", "yes", "on") else "false"
                        module_cfg["keep_empty_alerts"] = normalized
                        db.execute(
                            "UPDATE opensmart_modules SET config = ? WHERE name = 'Network IDS'",
                            (json.dumps(module_cfg),),
                        )
                        logger.info(
                            "Migrated network_ids_keep_empty_alerts=%s from settings to Network IDS module config",
                            normalized,
                        )
                db.execute("DELETE FROM settings WHERE key = 'network_ids_keep_empty_alerts'")
        except sqlite3.OperationalError as error:
            logger.warning("network_ids_keep_empty_alerts migration skipped: %s", error)
        db.commit()
    if bootstrap_admin_user:
        bootstrap_admin()


def generate_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + "-_=+!@#%"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def bootstrap_admin() -> None:
    with get_db() as db:
        existing = db.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1").fetchone()
        if existing:
            return
        password = generate_password()
        db.execute(
            """
            INSERT INTO users (username, password_hash, role, full_name, email, enabled, must_change_password, created_at)
            VALUES (?, ?, 'admin', 'OpenSMART Administrator', '', 1, 1, ?)
            """,
            ("admin", ph.hash(password), now_iso()),
        )
        db.execute(
            "INSERT INTO settings (key, value) VALUES ('wizard_completed', 'false') "
            "ON CONFLICT(key) DO UPDATE SET value = 'false'"
        )
        db.commit()
    print("OpenSMART initial admin account created", flush=True)
    print("Username: admin", flush=True)
    print(f"Password: {password}", flush=True)
    print("Change this password after first login.", flush=True)


def reset_data_tables() -> None:
    """Fast data reset via dump → unlink → recreate → restore.

    Algorithm:
      1. Dump preserve tables to a sidecar SQL file at
         <DB_PATH>.preserve.<utc-timestamp>.sql using INSERT statements.
      2. Delete the DB file plus -wal/-shm/-journal sidecars.
      3. Recreate schema via init_db(bootstrap_admin_user=False) — single
         source of truth for DDL.
      4. Clear default-seeded rows in preserve tables and replay the dump.
      5. Delete the sidecar SQL file on success; leave it in place on failure
         so the operator can manually recover with:
             sqlite3 <DB_PATH> < <DB_PATH>.preserve.<ts>.sql

    Cost is O(preserved-rows) regardless of operational data volume; reclaims
    disk space because the file is recreated from scratch. AUTOINCREMENT
    counters reset because sqlite_sequence is gone with the file.

    Tables preserved: users, settings, modules, opensmart_modules, audit_events.
    Tables wiped:     sessions, login_attempts, resource_snapshots.
                     Module DBs are reset separately by reset_telemetry_data().
    """
    preserve_tables = ("users", "settings", "modules", "opensmart_modules", "audit_events")
    db_path = Path(DB_PATH)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    backup_path = db_path.with_name(f"{db_path.name}.preserve.{timestamp}.sql")

    # 1. Dump preserve tables to a sidecar SQL file (INSERT statements only).
    with get_db() as db, backup_path.open("w", encoding="utf-8") as out:
        for table in preserve_tables:
            cur = db.execute(f"SELECT * FROM {table}")
            cols = [d[0] for d in cur.description]
            col_list = ", ".join(f'"{c}"' for c in cols)
            for row in cur.fetchall():
                values = ", ".join(_sql_literal(row[c]) for c in cols)
                out.write(f'INSERT INTO "{table}" ({col_list}) VALUES ({values});\n')

    # 2. Delete the DB file and its WAL/SHM/journal sidecars.
    for suffix in ("", "-wal", "-shm", "-journal"):
        target = db_path.with_name(db_path.name + suffix) if suffix else db_path
        try:
            target.unlink()
        except FileNotFoundError:
            pass

    # 3. Recreate schema (re-seeds default settings, modules, opensmart_modules
    #    via INSERT OR IGNORE; we will overwrite those next).
    init_db(bootstrap_admin_user=False)

    # 4. Clear default-seeded preserve rows, then replay the dump.
    try:
        with get_db() as db:
            for table in preserve_tables:
                db.execute(f"DELETE FROM {table}")
            with backup_path.open("r", encoding="utf-8") as inp:
                db.executescript(inp.read())
    except Exception:
        # Leave backup in place on failure for manual recovery.
        raise

    # 5. Success — remove the backup file.
    try:
        backup_path.unlink()
    except FileNotFoundError:
        pass


def reset_telemetry_data() -> None:
    """Reset IDS and Network Traffic module DBs without touching app data."""
    reset_telemetry_ids()
    reset_telemetry_network()


def reset_telemetry_ids() -> None:
    """Delete/recreate IDS module DB; preserve Network Traffic data."""
    _unlink_db_files(Path(NETWORK_IDS_DB_PATH))
    init_network_ids_db()


def reset_telemetry_network() -> None:
    """Delete/recreate Network Traffic module DB; preserve IDS data."""
    _unlink_db_files(Path(NETWORK_TRAFFIC_DB_PATH))
    init_network_traffic_db()


def _unlink_db_files(db_path: Path) -> None:
    for suffix in ("", "-wal", "-shm", "-journal"):
        target = db_path.with_name(db_path.name + suffix) if suffix else db_path
        try:
            target.unlink()
        except FileNotFoundError:
            pass


def _sql_literal(value: object) -> str:
    """Render a Python value as a SQLite literal for INSERT statements."""
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, bytes):
        return "X'" + value.hex() + "'"
    # Treat everything else as text; escape single quotes per SQL standard.
    text = str(value).replace("'", "''")
    return f"'{text}'"


def rows_to_dicts(rows: list[sqlite3.Row]) -> list[dict]:
    return [dict(row) for row in rows]


def write_audit_event(
    event_type: str,
    actor_user_id: int | None = None,
    actor_username: str = "",
    target: str = "",
    ip_address: str = "",
    detail: str = "",
) -> None:
    with get_db() as db:
        db.execute(
            """
            INSERT INTO audit_events (created_at, actor_user_id, actor_username, event_type, target, ip_address, detail)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (now_iso(), actor_user_id, actor_username, event_type, target, ip_address, detail),
        )
        db.commit()

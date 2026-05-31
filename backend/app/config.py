import os
import subprocess
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = BASE_DIR.parent
LOG_DIR = PROJECT_ROOT / "logs"
DB_PATH = Path(os.getenv("OPENSMART_DB_PATH", BASE_DIR / "opensmart.db"))
TELEMETRY_DB_PATH = Path(os.getenv("OPENSMART_TELEMETRY_DB_PATH", BASE_DIR / "opensmart_telemetry.db"))
NETWORK_IDS_DB_PATH = Path(os.getenv("OPENSMART_NETWORK_IDS_DB_PATH", BASE_DIR / "opensmart_network_ids.db"))
NETWORK_TRAFFIC_DB_PATH = Path(os.getenv("OPENSMART_NETWORK_TRAFFIC_DB_PATH", BASE_DIR / "opensmart_network_traffic.db"))
FRONTEND_ORIGIN = os.getenv("OPENSMART_FRONTEND_ORIGIN", "http://localhost:5173")
SESSION_COOKIE = "opensmart_session"
CSRF_COOKIE = "opensmart_csrf"
SESSION_TTL_HOURS = int(os.getenv("OPENSMART_SESSION_TTL_HOURS", "12"))
APP_VERSION = os.getenv("OPENSMART_VERSION", "v0.2 beta")


def read_git_build() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=BASE_DIR.parent,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown"


BUILD_VERSION = os.getenv("OPENSMART_BUILD", read_git_build())


def resolve_log_path(value: str | None = None) -> Path:
    path = Path(value or "logs/opensmart.log")
    return path if path.is_absolute() else PROJECT_ROOT / path

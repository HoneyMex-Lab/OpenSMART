import logging
import sys
from pathlib import Path

from .config import DB_PATH, LOG_DIR, NETWORK_IDS_DB_PATH, NETWORK_TRAFFIC_DB_PATH
from .database import generate_password, get_db, init_db, init_network_ids_db, init_network_traffic_db, reset_data_tables, reset_telemetry_data, reset_telemetry_ids, reset_telemetry_network
from .security import set_user_password

# Logger for admin tool operations. Messages include source=run_script so they
# are visually distinct and grep-able in opensmart.log.
_logger = logging.getLogger(__name__)


def _configure_admin_logging() -> None:
    """Install a FileHandler for opensmart.log when running as a CLI tool.

    The backend server configures logging via main._configure_file_logging().
    When admin_tools is invoked as a standalone process (python -m ...), no
    FileHandler is present yet, so we add one here.
    """
    path = LOG_DIR / "opensmart.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    root_logger = logging.getLogger()
    if not any(
        isinstance(h, logging.FileHandler) and getattr(h, "baseFilename", None) == str(path)
        for h in root_logger.handlers
    ):
        handler = logging.FileHandler(path, encoding="utf-8")
        handler.setLevel(logging.INFO)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        root_logger.addHandler(handler)
        if root_logger.level == logging.NOTSET or root_logger.level > logging.INFO:
            root_logger.setLevel(logging.INFO)


def print_password_box(title: str, username: str, password: str, footer: str = "Save this password now. It will not be shown again.") -> None:
    """Print the new password inside a prominent ASCII box."""
    lines = [
        title,
        "",
        f"  Username : {username}",
        f"  Password : {password}",
        "",
        f"  {footer}",
    ]
    width = max(len(line) for line in lines) + 4
    border = "*" * width
    print(border, flush=True)
    print("*" + " " * (width - 2) + "*", flush=True)
    for line in lines:
        padding = width - 2 - len(line) - 2
        print(f"*  {line}" + " " * padding + "*", flush=True)
    print("*" + " " * (width - 2) + "*", flush=True)
    print(border, flush=True)


def reset_admin_password() -> str:
    init_db(bootstrap_admin_user=False)
    password = generate_password()
    with get_db() as db:
        row = db.execute("SELECT id FROM users WHERE username = ? AND role = 'admin'", ("admin",)).fetchone()
        if not row:
            raise RuntimeError("Admin user does not exist")
    set_user_password(row["id"], password, require_change=True, invalidate_sessions=True)
    _logger.info("source=run_script action=reset_admin_password username=admin")
    return password


def reset_data() -> None:
    """Reset all operational/IDS data while keeping config, users, and settings."""
    init_db(bootstrap_admin_user=False)
    reset_data_tables()
    reset_telemetry_data()
    _logger.info("source=run_script action=reset_data_all username=system")


def reset_data_ids() -> None:
    """Reset only IDS alert data; preserve network traffic and config."""
    init_db(bootstrap_admin_user=False)
    reset_telemetry_ids()
    _logger.info("source=run_script action=reset_data_ids username=system")


def reset_data_network() -> None:
    """Reset only network traffic data; preserve IDS alerts and config."""
    init_db(bootstrap_admin_user=False)
    reset_telemetry_network()
    _logger.info("source=run_script action=reset_data_network username=system")


def full_reset() -> str:
    """Delete the database entirely and reinitialize. Returns the new admin password."""
    for db_path in (DB_PATH, NETWORK_IDS_DB_PATH, NETWORK_TRAFFIC_DB_PATH):
        _unlink_db_files(db_path)
    init_db(bootstrap_admin_user=True)
    init_network_ids_db()
    init_network_traffic_db()
    # After fresh init, reset the auto-generated password so we can return it explicitly
    password = generate_password()
    with get_db() as db:
        row = db.execute("SELECT id FROM users WHERE username = ? AND role = 'admin'", ("admin",)).fetchone()
    if row:
        set_user_password(row["id"], password, require_change=True, invalidate_sessions=True)
    _logger.info("source=run_script action=full_reset username=system")
    return password


def _unlink_db_files(db_path: Path) -> None:
    for suffix in ("", "-wal", "-shm", "-journal"):
        target = db_path.with_name(db_path.name + suffix) if suffix else db_path
        try:
            target.unlink()
        except FileNotFoundError:
            pass


def main() -> None:
    _configure_admin_logging()
    args = sys.argv[1:]

    if "--reset-data-all" in args or "--reset-data" in args:
        reset_data()
        print("OpenSMART full data reset complete.", flush=True)
        print("All IDS data, network traffic, sessions, audit events, and login attempts cleared.", flush=True)
        print("Users, settings, and module config are preserved.", flush=True)
        return

    if "--reset-data-ids" in args:
        reset_data_ids()
        print("IDS data reset complete.", flush=True)
        print("All IDS alerts and artifacts cleared. Network traffic data preserved.", flush=True)
        return

    if "--reset-data-network" in args:
        reset_data_network()
        print("Network traffic data reset complete.", flush=True)
        print("All network traffic events cleared. IDS alerts preserved.", flush=True)
        return

    if "--full-reset" in args:
        password = full_reset()
        print_password_box(
            "  OpenSMART - Full Reset Complete",
            "admin",
            password,
            "All data and config has been reset. Save this password now.",
        )
        return

    # Default: reset admin password
    password = reset_admin_password()
    print_password_box(
        "  OpenSMART - Admin Password Reset",
        "admin",
        password,
    )


if __name__ == "__main__":
    main()

from collections import deque
from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from ..config import resolve_log_path
from ..database import get_db, rows_to_dicts
from ..security import get_current_user

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("")
def list_audit_events(user: Annotated[dict, Depends(get_current_user)]) -> dict:
    with get_db() as db:
        if user["role"] == "admin":
            rows = db.execute(
                """
                SELECT created_at, actor_username, event_type, target, ip_address, detail
                FROM audit_events
                WHERE event_type IN ('logon', 'logout', 'settings_update', 'tools_config_update', 'opensmart_config_update', 'user_create', 'user_update', 'user_delete', 'password_change', 'profile_update', 'sessions_terminated', 'provisioning_start', 'provisioning_stop')
                ORDER BY id DESC
                LIMIT 100
                """
            ).fetchall()
        else:
            rows = db.execute(
                """
                SELECT created_at, actor_username, event_type, target, ip_address, detail
                FROM audit_events
                WHERE actor_user_id = ? AND event_type = 'logon'
                ORDER BY id DESC
                LIMIT 100
                """,
                (user["id"],),
            ).fetchall()
    return {"events": rows_to_dicts(rows)}


@router.get("/log")
def get_audit_log(user: Annotated[dict, Depends(get_current_user)], lines: int = 500) -> JSONResponse:
    if user["role"] != "admin":
        return JSONResponse(status_code=403, content={"error": "Admin only"})
    with get_db() as db:
        row = db.execute("SELECT value FROM settings WHERE key = 'log_file_path'").fetchone()
    log_file_path = row["value"] if row else None
    path = resolve_log_path(log_file_path)
    lines = max(1, min(lines, 5000))
    if not path.exists():
        return JSONResponse({"lines": [], "path": str(path), "error": "Log file not found"})
    with open(path, encoding="utf-8", errors="replace") as f:
        tail = list(deque(f, maxlen=lines))
    return JSONResponse({"lines": [line.rstrip("\n") for line in tail], "path": str(path), "error": None})

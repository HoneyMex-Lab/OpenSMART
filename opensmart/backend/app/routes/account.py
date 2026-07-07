import logging
import threading
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from .. import provisioning
from ..database import get_db, rows_to_dicts, write_audit_event
from ..security import get_current_user, require_csrf, set_user_password, validate_password_complexity, verify_password

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/account", tags=["account"])


def _sync_tool_passwords(password: str) -> None:
    """Keep tool credentials we provision in step with the admin password.
    Best-effort and off the request path: runs in a background thread so a
    slow/failed sync never delays or fails the user's password change. Only
    Arkime today (the one tool whose admin we create); other tools manage
    their own credentials."""
    def _run() -> None:
        ok, detail = provisioning.sync_arkime_password(password)
        if ok:
            logger.info("Arkime admin password synced to the OpenSMART admin password.")
        else:
            logger.warning("Arkime admin password sync skipped/failed: %s", detail[:300])
    threading.Thread(target=_run, daemon=True).start()


class PasswordPayload(BaseModel):
    currentPassword: str = Field(min_length=1, max_length=200)
    newPassword: str = Field(min_length=1, max_length=200)


class ProfilePayload(BaseModel):
    fullName: str = Field(default="", max_length=120)
    email: str = Field(default="", max_length=180)


@router.post("/password")
def change_password(payload: PasswordPayload, user: Annotated[dict, Depends(require_csrf)]) -> dict:
    with get_db() as db:
        row = db.execute("SELECT password_hash FROM users WHERE id = ?", (user["id"],)).fetchone()
        if not row or not verify_password(payload.currentPassword, row["password_hash"]):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")
    validate_password_complexity(payload.newPassword)
    set_user_password(user["id"], payload.newPassword, require_change=False, invalidate_sessions=False)
    write_audit_event("password_change", user["id"], user["username"], "account", "", "password changed")
    # Admins share a single sign-in password with the tools OpenSMART
    # provisions (Arkime today), so a changed admin password propagates there.
    if user["role"] == "admin":
        _sync_tool_passwords(payload.newPassword)
    return {"ok": True}


@router.put("/profile")
def update_profile(payload: ProfilePayload, user: Annotated[dict, Depends(require_csrf)]) -> dict:
    with get_db() as db:
        db.execute(
            "UPDATE users SET full_name = ?, email = ? WHERE id = ?",
            (payload.fullName.strip(), payload.email.strip(), user["id"]),
        )
        db.commit()
    write_audit_event("profile_update", user["id"], user["username"], "account", "", "profile updated")
    return {
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "fullName": payload.fullName.strip(),
            "email": payload.email.strip(),
        }
    }


@router.get("/sessions")
def account_sessions(user: Annotated[dict, Depends(get_current_user)]) -> dict:
    with get_db() as db:
        sessions = rows_to_dicts(
            db.execute(
                """
                SELECT token, created_at, expires_at, ip_address, user_agent
                FROM sessions
                WHERE user_id = ?
                ORDER BY created_at DESC
                """,
                (user["id"],),
            ).fetchall()
        )
        logons = rows_to_dicts(
            db.execute(
                """
                SELECT created_at, ip_address, detail
                FROM audit_events
                WHERE actor_user_id = ? AND event_type = 'logon'
                ORDER BY created_at DESC
                LIMIT 3
                """,
                (user["id"],),
            ).fetchall()
        )
    for session in sessions:
        session["current"] = session["token"] == user["token"]
        session.pop("token", None)
    return {"sessions": sessions, "logons": logons}


@router.delete("/sessions/others")
def terminate_other_sessions(user: Annotated[dict, Depends(require_csrf)]) -> dict:
    with get_db() as db:
        db.execute("DELETE FROM sessions WHERE user_id = ? AND token != ?", (user["id"], user["token"]))
        db.commit()
    write_audit_event("sessions_terminated", user["id"], user["username"], "account", "", "terminated other sessions")
    return account_sessions(user)

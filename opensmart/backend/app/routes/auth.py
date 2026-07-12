from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from ..config import CSRF_COOKIE, SESSION_COOKIE
from ..database import get_db, write_audit_event
from ..security import (
    check_lockout,
    clear_failed_logins,
    create_session,
    destroy_session,
    get_client_ip,
    get_current_user,
    record_failed_login,
    require_csrf,
    verify_password,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginPayload(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=200)


def public_user(user: dict) -> dict:
    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "fullName": user["full_name"],
        "email": user["email"],
        "mustChangePassword": bool(user["must_change_password"]),
        "theme": user["theme"] if "theme" in user.keys() else "",
    }


@router.post("/login")
def login(payload: LoginPayload, request: Request, response: Response) -> dict:
    ip_address = get_client_ip(request)
    username = payload.username.strip()
    check_lockout(username, ip_address)
    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE username = ? AND enabled = 1", (username,)).fetchone()
    if not row or not verify_password(payload.password, row["password_hash"]):
        record_failed_login(username, ip_address)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
    clear_failed_logins(username, ip_address)
    create_session(response, row["id"], ip_address, request.headers.get("user-agent", ""))
    write_audit_event("logon", row["id"], row["username"], "auth", ip_address, "successful login")
    return {"user": public_user(dict(row))}


@router.post("/logout")
def logout(
    response: Response,
    _: Annotated[dict, Depends(require_csrf)],
    session_token: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
) -> dict:
    write_audit_event("logout", _["id"], _["username"], "auth", "", "user logout")
    destroy_session(response, session_token)
    return {"ok": True}


@router.get("/me")
def me(
    user: Annotated[dict, Depends(get_current_user)],
    csrf_token: Annotated[str | None, Cookie(alias=CSRF_COOKIE)] = None,
) -> dict:
    data = public_user(user)
    data["csrfToken"] = csrf_token
    return {"user": data}

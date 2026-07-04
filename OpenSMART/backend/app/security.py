import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from fastapi import Cookie, Depends, HTTPException, Request, Response, status

from .config import CSRF_COOKIE, SESSION_COOKIE, SESSION_TTL_HOURS
from .database import get_db, now_iso

ph = PasswordHasher()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value)


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    return request.client.host if request.client else "unknown"


def get_int_setting(key: str, default: int) -> int:
    with get_db() as db:
        row = db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    if not row:
        return default
    try:
        return int(row["value"])
    except ValueError:
        return default


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return ph.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError):
        return False


def hash_password(password: str) -> str:
    return ph.hash(password)


def check_lockout(username: str, ip_address: str) -> None:
    with get_db() as db:
        row = db.execute(
            "SELECT locked_until FROM login_attempts WHERE username = ? AND ip_address = ?",
            (username, ip_address),
        ).fetchone()
    locked_until = parse_dt(row["locked_until"]) if row else None
    if locked_until and locked_until > utc_now():
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed logins. Try again after {locked_until.isoformat()}.",
        )


def record_failed_login(username: str, ip_address: str) -> None:
    limit = get_int_setting("failed_login_limit", 5)
    lockout_minutes = get_int_setting("lockout_minutes", 15)
    with get_db() as db:
        row = db.execute(
            "SELECT failed_count FROM login_attempts WHERE username = ? AND ip_address = ?",
            (username, ip_address),
        ).fetchone()
        failed_count = (row["failed_count"] if row else 0) + 1
        locked_until = None
        if failed_count >= limit:
            locked_until = (utc_now() + timedelta(minutes=lockout_minutes)).isoformat()
        db.execute(
            """
            INSERT INTO login_attempts (username, ip_address, failed_count, locked_until, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(username, ip_address) DO UPDATE SET
                failed_count = excluded.failed_count,
                locked_until = excluded.locked_until,
                updated_at = excluded.updated_at
            """,
            (username, ip_address, failed_count, locked_until, now_iso()),
        )
        db.commit()


def clear_failed_logins(username: str, ip_address: str) -> None:
    with get_db() as db:
        db.execute("DELETE FROM login_attempts WHERE username = ? AND ip_address = ?", (username, ip_address))
        db.commit()


def create_session(response: Response, user_id: int, ip_address: str = "", user_agent: str = "") -> None:
    token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    expires_at = utc_now() + timedelta(hours=SESSION_TTL_HOURS)
    with get_db() as db:
        db.execute(
            """
            INSERT INTO sessions (token, user_id, csrf_token, expires_at, created_at, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (token, user_id, csrf_token, expires_at.isoformat(), now_iso(), ip_address, user_agent),
        )
        db.commit()
    response.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax", max_age=SESSION_TTL_HOURS * 3600)
    response.set_cookie(CSRF_COOKIE, csrf_token, httponly=False, samesite="lax", max_age=SESSION_TTL_HOURS * 3600)


def destroy_session(response: Response, token: str | None) -> None:
    if token:
        with get_db() as db:
            db.execute("DELETE FROM sessions WHERE token = ?", (token,))
            db.commit()
    response.delete_cookie(SESSION_COOKIE)
    response.delete_cookie(CSRF_COOKIE)


def get_current_user(session_token: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None) -> dict:
    if not session_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    with get_db() as db:
        row = db.execute(
            """
            SELECT s.token, s.csrf_token, s.expires_at, u.id, u.username, u.role, u.full_name, u.email, u.enabled
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token = ?
            """,
            (session_token,),
        ).fetchone()
    if not row or not row["enabled"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    if parse_dt(row["expires_at"]) <= utc_now():
        destroy_session(Response(), session_token)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired")
    return dict(row)


def require_csrf(request: Request, user: Annotated[dict, Depends(get_current_user)]) -> dict:
    csrf_header = request.headers.get("x-csrf-token")
    if not csrf_header or not secrets.compare_digest(csrf_header, user["csrf_token"]):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token")
    return user


def require_admin(user: Annotated[dict, Depends(require_csrf)]) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return user


def require_admin_read(user: Annotated[dict, Depends(get_current_user)]) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return user

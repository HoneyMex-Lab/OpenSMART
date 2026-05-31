from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from ..database import get_db, now_iso, rows_to_dicts, write_audit_event
from ..security import hash_password, require_admin, require_admin_read

router = APIRouter(prefix="/api/users", tags=["users"])


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=12, max_length=200)
    role: str = Field(pattern="^(admin|user)$")
    fullName: str = ""
    email: str = ""
    enabled: bool = True


class UserUpdate(BaseModel):
    role: str = Field(pattern="^(admin|user)$")
    fullName: str = ""
    email: str = ""
    enabled: bool = True
    password: str | None = Field(default=None, min_length=12, max_length=200)


def list_users_response() -> dict:
    with get_db() as db:
        rows = db.execute("SELECT id, username, role, full_name, email, enabled, created_at FROM users ORDER BY username").fetchall()
    users = rows_to_dicts(rows)
    for user in users:
        user["enabled"] = bool(user["enabled"])
        user["fullName"] = user.pop("full_name")
    return {"users": users}


@router.get("")
def list_users(_: Annotated[dict, Depends(require_admin_read)]) -> dict:
    return list_users_response()


@router.post("")
def create_user(payload: UserCreate, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    try:
        with get_db() as db:
            db.execute(
                """
                INSERT INTO users (username, password_hash, role, full_name, email, enabled, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.username.strip(),
                    hash_password(payload.password),
                    payload.role,
                    payload.fullName,
                    payload.email,
                    1 if payload.enabled else 0,
                    now_iso(),
                ),
            )
            db.commit()
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Could not create user") from exc
    write_audit_event("user_create", admin["id"], admin["username"], payload.username.strip(), "", "user created")
    return list_users_response()


@router.put("/{user_id}")
def update_user(user_id: int, payload: UserUpdate, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    if user_id == admin["id"] and not payload.enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot disable your own account")
    with get_db() as db:
        db.execute(
            "UPDATE users SET role = ?, full_name = ?, email = ?, enabled = ? WHERE id = ?",
            (payload.role, payload.fullName, payload.email, 1 if payload.enabled else 0, user_id),
        )
        if payload.password:
            db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(payload.password), user_id))
        db.commit()
    write_audit_event("user_update", admin["id"], admin["username"], str(user_id), "", "user updated")
    return list_users_response()


@router.delete("/{user_id}")
def delete_user(user_id: int, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    if user_id == admin["id"]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete your own account")
    with get_db() as db:
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()
    write_audit_event("user_delete", admin["id"], admin["username"], str(user_id), "", "user deleted")
    return list_users_response()

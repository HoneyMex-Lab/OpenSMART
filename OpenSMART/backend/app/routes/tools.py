from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from ..database import get_db, rows_to_dicts, write_audit_event
from ..security import get_current_user, require_admin

router = APIRouter(prefix="/api/tools", tags=["tools"])


class ToolPayload(BaseModel):
    id: int
    enabled: bool
    config: str = "{}"


@router.get("")
def list_tools(_: Annotated[dict, Depends(get_current_user)]) -> dict:
    with get_db() as db:
        rows = db.execute("SELECT id, name, description, enabled, config FROM modules ORDER BY name").fetchall()
    tools = rows_to_dicts(rows)
    for tool in tools:
        tool["enabled"] = bool(tool["enabled"])
    return {"tools": tools}


@router.put("")
def update_tools(payload: list[ToolPayload], admin: Annotated[dict, Depends(require_admin)]) -> dict:
    with get_db() as db:
        for tool in payload:
            db.execute(
                "UPDATE modules SET enabled = ?, config = ? WHERE id = ?",
                (1 if tool.enabled else 0, tool.config, tool.id),
            )
        db.commit()
    write_audit_event("tools_config_update", admin["id"], admin["username"], "tools", "", "tools configuration updated")
    return list_tools(admin)

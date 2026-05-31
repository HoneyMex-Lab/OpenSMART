from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from .. import notifications
from ..database import get_db, rows_to_dicts, write_audit_event
from ..security import get_current_user, require_admin

router = APIRouter(prefix="/api/opensmart-modules", tags=["opensmart-modules"])


class OpenSmartModulePayload(BaseModel):
    id: int
    enabled: bool
    config: str = "{}"


@router.get("")
def list_opensmart_modules(_: Annotated[dict, Depends(get_current_user)]) -> dict:
    with get_db() as db:
        rows = db.execute("SELECT id, name, description, enabled, config FROM opensmart_modules ORDER BY id").fetchall()
    modules = rows_to_dicts(rows)
    for module in modules:
        module["enabled"] = bool(module["enabled"])
    return {"modules": modules}


@router.put("")
def update_opensmart_modules(payload: list[OpenSmartModulePayload], admin: Annotated[dict, Depends(require_admin)]) -> dict:
    ids_changed = False
    with get_db() as db:
        for module in payload:
            current = db.execute("SELECT name, enabled, config FROM opensmart_modules WHERE id = ?", (module.id,)).fetchone()
            if current and current["name"] == "Network IDS" and (bool(current["enabled"]) != module.enabled or current["config"] != module.config):
                ids_changed = True
            db.execute(
                "UPDATE opensmart_modules SET enabled = ?, config = ? WHERE id = ?",
                (1 if module.enabled else 0, module.config, module.id),
            )
        db.commit()
    write_audit_event("opensmart_config_update", admin["id"], admin["username"], "opensmart_modules", "", "OpenSMART module configuration updated")
    if ids_changed:
        notifications.notify_ids_system_event("config_update", "Network IDS configuration updated")
    return list_opensmart_modules(admin)

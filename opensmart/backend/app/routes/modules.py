from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from ..database import get_db, rows_to_dicts
from ..security import get_current_user, require_admin

router = APIRouter(prefix="/api/modules", tags=["modules"])


class ModulePayload(BaseModel):
    id: int
    enabled: bool
    config: str = "{}"


@router.get("")
def list_modules(_: Annotated[dict, Depends(get_current_user)]) -> dict:
    with get_db() as db:
        rows = db.execute("SELECT id, name, description, enabled, config FROM modules ORDER BY name").fetchall()
    modules = rows_to_dicts(rows)
    for module in modules:
        module["enabled"] = bool(module["enabled"])
    return {"modules": modules}


@router.put("")
def update_modules(payload: list[ModulePayload], _: Annotated[dict, Depends(require_admin)]) -> dict:
    with get_db() as db:
        for module in payload:
            db.execute(
                "UPDATE modules SET enabled = ?, config = ? WHERE id = ?",
                (1 if module.enabled else 0, module.config, module.id),
            )
        db.commit()
    return list_modules(_)

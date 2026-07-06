import json
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from .. import provisioning
from ..database import write_audit_event
from ..security import require_admin, require_admin_read

router = APIRouter(prefix="/api/provisioning", tags=["provisioning"])


class ProvisionRequest(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    kind: str = Field(pattern="^(container|module|tool)$")


def _require_known_container(name: str) -> None:
    if name not in provisioning.KNOWN_CONTAINERS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unknown container '{name}'")


@router.post("/start")
def start(payload: ProvisionRequest, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    if payload.kind == "container":
        _require_known_container(payload.name)
        ok, detail = provisioning.start_container(payload.name)
        result = {"name": payload.name, "ok": ok, "detail": detail, "containers": [{"container": payload.name, "ok": ok, "detail": detail}]}
    else:
        result = provisioning.provision_target(payload.name, payload.kind)
    write_audit_event("provisioning_start", admin["id"], admin["username"], f"{payload.kind}:{payload.name}", "", json.dumps(result)[:500])
    return result


@router.post("/stop")
def stop(payload: ProvisionRequest, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    if payload.kind != "container":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only individual containers can be stopped directly")
    _require_known_container(payload.name)
    ok, detail = provisioning.stop_container(payload.name)
    result = {"name": payload.name, "ok": ok, "detail": detail}
    write_audit_event("provisioning_stop", admin["id"], admin["username"], f"container:{payload.name}", "", detail[:500])
    return result


@router.get("/status/{container}")
def container_status(container: str, _: Annotated[dict, Depends(require_admin_read)]) -> dict:
    _require_known_container(container)
    return provisioning.container_status(container)

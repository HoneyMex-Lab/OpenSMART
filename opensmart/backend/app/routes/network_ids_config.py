from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from .. import network_ids_config as ids
from ..database import write_audit_event
from ..security import require_admin, require_admin_read

router = APIRouter(prefix="/api/network-ids/manage", tags=["network-ids-config"])


def _bad(error: ids.IdsConfigError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))


class FileWrite(BaseModel):
    content: str = Field(max_length=4_000_000)


class SourceAction(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    params: dict[str, str] = Field(default_factory=dict)


class DetectionSettings(BaseModel):
    HOME_NET: str | None = Field(default=None, max_length=2000)
    EXTERNAL_NET: str | None = Field(default=None, max_length=2000)


@router.get("/summary")
def summary(_: Annotated[dict, Depends(require_admin_read)]) -> dict:
    return ids.rules_summary()


@router.get("/files/{kind}")
def read_file(kind: str, _: Annotated[dict, Depends(require_admin_read)]) -> dict:
    try:
        return {"kind": kind, "content": ids.read_config(kind)}
    except ids.IdsConfigError as error:
        raise _bad(error) from error


@router.put("/files/{kind}")
def write_file(kind: str, payload: FileWrite, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    try:
        ids.write_config(kind, payload.content)
    except ids.IdsConfigError as error:
        raise _bad(error) from error
    write_audit_event("ids_config_write", admin["id"], admin["username"], f"ids:{kind}", "", "config file updated")
    return {"ok": True}


@router.get("/sources")
def sources(_: Annotated[dict, Depends(require_admin_read)]) -> dict:
    return {"sources": ids.list_sources()}


@router.post("/sources/{action}")
def source_action(action: str, payload: SourceAction, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    if action not in ("enable", "disable"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unknown action '{action}'")
    try:
        if action == "enable":
            ids.enable_source(payload.name, payload.params)
        else:
            ids.disable_source(payload.name)
    except ids.IdsConfigError as error:
        raise _bad(error) from error
    write_audit_event(f"ids_source_{action}", admin["id"], admin["username"], f"ids:source:{payload.name}", "", action)
    return {"ok": True}


@router.post("/update")
def update_rules(admin: Annotated[dict, Depends(require_admin)]) -> dict:
    ok, detail = ids.update_rules()
    write_audit_event("ids_rules_update", admin["id"], admin["username"], "ids:rules", "", detail[:500])
    return {"ok": ok, "detail": detail}


@router.post("/test")
def test_config(_: Annotated[dict, Depends(require_admin_read)]) -> dict:
    ok, detail = ids.test_config()
    return {"ok": ok, "detail": detail}


@router.post("/restart")
def restart(admin: Annotated[dict, Depends(require_admin)]) -> dict:
    ok, detail = ids.restart()
    write_audit_event("ids_restart", admin["id"], admin["username"], "ids:suricata", "", detail[:500])
    return {"ok": ok, "detail": detail}


@router.get("/detection")
def detection(_: Annotated[dict, Depends(require_admin_read)]) -> dict:
    return {"settings": ids.detection_settings()}


@router.put("/detection")
def update_detection(payload: DetectionSettings, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    values = {k: v for k, v in payload.model_dump().items() if v is not None}
    try:
        ids.update_detection_settings(values)
    except ids.IdsConfigError as error:
        raise _bad(error) from error
    write_audit_event("ids_detection_update", admin["id"], admin["username"], "ids:detection", "", ", ".join(values))
    return {"ok": True}

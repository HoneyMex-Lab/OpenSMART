from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from .. import network_config as netcfg
from ..database import write_audit_event
from ..security import get_client_ip, require_admin, require_admin_read

router = APIRouter(prefix="/api/network", tags=["network-config"])


def _bad(error: netcfg.NetworkConfigError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))


class InterfaceUpdate(BaseModel):
    alias: str | None = Field(default=None, max_length=60)
    description: str | None = Field(default=None, max_length=300)
    role: str | None = Field(default=None, max_length=20)
    monitor: bool | None = None


class RemapPayload(BaseModel):
    new_name: str = Field(min_length=1, max_length=40)


class MtuPayload(BaseModel):
    mtu: int = Field(ge=0, le=65535)
    confirm_seconds: int = Field(default=60, ge=0, le=3600)


class TokenPayload(BaseModel):
    token: str = Field(min_length=1, max_length=64)


@router.get("/interfaces")
def list_interfaces(_: Annotated[dict, Depends(require_admin_read)]) -> dict:
    return {"interfaces": netcfg.list_interfaces()}


@router.post("/interfaces/rescan")
def rescan(_: Annotated[dict, Depends(require_admin_read)]) -> dict:
    return {"interfaces": netcfg.list_interfaces(force=True)}


@router.put("/interfaces/{name}")
def update_interface(name: str, payload: InterfaceUpdate, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    fields = {k: v for k, v in payload.model_dump().items() if v is not None}
    try:
        result = netcfg.update_interface(name, fields)
    except netcfg.NetworkConfigError as error:
        raise _bad(error) from error
    write_audit_event("network_interface_update", admin["id"], admin["username"], f"interface:{name}", "", ", ".join(fields))
    return result


@router.post("/interfaces/{name}/remap")
def remap_interface(name: str, payload: RemapPayload, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    try:
        netcfg.remap(name, payload.new_name)
    except netcfg.NetworkConfigError as error:
        raise _bad(error) from error
    write_audit_event("network_interface_remap", admin["id"], admin["username"], f"interface:{name}", "", f"-> {payload.new_name}")
    return {"ok": True}


@router.get("/interfaces/{name}/mtu/status")
def mtu_status(name: str, _: Annotated[dict, Depends(require_admin_read)]) -> dict:
    return {"apply": netcfg.mtu_apply_status(name)}


@router.post("/interfaces/{name}/mtu")
def set_mtu(name: str, payload: MtuPayload, request: Request, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    try:
        result = netcfg.set_mtu(
            name, payload.mtu,
            confirm_seconds=payload.confirm_seconds,
            actor=admin["username"],
            client_ip=get_client_ip(request),
        )
    except netcfg.NetworkConfigError as error:
        raise _bad(error) from error
    write_audit_event("network_interface_mtu_apply", admin["id"], admin["username"], f"interface:{name}", get_client_ip(request), f"{result['old_mtu']} -> {result['new_mtu']}")
    return result


@router.post("/interfaces/{name}/mtu/confirm")
def confirm_mtu(name: str, payload: TokenPayload, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    try:
        netcfg.confirm_mtu(payload.token)
    except netcfg.NetworkConfigError as error:
        raise _bad(error) from error
    write_audit_event("network_interface_mtu_confirm", admin["id"], admin["username"], f"interface:{name}", "", "kept")
    return {"ok": True}


@router.post("/interfaces/{name}/mtu/cancel")
def cancel_mtu(name: str, payload: TokenPayload, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    try:
        netcfg.cancel_mtu(payload.token)
    except netcfg.NetworkConfigError as error:
        raise _bad(error) from error
    write_audit_event("network_interface_mtu_cancel", admin["id"], admin["username"], f"interface:{name}", "", "reverted early")
    return {"ok": True}

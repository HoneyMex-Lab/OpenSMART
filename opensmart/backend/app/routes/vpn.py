from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from .. import vpn
from ..database import write_audit_event
from ..security import require_admin, require_admin_read

router = APIRouter(prefix="/api/vpn", tags=["vpn"])


class InstanceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=30)
    vpn_type: str = Field(pattern="^(openvpn|wireguard)$")
    port: int = Field(ge=1024, le=65535)
    auth_mode: str = Field(default="certs", pattern="^(certs|ldap)$")
    ldap_config: dict[str, str] = Field(default_factory=dict)


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=40)
    server_host: str = Field(min_length=1, max_length=253)


def _bad_request(error: vpn.VpnError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))


@router.get("/instances")
def instances(_: Annotated[dict, Depends(require_admin_read)]) -> dict:
    return {"instances": vpn.list_instances()}


@router.post("/instances")
def create_instance(payload: InstanceCreate, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    try:
        instance = vpn.create_instance(payload.name, payload.vpn_type, payload.port, payload.auth_mode, payload.ldap_config)
    except vpn.VpnError as error:
        raise _bad_request(error) from error
    write_audit_event("vpn_instance_create", admin["id"], admin["username"], f"vpn:{payload.name}", "", f"{payload.vpn_type} port {payload.port} auth {payload.auth_mode}")
    return {"instance": instance}


@router.delete("/instances/{name}")
def delete_instance(name: str, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    try:
        vpn.delete_instance(name)
    except vpn.VpnError as error:
        raise _bad_request(error) from error
    write_audit_event("vpn_instance_delete", admin["id"], admin["username"], f"vpn:{name}", "", "")
    return {"ok": True}


@router.post("/instances/{name}/{action}")
def instance_action(name: str, action: str, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    actions = {"start": vpn.start_instance, "stop": vpn.stop_instance, "restart": vpn.restart_instance}
    if action not in actions:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unknown action '{action}'")
    try:
        ok, detail = actions[action](name)
    except vpn.VpnError as error:
        raise _bad_request(error) from error
    write_audit_event(f"vpn_instance_{action}", admin["id"], admin["username"], f"vpn:{name}", "", detail[:500])
    return {"ok": ok, "detail": detail}


@router.get("/instances/{name}/users")
def users(name: str, _: Annotated[dict, Depends(require_admin_read)]) -> dict:
    try:
        return {"users": vpn.list_users(name)}
    except vpn.VpnError as error:
        raise _bad_request(error) from error


@router.post("/instances/{name}/users")
def create_user(name: str, payload: UserCreate, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    try:
        result = vpn.create_user(name, payload.username, payload.server_host)
    except vpn.VpnError as error:
        raise _bad_request(error) from error
    write_audit_event("vpn_user_create", admin["id"], admin["username"], f"vpn:{name}:{payload.username}", "", "")
    return result


@router.post("/instances/{name}/users/{username}/revoke")
def revoke_user(name: str, username: str, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    try:
        vpn.revoke_user(name, username)
    except vpn.VpnError as error:
        raise _bad_request(error) from error
    write_audit_event("vpn_user_revoke", admin["id"], admin["username"], f"vpn:{name}:{username}", "", "")
    return {"ok": True}


@router.get("/instances/{name}/users/{username}/config")
def user_config(name: str, username: str, admin: Annotated[dict, Depends(require_admin)]) -> PlainTextResponse:
    try:
        filename, content = vpn.user_config(name, username)
    except vpn.VpnError as error:
        raise _bad_request(error) from error
    write_audit_event("vpn_user_config_download", admin["id"], admin["username"], f"vpn:{name}:{username}", "", "")
    return PlainTextResponse(content, headers={"Content-Disposition": f'attachment; filename="{filename}"'})

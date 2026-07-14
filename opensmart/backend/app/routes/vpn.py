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
    subnet: str | None = Field(default=None, max_length=18)
    settings: dict[str, str] | None = None
    ca: str | None = Field(default=None, max_length=30)


class CaCreate(BaseModel):
    name: str = Field(min_length=1, max_length=30)
    cn: str | None = Field(default=None, max_length=64)
    description: str = Field(default="", max_length=200)


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=40)
    server_host: str = Field(min_length=1, max_length=253)


class InstanceUpdate(BaseModel):
    settings: dict[str, str] | None = None
    ldap_config: dict[str, str] | None = None


class UserEnabled(BaseModel):
    enabled: bool


def _bad_request(error: vpn.VpnError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))


@router.get("/cas")
def cas(_: Annotated[dict, Depends(require_admin_read)]) -> dict:
    return {"cas": vpn.list_cas()}


@router.post("/cas")
def create_ca(payload: CaCreate, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    try:
        ca = vpn.create_ca(payload.name, payload.description, payload.cn)
    except vpn.VpnError as error:
        raise _bad_request(error) from error
    write_audit_event("vpn_ca_create", admin["id"], admin["username"], f"vpn-ca:{payload.name}", "", ca.get("cn", ""))
    return {"ca": ca}


@router.delete("/cas/{name}")
def delete_ca(name: str, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    try:
        vpn.delete_ca(name)
    except vpn.VpnError as error:
        raise _bad_request(error) from error
    write_audit_event("vpn_ca_delete", admin["id"], admin["username"], f"vpn-ca:{name}", "", "")
    return {"ok": True}


@router.get("/instances")
def instances(_: Annotated[dict, Depends(require_admin_read)]) -> dict:
    return {"instances": vpn.list_instances()}


@router.post("/instances")
def create_instance(payload: InstanceCreate, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    try:
        instance = vpn.create_instance(payload.name, payload.vpn_type, payload.port, payload.auth_mode, payload.ldap_config, payload.subnet, payload.settings, payload.ca)
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


@router.put("/instances/{name}")
def update_instance(name: str, payload: InstanceUpdate, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    try:
        instance = vpn.update_instance(name, payload.settings, payload.ldap_config)
    except vpn.VpnError as error:
        raise _bad_request(error) from error
    write_audit_event("vpn_instance_update", admin["id"], admin["username"], f"vpn:{name}", "", "server settings updated")
    return {"instance": instance}


@router.get("/instances/{name}/status")
def instance_status(name: str, _: Annotated[dict, Depends(require_admin_read)]) -> dict:
    try:
        return vpn.instance_status(name)
    except vpn.VpnError as error:
        raise _bad_request(error) from error


@router.get("/instances/{name}/logs")
def instance_logs(name: str, _: Annotated[dict, Depends(require_admin_read)], tail: int = 200) -> dict:
    try:
        return {"logs": vpn.instance_logs(name, tail)}
    except vpn.VpnError as error:
        raise _bad_request(error) from error


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


@router.post("/instances/{name}/users/{username}/enabled")
def set_user_enabled(name: str, username: str, payload: UserEnabled, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    try:
        vpn.set_user_enabled(name, username, payload.enabled)
    except vpn.VpnError as error:
        raise _bad_request(error) from error
    write_audit_event("vpn_user_enabled", admin["id"], admin["username"], f"vpn:{name}:{username}", "", "enabled" if payload.enabled else "disabled")
    return {"ok": True}


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


# Registered last on purpose: this {action} path would otherwise shadow the
# more specific /instances/{name}/users (and /status, /logs) routes above,
# since Starlette matches in registration order.
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

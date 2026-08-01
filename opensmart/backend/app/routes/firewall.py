from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from .. import firewall as fw
from ..database import write_audit_event
from ..security import get_client_ip, require_admin, require_admin_read

router = APIRouter(prefix="/api/firewall", tags=["firewall"])


def _bad(error: fw.FirewallError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))


class ProfileCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=300)


class ProfileUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    description: str | None = Field(default=None, max_length=300)
    policies: str | None = Field(default=None, max_length=2000)
    custom_nft: str | None = Field(default=None, max_length=200_000)


class CloneRequest(BaseModel):
    new_name: str = Field(min_length=1, max_length=80)


class RuleCreate(BaseModel):
    chain: str
    position: int | None = None
    enabled: bool = True
    action: str = "accept"
    reject_with: str = Field(default="", max_length=40)
    family: str = "inet"
    protocol: str = Field(default="any", max_length=20)
    iif: str = Field(default="", max_length=200)
    oif: str = Field(default="", max_length=200)
    src: str = Field(default="", max_length=500)
    src_negate: bool = False
    dst: str = Field(default="", max_length=500)
    dst_negate: bool = False
    sport: str = Field(default="", max_length=200)
    dport: str = Field(default="", max_length=200)
    ct_state: str = Field(default="", max_length=100)
    icmp_type: str = Field(default="", max_length=40)
    log: bool = False
    log_prefix: str = Field(default="", max_length=60)
    rate_limit: str = Field(default="", max_length=60)
    description: str = Field(default="", max_length=300)


class RuleUpdate(BaseModel):
    enabled: bool | None = None
    action: str | None = None
    reject_with: str | None = Field(default=None, max_length=40)
    protocol: str | None = Field(default=None, max_length=20)
    iif: str | None = Field(default=None, max_length=200)
    oif: str | None = Field(default=None, max_length=200)
    src: str | None = Field(default=None, max_length=500)
    src_negate: bool | None = None
    dst: str | None = Field(default=None, max_length=500)
    dst_negate: bool | None = None
    sport: str | None = Field(default=None, max_length=200)
    dport: str | None = Field(default=None, max_length=200)
    ct_state: str | None = Field(default=None, max_length=100)
    icmp_type: str | None = Field(default=None, max_length=40)
    log: bool | None = None
    log_prefix: str | None = Field(default=None, max_length=60)
    rate_limit: str | None = Field(default=None, max_length=60)
    description: str | None = Field(default=None, max_length=300)


class MoveRequest(BaseModel):
    direction: str


class AliasCreate(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    kind: str
    values_csv: str = Field(default="", max_length=2000)
    description: str = Field(default="", max_length=300)


class AliasUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=60)
    values_csv: str | None = Field(default=None, max_length=2000)
    description: str | None = Field(default=None, max_length=300)


class ApplyRequest(BaseModel):
    confirm_seconds: int = Field(default=60, ge=0, le=3600)


class TokenPayload(BaseModel):
    token: str = Field(min_length=1, max_length=64)


def _clean(payload: BaseModel) -> dict:
    return {k: v for k, v in payload.model_dump().items() if v is not None}


@router.get("/summary")
def summary(_: Annotated[dict, Depends(require_admin_read)]) -> dict:
    profile = fw.active_profile()
    return {
        "profiles": fw.list_profiles(),
        "active_profile": profile,
        "rule_count": len(fw.list_rules(profile["id"])) if profile else 0,
        "live": fw.live_state(),
        "pending_apply": fw.apply_status(),
    }


@router.get("/profiles")
def list_profiles(_: Annotated[dict, Depends(require_admin_read)]) -> dict:
    return {"profiles": fw.list_profiles()}


@router.post("/profiles")
def create_profile(payload: ProfileCreate, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    try:
        profile = fw.create_profile(payload.name, payload.description)
    except fw.FirewallError as error:
        raise _bad(error) from error
    write_audit_event("firewall_profile_create", admin["id"], admin["username"], f"profile:{profile['id']}", "", payload.name)
    return profile


@router.put("/profiles/{profile_id}")
def update_profile(profile_id: int, payload: ProfileUpdate, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    try:
        profile = fw.update_profile(profile_id, _clean(payload))
    except fw.FirewallError as error:
        raise _bad(error) from error
    write_audit_event("firewall_profile_update", admin["id"], admin["username"], f"profile:{profile_id}", "", ", ".join(_clean(payload)))
    return profile


@router.delete("/profiles/{profile_id}")
def delete_profile(profile_id: int, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    try:
        fw.delete_profile(profile_id)
    except fw.FirewallError as error:
        raise _bad(error) from error
    write_audit_event("firewall_profile_delete", admin["id"], admin["username"], f"profile:{profile_id}", "", "")
    return {"ok": True}


@router.post("/profiles/{profile_id}/clone")
def clone_profile(profile_id: int, payload: CloneRequest, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    try:
        profile = fw.clone_profile(profile_id, payload.new_name)
    except fw.FirewallError as error:
        raise _bad(error) from error
    write_audit_event("firewall_profile_clone", admin["id"], admin["username"], f"profile:{profile_id}", "", f"-> {payload.new_name}")
    return profile


@router.get("/profiles/{profile_id}/preview")
def preview_profile(profile_id: int, _: Annotated[dict, Depends(require_admin_read)]) -> dict:
    try:
        return {"nft": fw.render_profile(profile_id)}
    except fw.FirewallError as error:
        raise _bad(error) from error


@router.post("/profiles/{profile_id}/validate")
def validate_profile(profile_id: int, request: Request, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    # require_admin (not require_admin_read): this spawns a host-networked,
    # NET_ADMIN-capable container, so it needs the same CSRF + password-reset
    # gate as any other side-effecting action, even though it doesn't itself
    # mutate firewall state.
    try:
        ok, detail = fw.validate(profile_id)
        warnings = fw.analyze(profile_id, client_ip=get_client_ip(request))
    except fw.FirewallError as error:
        raise _bad(error) from error
    write_audit_event("firewall_validate", admin["id"], admin["username"], f"profile:{profile_id}", get_client_ip(request), f"ok={ok}")
    return {"ok": ok, "detail": detail, "warnings": warnings}


@router.get("/profiles/{profile_id}/rules")
def list_rules(profile_id: int, _: Annotated[dict, Depends(require_admin_read)]) -> dict:
    try:
        return {"rules": fw.list_rules(profile_id)}
    except fw.FirewallError as error:
        raise _bad(error) from error


@router.post("/profiles/{profile_id}/rules")
def create_rule(profile_id: int, payload: RuleCreate, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    fields = payload.model_dump()
    try:
        rule = fw.create_rule(profile_id, fields)
    except fw.FirewallError as error:
        raise _bad(error) from error
    write_audit_event("firewall_rule_create", admin["id"], admin["username"], f"profile:{profile_id}:rule:{rule['id']}", "", payload.description)
    return rule


@router.put("/rules/{rule_id}")
def update_rule(rule_id: int, payload: RuleUpdate, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    try:
        rule = fw.update_rule(rule_id, _clean(payload))
    except fw.FirewallError as error:
        raise _bad(error) from error
    write_audit_event("firewall_rule_update", admin["id"], admin["username"], f"rule:{rule_id}", "", ", ".join(_clean(payload)))
    return rule


@router.delete("/rules/{rule_id}")
def delete_rule(rule_id: int, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    try:
        fw.delete_rule(rule_id)
    except fw.FirewallError as error:
        raise _bad(error) from error
    write_audit_event("firewall_rule_delete", admin["id"], admin["username"], f"rule:{rule_id}", "", "")
    return {"ok": True}


@router.post("/rules/{rule_id}/move")
def move_rule(rule_id: int, payload: MoveRequest, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    try:
        rule = fw.move_rule(rule_id, payload.direction)
    except fw.FirewallError as error:
        raise _bad(error) from error
    write_audit_event("firewall_rule_move", admin["id"], admin["username"], f"rule:{rule_id}", "", payload.direction)
    return rule


@router.get("/live")
def live(_: Annotated[dict, Depends(require_admin_read)]) -> dict:
    return fw.live_state()


class LogsRequest(BaseModel):
    lines: int = Field(default=200, ge=1, le=2000)


@router.post("/logs")
def logs(payload: LogsRequest, _: Annotated[dict, Depends(require_admin)]) -> dict:
    # require_admin (not require_admin_read), and POST (not GET): this
    # spawns a host-networked, CAP_SYSLOG container as a side effect, so a
    # bare GET (no CSRF token needed, triggerable by a forced top-level
    # navigation since the session cookie is SameSite=Lax) must not be able
    # to invoke it — same reasoning as the validate_profile endpoint above.
    return {"lines": fw.read_logs(payload.lines)}


@router.get("/applies")
def applies(_: Annotated[dict, Depends(require_admin_read)]) -> dict:
    return {"applies": fw.list_applies()}


@router.post("/profiles/{profile_id}/apply")
def apply_profile(profile_id: int, payload: ApplyRequest, request: Request, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    try:
        result = fw.apply(profile_id, confirm_seconds=payload.confirm_seconds, actor=admin["username"], client_ip=get_client_ip(request))
    except fw.FirewallError as error:
        raise _bad(error) from error
    write_audit_event("firewall_apply", admin["id"], admin["username"], f"profile:{profile_id}", get_client_ip(request), f"token={result['token']}")
    return result


@router.post("/apply/confirm")
def confirm_apply(payload: TokenPayload, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    try:
        fw.confirm_apply(payload.token)
    except fw.FirewallError as error:
        raise _bad(error) from error
    write_audit_event("firewall_apply_confirm", admin["id"], admin["username"], "firewall", "", payload.token)
    return {"ok": True}


@router.post("/apply/cancel")
def cancel_apply(payload: TokenPayload, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    try:
        fw.cancel_apply(payload.token)
    except fw.FirewallError as error:
        raise _bad(error) from error
    write_audit_event("firewall_apply_cancel", admin["id"], admin["username"], "firewall", "", payload.token)
    return {"ok": True}


@router.get("/aliases")
def list_aliases(_: Annotated[dict, Depends(require_admin_read)]) -> dict:
    return {"aliases": fw.list_aliases()}


@router.post("/aliases")
def create_alias(payload: AliasCreate, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    try:
        alias = fw.create_alias(payload.name, payload.kind, payload.values_csv, payload.description)
    except fw.FirewallError as error:
        raise _bad(error) from error
    write_audit_event("firewall_alias_create", admin["id"], admin["username"], f"alias:{alias['id']}", "", payload.name)
    return alias


@router.put("/aliases/{alias_id}")
def update_alias(alias_id: int, payload: AliasUpdate, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    fields = {k: v for k, v in payload.model_dump().items() if v is not None}
    try:
        alias = fw.update_alias(alias_id, fields)
    except fw.FirewallError as error:
        raise _bad(error) from error
    write_audit_event("firewall_alias_update", admin["id"], admin["username"], f"alias:{alias_id}", "", ", ".join(fields))
    return alias


@router.delete("/aliases/{alias_id}")
def delete_alias(alias_id: int, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    fw.delete_alias(alias_id)
    write_audit_event("firewall_alias_delete", admin["id"], admin["username"], f"alias:{alias_id}", "", "")
    return {"ok": True}

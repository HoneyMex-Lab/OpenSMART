from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from .. import firewall as fw
from .. import firewall_import as fwi
from ..database import write_audit_event
from ..security import get_client_ip, require_admin, require_admin_read

router = APIRouter(prefix="/api/firewall", tags=["firewall"])


def _bad(error: fw.FirewallError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))


def _import_bad(error: fwi.FirewallImportError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))


class ProfileCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=300)
    engine: str = Field(default="nftables", max_length=20)


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


class ImportParseRequest(BaseModel):
    engine: str = Field(max_length=20)
    text: str = Field(max_length=2_000_000)


class ImportConfirmRequest(BaseModel):
    engine: str = Field(max_length=20)
    profile_name: str = Field(min_length=1, max_length=80)
    profile_description: str = Field(default="", max_length=300)
    # Loosely typed on purpose — each row is validated field-by-field by
    # firewall.create_rule() itself (the same validation any hand-entered
    # rule goes through), so this endpoint doesn't need its own duplicate
    # schema. A row may carry a client-side-only "skip": true to omit it.
    rules: list[dict] = Field(default_factory=list)
    # Maps an interface name FOUND IN THE IMPORT to an interface name to
    # actually use ("" means "clear it — match any interface").  Applied to
    # every rule's iif/oif before creation, never partially — an import
    # that references an interface the admin didn't map is used as typed.
    interface_map: dict[str, str] = Field(default_factory=dict)


def _clean(payload: BaseModel) -> dict:
    return {k: v for k, v in payload.model_dump().items() if v is not None}


@router.get("/allowlist-status")
def allowlist_status(_: Annotated[dict, Depends(require_admin_read)]) -> dict:
    """Cheap, DB-only status for the app-wide "open to any network" warning
    banner (see AppShell.tsx) — deliberately separate from summary() so
    every page load doesn't need the full profile/rules/live-state payload
    (the last of which spawns a one-off container)."""
    return fw.allowlist_status()


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
        profile = fw.create_profile(payload.name, payload.description, engine=payload.engine)
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


@router.post("/import/parse")
def import_parse(payload: ImportParseRequest, _: Annotated[dict, Depends(require_admin)]) -> dict:
    """Parses an uploaded ruleset into a DRAFT — nothing is saved here. The
    admin reviews the result (rules/warnings/unsupported/interfaces_found)
    and, if they proceed, calls /import/confirm with the (possibly edited)
    rows and an interface mapping."""
    try:
        return fwi.parse(payload.engine, payload.text)
    except fwi.FirewallImportError as error:
        raise _import_bad(error) from error


@router.post("/import/confirm")
def import_confirm(payload: ImportConfirmRequest, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    """Creates a NEW profile from the reviewed draft — never merges into an
    existing one. Every row is validated UP FRONT, before anything is
    created — a batch import must never partially succeed (some rows
    imported, the rest silently dropped by a mid-loop failure) since
    nothing about the parser's output guarantees every row already passes
    this app's normal field-grammar rules. If validation somehow still
    fails after that (or any other unexpected error), the profile — if one
    was already created — is removed rather than left behind empty or
    partial."""
    errors = fw.validate_import_rows(payload.rules)
    if errors:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="; ".join(errors[:20]) + (f" (+{len(errors) - 20} more)" if len(errors) > 20 else ""))

    profile = None
    try:
        profile = fw.create_profile(payload.profile_name, payload.profile_description, engine=payload.engine)
        created = 0
        for row in payload.rules:
            if row.get("skip"):
                continue
            fields = {key: value for key, value in row.items() if key != "skip"}
            for side in ("iif", "oif"):
                if fields.get(side):
                    remapped = [payload.interface_map.get(part.strip(), part.strip()) for part in fields[side].split(",")]
                    fields[side] = ",".join(part for part in remapped if part)
            fw.create_rule(profile["id"], fields)
            created += 1
    except fw.FirewallError as error:
        if profile is not None:
            _cleanup_failed_import(profile["id"])
        raise _bad(error) from error
    except Exception as error:
        if profile is not None:
            _cleanup_failed_import(profile["id"])
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Import failed: {error}") from error
    write_audit_event(
        "firewall_import", admin["id"], admin["username"], f"profile:{profile['id']}", "",
        f"engine={payload.engine} rules_created={created}",
    )
    return {"profile": profile, "created": created}


def _cleanup_failed_import(profile_id: int) -> None:
    """Best-effort — a freshly created, never-applied profile has no
    pending apply, so this should always succeed; swallow a failure here
    rather than mask the real error that triggered the cleanup."""
    try:
        fw.delete_profile(profile_id)
    except fw.FirewallError:
        pass


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

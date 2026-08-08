import json
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
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


# nginx is the sole externally-reachable entry point (the app's own :8000 is
# loopback-only — see containers/run/opensmart/docker-compose.yml), so any
# request that recreates/restarts it arrives THROUGH the very container it's
# about to tear down. Doing that synchronously deadlocks: nginx's graceful
# stop waits for this in-flight request to finish, which won't finish until
# the recreate (which needs the old container fully stopped) completes —
# broken only by Docker's stop-timeout force-killing nginx after ~10s,
# resetting this connection. Confirmed live via `docker events` on a real
# first install (SIGQUIT at T, SIGKILL 10.017s later, connection reset).
# Deferring the actual compose call past the response (BackgroundTasks runs
# after the response is sent) avoids the deadlock entirely: nginx finishes
# closing this connection immediately, so the stop is fast and the recreate
# no longer blocks on itself.
_NGINX_SCHEDULED_DETAIL = "Applying — the proxy restarts in the background to pick this up."


def _deferred_nginx(action: str, admin: dict) -> None:
    ok, detail = provisioning.start_container("nginx") if action == "start" else provisioning.restart_container("nginx")
    write_audit_event(f"provisioning_{action}_result", admin["id"], admin["username"], "container:nginx", "", json.dumps({"ok": ok, "detail": detail})[:500])


@router.post("/start")
def start(payload: ProvisionRequest, background_tasks: BackgroundTasks, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    if payload.kind == "container":
        _require_known_container(payload.name)
        if payload.name == "nginx":
            background_tasks.add_task(_deferred_nginx, "start", admin)
            result = {"name": "nginx", "ok": True, "detail": _NGINX_SCHEDULED_DETAIL, "containers": [{"container": "nginx", "ok": True, "detail": "restart scheduled"}]}
        else:
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


@router.get("/overview")
def overview(_: Annotated[dict, Depends(require_admin_read)]) -> dict:
    return {"projects": provisioning.container_overview(), "vpn": provisioning.vpn_summary()}


@router.get("/host-interfaces")
def host_interfaces(_: Annotated[dict, Depends(require_admin_read)]) -> dict:
    return {"interfaces": provisioning.host_interfaces()}


@router.get("/host-resources")
def host_resources(_: Annotated[dict, Depends(require_admin_read)]) -> dict:
    return provisioning.host_resources()


@router.post("/restart")
def restart(payload: ProvisionRequest, background_tasks: BackgroundTasks, admin: Annotated[dict, Depends(require_admin)]) -> dict:
    if payload.kind != "container":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only individual containers can be restarted directly")
    _require_known_container(payload.name)
    if payload.name == "nginx":
        background_tasks.add_task(_deferred_nginx, "restart", admin)
        ok, detail = True, _NGINX_SCHEDULED_DETAIL
    else:
        ok, detail = provisioning.restart_container(payload.name)
    result = {"name": payload.name, "ok": ok, "detail": detail}
    write_audit_event("provisioning_restart", admin["id"], admin["username"], f"container:{payload.name}", "", detail[:500])
    return result

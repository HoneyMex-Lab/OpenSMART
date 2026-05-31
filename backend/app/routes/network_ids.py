from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from .. import network_ids
from ..security import get_current_user

router = APIRouter(prefix="/api/network-ids", tags=["network-ids"])


class AckAlertPayload(BaseModel):
    alert_id: int


@router.get("/config")
def get_config(_: Annotated[dict, Depends(get_current_user)]) -> dict:
    return {"config": network_ids.config_status()}


@router.get("/status")
def get_status(_: Annotated[dict, Depends(get_current_user)]) -> dict:
    """Cheap polling endpoint for ingestion progress (no summary build)."""
    config = network_ids.ids_config()
    return network_ids.read_state(config["eve_json_path"])


@router.get("/summary")
def get_summary(
    _: Annotated[dict, Depends(get_current_user)],
    timeframe: str = "1d",
    start_time: str = "",
    end_time: str = "",
    q: str = "",
    top_n: int | None = None,
    refresh: bool = False,
    query_id: str = "",
    signature: str = "",
    src_ip: str = "",
    dest_ip: str = "",
    category: str = "",
    severity: str = "",
    proto: str = "",
) -> dict:
    filters = locals().copy()
    filters.pop("_")
    filters["refresh"] = "true" if refresh else "false"
    return network_ids.summary({key: str(value) for key, value in filters.items() if value not in (None, "")})


@router.get("/alerts")
def get_alerts(
    _: Annotated[dict, Depends(get_current_user)],
    timeframe: str = "1d",
    start_time: str = "",
    end_time: str = "",
    q: str = "",
    limit: int | None = Query(None, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    sort: str = "timestamp",
    direction: str = "desc",
    timestamp: str = "",
    src_ip: str = "",
    src_port: str = "",
    dest_ip: str = "",
    dest_port: str = "",
    proto: str = "",
    severity: str = "",
    category: str = "",
    signature: str = "",
    signature_id: str = "",
    signature_source: str = "",
    confidence: str = "",
    payload_printable: str = "",
    payload: str = "",
    gid: str = "",
    action: str = "",
    metadata: str = "",
    flow_id: str = "",
    app_proto: str = "",
    in_iface: str = "",
    host: str = "",
    community_id: str = "",
    tx_id: str = "",
    packet_info_linktype: str = "",
    query_id: str = "",
) -> dict:
    filters = locals().copy()
    filters.pop("_")
    return network_ids.alerts({key: str(value) for key, value in filters.items() if value not in (None, "")})


@router.post("/alerts/cancel")
def cancel_alerts(
    _: Annotated[dict, Depends(get_current_user)],
    query_id: str,
) -> dict:
    network_ids.cancel_alert_query(query_id)
    return {"ok": True}


@router.post("/summary/cancel")
def cancel_summary(
    _: Annotated[dict, Depends(get_current_user)],
    query_id: str,
) -> dict:
    network_ids.cancel_alert_query(query_id)
    return {"ok": True}


@router.get("/details")
def get_details(
    _: Annotated[dict, Depends(get_current_user)],
    table: str = "",
    timeframe: str = "1d",
    start_time: str = "",
    end_time: str = "",
    q: str = "",
    top_n: int | None = None,
    query_id: str = "",
) -> dict:
    filters = {"table": table, "timeframe": timeframe}
    if start_time:
        filters["start_time"] = start_time
    if end_time:
        filters["end_time"] = end_time
    if q:
        filters["q"] = q
    if top_n is not None:
        filters["top_n"] = str(top_n)
    if query_id:
        filters["query_id"] = query_id
    return network_ids.details_table(filters)


@router.get("/attack-map")
def get_attack_map(
    _: Annotated[dict, Depends(get_current_user)],
    timeframe: str = "1d",
    start_time: str = "",
    end_time: str = "",
    q: str = "",
    mode: str = "src_ip",
    top_n: int | None = None,
    query_id: str = "",
) -> dict:
    filters = {"timeframe": timeframe, "start_time": start_time, "end_time": end_time, "q": q, "mode": mode, "query_id": query_id}
    if top_n is not None:
        filters["top_n"] = str(top_n)
    return network_ids.attack_map({key: str(value) for key, value in filters.items() if value not in (None, "")})


@router.post("/details/cancel")
def cancel_details(
    _: Annotated[dict, Depends(get_current_user)],
    query_id: str,
) -> dict:
    network_ids.cancel_details_query(query_id)
    return {"ok": True}


@router.post("/tracking/ack")
def ack_alert(payload: AckAlertPayload, user: Annotated[dict, Depends(get_current_user)]) -> dict:
    network_ids.acknowledge_alert(payload.alert_id, user["username"], "full")
    return {"ok": True}


@router.post("/tracking/ack-critical")
def ack_critical(
    user: Annotated[dict, Depends(get_current_user)],
    timeframe: str = "1d",
    start_time: str = "",
    end_time: str = "",
    q: str = "",
) -> dict:
    filters = {"timeframe": timeframe, "start_time": start_time, "end_time": end_time, "q": q}
    count = network_ids.acknowledge_critical({key: value for key, value in filters.items() if value}, user["username"])
    return {"ok": True, "count": count}

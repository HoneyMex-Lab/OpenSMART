from typing import Annotated

from fastapi import APIRouter, Depends

from .. import network_traffic
from ..security import get_current_user

router = APIRouter(prefix="/api/network-traffic", tags=["network-traffic"])


@router.get("/config")
def get_config(_: Annotated[dict, Depends(get_current_user)]) -> dict:
    return {"config": network_traffic.config_status()}


@router.get("/summary")
def get_summary(
    _: Annotated[dict, Depends(get_current_user)],
    timeframe: str = "1d",
    start_time: str = "",
    end_time: str = "",
    q: str = "",
    top_n: int = 10,
    refresh: bool = False,
    query_id: str = "",
) -> dict:
    filters = {"timeframe": timeframe, "start_time": start_time, "end_time": end_time, "q": q, "top_n": str(top_n), "refresh": "true" if refresh else "false", "query_id": query_id}
    return network_traffic.summary({key: value for key, value in filters.items() if value != ""})


@router.post("/summary/cancel")
def cancel_summary(
    _: Annotated[dict, Depends(get_current_user)],
    query_id: str,
) -> dict:
    network_traffic.cancel_query(query_id)
    return {"ok": True}


@router.get("/details")
def get_details(
    _: Annotated[dict, Depends(get_current_user)],
    table: str = "events",
    field: str = "",
    value: str = "",
    timeframe: str = "1d",
    start_time: str = "",
    end_time: str = "",
    q: str = "",
    limit: int = 500,
    query_id: str = "",
) -> dict:
    filters = {"table": table, "field": field, "value": value, "timeframe": timeframe, "start_time": start_time, "end_time": end_time, "q": q, "limit": str(limit), "query_id": query_id}
    return network_traffic.details({key: value for key, value in filters.items() if value != ""})


@router.post("/details/cancel")
def cancel_details(
    _: Annotated[dict, Depends(get_current_user)],
    query_id: str,
) -> dict:
    network_traffic.cancel_query(query_id)
    return {"ok": True}

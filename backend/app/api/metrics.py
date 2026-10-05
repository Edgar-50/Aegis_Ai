from fastapi import APIRouter, Response
from prometheus_client import CONTENT_TYPE_LATEST, Gauge, generate_latest
from app.services.store import EVENTS, INCIDENTS
from app.services.v06 import RESPONSE_ACTIONS

router = APIRouter(tags=["observability"])
EVENTS_G = Gauge("aegis_events_runtime", "Events in Aegis runtime")
INCIDENTS_G = Gauge("aegis_incidents_runtime", "Incidents in Aegis runtime")
PENDING_G = Gauge("aegis_soar_pending", "SOAR actions pending approval")

@router.get("/metrics", include_in_schema=False)
async def metrics():
    EVENTS_G.set(len(EVENTS)); INCIDENTS_G.set(len(INCIDENTS)); PENDING_G.set(sum(1 for a in RESPONSE_ACTIONS if a.get("status") == "pending_approval"))
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

from uuid import uuid4
from app.models.schemas import SecurityEventIn, SecurityEventOut
from app.services.detection import detect
from app.services.incidents import correlate
from app.services.store import EVENTS, STORE_LOCK
from app.services.websocket import manager
from app.services.bus import BUS
from app.services.graphdb import GRAPH
from app.core.database import persist_event, persist_incident

async def process_event(event: SecurityEventIn, origin: str = "api") -> SecurityEventOut:
    result = SecurityEventOut(id=str(uuid4()), **event.model_dump(), detection=detect(event))
    result.metadata = {**result.metadata, "ingest_origin": origin}
    with STORE_LOCK:
        incident = correlate(result)
        if incident:
            result.incident_id = incident.id
        EVENTS.appendleft(result)
    await persist_event(result)
    if incident:
        await persist_incident(incident)
    await GRAPH.persist_event(result)
    payload = result.model_dump(mode="json")
    await BUS.publish("aegis.security.events", payload)
    await manager.broadcast({"type": "event", "data": payload})
    if incident:
        inc_payload = incident.model_dump(mode="json")
        await BUS.publish("aegis.security.incidents", inc_payload)
        await manager.broadcast({"type": "incident", "data": inc_payload})
    return result

from fastapi import APIRouter
from app.models.schemas import SecurityEventIn, SecurityEventOut
from app.services.pipeline import process_event
from app.services.store import EVENTS

router = APIRouter(prefix="/events", tags=["events"])

@router.post("", response_model=SecurityEventOut)
async def ingest_event(event: SecurityEventIn) -> SecurityEventOut:
    return await process_event(event, origin="api")

@router.get("", response_model=list[SecurityEventOut])
async def list_events(limit: int = 50, severity: str | None = None, source_ip: str | None = None, country: str | None = None, event_type: str | None = None, min_score: int = 0, search: str | None = None):
    rows = list(EVENTS)
    if severity: rows = [e for e in rows if e.detection.severity == severity]
    if source_ip: rows = [e for e in rows if e.source_ip == source_ip]
    if country: rows = [e for e in rows if (e.country or "").upper() == country.upper()]
    if event_type: rows = [e for e in rows if e.event_type == event_type]
    if min_score: rows = [e for e in rows if e.detection.threat_score >= min_score]
    if search:
        q = search.lower().strip()
        rows = [e for e in rows if q in " ".join(filter(None, [e.source_ip, e.destination_ip, e.username, e.hostname, e.event_type, e.sensor, e.detection.summary])).lower()]
    return rows[: min(max(limit, 1), 500)]

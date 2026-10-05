from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from app.services.store import INCIDENTS, EVENTS
from app.services.v06 import attack_graph, attack_heatmap, entity_profiles, geo_activity
from app.services.graphdb import GRAPH

router = APIRouter(prefix="/hunting", tags=["hunting"])

class HuntQuery(BaseModel):
    source_ip: str | None = None
    username: str | None = None
    hostname: str | None = None
    event_type: str | None = None
    severity: str | None = None
    country: str | None = None
    sensor: str | None = None
    technique: str | None = None
    min_risk: int = Field(default=0, ge=0, le=100)
    hours: int = Field(default=24, ge=1, le=24*30)
    limit: int = Field(default=200, ge=1, le=1000)

@router.get("/entities")
async def entities(limit: int = 50):
    return entity_profiles()[:min(max(limit, 1), 200)]

@router.get("/attack-heatmap")
async def heatmap():
    return attack_heatmap()

@router.get("/geo-activity")
async def geo():
    return geo_activity()

@router.get("/attack-graph/{incident_id}")
async def graph(incident_id: str):
    incident = next((i for i in INCIDENTS if i.id == incident_id), None)
    if not incident:
        raise HTTPException(404, "incident not found")
    persisted = await GRAPH.incident_subgraph(incident_id)
    return persisted or attack_graph(incident)

@router.post("/query")
async def hunt(payload: HuntQuery):
    cutoff = datetime.now(timezone.utc) - timedelta(hours=payload.hours)
    rows = [e for e in EVENTS if e.timestamp >= cutoff]
    if payload.source_ip: rows = [e for e in rows if e.source_ip == payload.source_ip]
    if payload.username: rows = [e for e in rows if (e.username or "").lower() == payload.username.lower()]
    if payload.hostname: rows = [e for e in rows if (e.hostname or "").lower() == payload.hostname.lower()]
    if payload.event_type: rows = [e for e in rows if e.event_type == payload.event_type]
    if payload.severity: rows = [e for e in rows if e.detection.severity == payload.severity]
    if payload.country: rows = [e for e in rows if (e.country or "").upper() == payload.country.upper()]
    if payload.sensor: rows = [e for e in rows if e.sensor == payload.sensor]
    if payload.technique: rows = [e for e in rows if any(payload.technique.lower() in t.lower() for t in e.detection.mitre_techniques)]
    if payload.min_risk: rows = [e for e in rows if e.detection.threat_score >= payload.min_risk]
    rows = sorted(rows, key=lambda e: (e.detection.threat_score, e.timestamp), reverse=True)[:payload.limit]
    return {"query": payload.model_dump(), "matches": len(rows), "events": [e.model_dump(mode="json") for e in rows]}

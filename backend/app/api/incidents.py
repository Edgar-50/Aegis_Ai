from datetime import datetime, timezone
from hashlib import sha256
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from app.models.schemas import EvidenceItem, Incident, IncidentNote
from app.services.store import INCIDENTS
from app.core.auth import require_roles
from app.core.database import persist_incident

router = APIRouter(prefix="/incidents", tags=["incidents"])


class NoteIn(BaseModel):
    body: str = Field(min_length=1, max_length=4000)


class EvidenceIn(BaseModel):
    label: str = Field(min_length=1, max_length=200)
    kind: str = Field(min_length=1, max_length=80)
    value: str = Field(min_length=1, max_length=8000)


@router.get("", response_model=list[Incident])
async def list_incidents(limit: int = 50):
    return list(INCIDENTS)[: min(max(limit, 1), 200)]


@router.get("/{incident_id}", response_model=Incident)
async def get_incident(incident_id: str):
    for incident in INCIDENTS:
        if incident.id == incident_id:
            return incident
    raise HTTPException(404, "incident not found")


@router.patch("/{incident_id}/status", response_model=Incident)
async def set_status(incident_id: str, status: str, user: dict = Depends(require_roles("analyst", "admin"))):
    allowed = {"open", "investigating", "contained", "closed"}
    if status not in allowed:
        raise HTTPException(400, f"status must be one of {sorted(allowed)}")
    for incident in INCIDENTS:
        if incident.id == incident_id:
            incident.status = status
            incident.assignee = incident.assignee or user["sub"]
            await persist_incident(incident)
            return incident
    raise HTTPException(404, "incident not found")


@router.post("/{incident_id}/notes", response_model=Incident)
async def add_note(incident_id: str, note: NoteIn, user: dict = Depends(require_roles("analyst", "admin"))):
    for incident in INCIDENTS:
        if incident.id == incident_id:
            incident.notes.append(IncidentNote(id=str(uuid4()), author=user["sub"], body=note.body, created_at=datetime.now(timezone.utc)))
            await persist_incident(incident)
            return incident
    raise HTTPException(404, "incident not found")


@router.post("/{incident_id}/evidence", response_model=Incident)
async def add_evidence(incident_id: str, evidence: EvidenceIn, user: dict = Depends(require_roles("analyst", "admin"))):
    for incident in INCIDENTS:
        if incident.id == incident_id:
            digest = sha256(evidence.value.encode()).hexdigest()
            incident.evidence.append(EvidenceItem(id=str(uuid4()), label=evidence.label, kind=evidence.kind, value=evidence.value, sha256=digest))
            await persist_incident(incident)
            return incident
    raise HTTPException(404, "incident not found")

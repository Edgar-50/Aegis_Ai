from fastapi import APIRouter, HTTPException
from app.services.store import INCIDENTS
from app.services.v06 import incident_report

router = APIRouter(prefix="/reports", tags=["reports"])

@router.get("/incidents/{incident_id}")
async def report(incident_id: str):
    incident = next((i for i in INCIDENTS if i.id == incident_id), None)
    if not incident:
        raise HTTPException(404, "incident not found")
    return incident_report(incident)

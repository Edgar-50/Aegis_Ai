from fastapi import APIRouter
from app.services.bus import BUS
from app.services.v07 import detection_coverage, event_trend, system_snapshot

router = APIRouter(prefix="/system", tags=["system"])

@router.get("/status")
async def status():
    return system_snapshot(BUS.status())

@router.get("/trend")
async def trend(hours: int = 12):
    return event_trend(min(max(hours, 1), 48))

@router.get("/coverage")
async def coverage():
    return detection_coverage()

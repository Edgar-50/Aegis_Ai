from collections import Counter
from fastapi import APIRouter
from app.services.store import EVENTS
from app.services.bus import BUS
from app.services.sigma import SIGMA

router = APIRouter(prefix="/intelligence", tags=["intelligence"])


@router.get("/overview")
async def overview():
    events = list(EVENTS)
    reputation = Counter(e.detection.threat_intel.reputation for e in events)
    tags = Counter(t for e in events for t in e.detection.threat_intel.tags)
    sigma = Counter(h for e in events for h in e.detection.sigma_hits)
    return {
        "reputation_counts": dict(reputation),
        "top_intel_tags": tags.most_common(8),
        "top_sigma_hits": sigma.most_common(8),
        "loaded_sigma_rules": len(SIGMA.rules),
        "event_bus": BUS.status(),
    }

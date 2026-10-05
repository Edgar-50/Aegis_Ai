from collections import Counter
from fastapi import APIRouter
from app.services.store import EVENTS, INCIDENTS
from app.services.bus import BUS

router = APIRouter(prefix="/analytics", tags=["analytics"])


@router.get("/summary")
async def summary() -> dict:
    events = list(EVENTS)
    incidents = list(INCIDENTS)
    severity_counts = Counter(e.detection.severity for e in events)
    technique_counts = Counter(t for e in events for t in e.detection.mitre_techniques)
    source_counts = Counter(e.source_ip for e in events)
    phase_counts = Counter(p for e in events for p in e.detection.kill_chain_phases)
    avg_score = round(sum(e.detection.threat_score for e in events) / len(events), 2) if events else 0
    malicious = sum(1 for e in events if e.detection.threat_intel.reputation == "malicious")
    sigma_matches = sum(len(e.detection.sigma_hits) for e in events)
    return {
        "total_events": len(events),
        "open_incidents": sum(1 for i in incidents if i.status != "closed"),
        "critical_events": severity_counts.get("critical", 0),
        "high_risk_events": sum(1 for e in events if e.detection.threat_score >= 70),
        "average_threat_score": avg_score,
        "severity_counts": dict(severity_counts),
        "top_mitre_techniques": technique_counts.most_common(6),
        "top_sources": source_counts.most_common(6),
        "attack_phases": phase_counts.most_common(8),
        "malicious_indicators": malicious,
        "sigma_matches": sigma_matches,
        "stream_health": "online",
        "event_bus": BUS.status(),
    }

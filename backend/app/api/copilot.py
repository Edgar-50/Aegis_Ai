from datetime import datetime, timedelta, timezone
from fastapi import APIRouter
from app.models.schemas import CopilotQuery, CopilotResponse
from app.services.store import EVENTS, INCIDENTS

router = APIRouter(prefix="/copilot", tags=["copilot"])

COUNTRY_NAMES = {"uk": "GB", "united kingdom": "GB", "russia": "RU", "russian": "RU", "kenya": "KE", "china": "CN"}


@router.post("/query", response_model=CopilotResponse)
async def query_copilot(payload: CopilotQuery):
    q = payload.query.lower()
    events = list(EVENTS)
    incidents = list(INCIDENTS)
    filters = {}

    if "critical" in q:
        events = [e for e in events if e.detection.severity == "critical"]
        incidents = [i for i in incidents if i.severity == "critical"]
        filters["severity"] = "critical"
    elif "high" in q and "risk" in q:
        events = [e for e in events if e.detection.threat_score >= 70]
        incidents = [i for i in incidents if i.threat_score >= 70]
        filters["threat_score_gte"] = 70

    if "last 24" in q or "past 24" in q or "today" in q:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        events = [e for e in events if e.timestamp >= cutoff]
        incidents = [i for i in incidents if i.last_seen >= cutoff]
        filters["since"] = cutoff.isoformat()

    if "credential" in q or "brute force" in q:
        events = [e for e in events if any("T1110" in t or "credential" in t.lower() for t in e.detection.mitre_techniques + e.detection.kill_chain_phases)]
        incidents = [i for i in incidents if any("T1110" in t for t in i.mitre_techniques)]
        filters["attack_focus"] = "credential-access"

    if "outside the uk" in q or "outside uk" in q:
        events = [e for e in events if (e.country or "").upper() not in {"GB", "UK"}]
        filters["country_not_in"] = ["GB", "UK"]

    for phrase, code in COUNTRY_NAMES.items():
        if f"from {phrase}" in q:
            events = [e for e in events if (e.country or "").upper() == code]
            filters["country"] = code
            break

    severe = sorted(events, key=lambda e: e.detection.threat_score, reverse=True)[:3]
    if events:
        top = ", ".join(f"{e.source_ip} ({e.detection.threat_score})" for e in severe)
        answer = f"Aegis Copilot found {len(events)} matching events and {len(incidents)} matching incidents. Highest-risk sources: {top}."
    else:
        answer = "Aegis Copilot found no telemetry matching those conditions in the current analysis window."

    return CopilotResponse(
        answer=answer,
        filters=filters,
        matched_events=len(events),
        matched_incidents=len(incidents),
        recommended_followups=[
            "Open the highest-risk incident timeline",
            "Pivot on the source IP across all sensors",
            "Review mapped MITRE ATT&CK techniques and containment actions",
        ],
    )

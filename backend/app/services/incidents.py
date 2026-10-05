from datetime import timedelta
from uuid import uuid4
from app.models.schemas import Incident, SecurityEventOut, TimelineEntry
from app.services.store import INCIDENTS

CORRELATION_WINDOW = timedelta(minutes=15)


def _timeline(event: SecurityEventOut) -> TimelineEntry:
    return TimelineEntry(
        event_id=event.id,
        timestamp=event.timestamp,
        event_type=event.event_type,
        severity=event.detection.severity,
        technique=event.detection.mitre_techniques[0] if event.detection.mitre_techniques else None,
        phase=event.detection.kill_chain_phases[0] if event.detection.kill_chain_phases else None,
    )


def correlate(event: SecurityEventOut) -> Incident | None:
    if event.detection.threat_score < 45:
        return None

    for incident in INCIDENTS:
        if (
            incident.source_ip == event.source_ip
            and incident.status != "closed"
            and event.timestamp - incident.last_seen <= CORRELATION_WINDOW
        ):
            previous_score = incident.threat_score
            incident.event_ids.append(event.id)
            incident.last_seen = event.timestamp
            incident.event_count += 1
            incident.threat_score = max(previous_score, event.detection.threat_score)
            if event.detection.threat_score >= previous_score:
                incident.severity = event.detection.severity
            incident.mitre_techniques = list(dict.fromkeys(incident.mitre_techniques + event.detection.mitre_techniques))
            incident.kill_chain_phases = list(dict.fromkeys(incident.kill_chain_phases + event.detection.kill_chain_phases))
            incident.timeline.append(_timeline(event))
            incident.summary = f"Correlated {incident.event_count} suspicious events from {event.source_ip} across {len(incident.kill_chain_phases)} attack phases"
            return incident

    incident = Incident(
        id=str(uuid4()),
        title=f"{event.detection.severity.upper()} activity from {event.source_ip}",
        severity=event.detection.severity,
        threat_score=event.detection.threat_score,
        source_ip=event.source_ip,
        event_ids=[event.id],
        mitre_techniques=event.detection.mitre_techniques,
        kill_chain_phases=event.detection.kill_chain_phases,
        first_seen=event.timestamp,
        last_seen=event.timestamp,
        summary=event.detection.summary,
        timeline=[_timeline(event)],
    )
    INCIDENTS.appendleft(incident)
    return incident

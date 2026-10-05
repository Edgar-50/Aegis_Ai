from __future__ import annotations
from collections import Counter
from datetime import datetime, timedelta, timezone
from app.services.store import EVENTS, INCIDENTS


def event_trend(hours: int = 12) -> list[dict]:
    now = datetime.now(timezone.utc)
    buckets = []
    for offset in reversed(range(hours)):
        start = now - timedelta(hours=offset + 1)
        end = now - timedelta(hours=offset)
        rows = [e for e in EVENTS if start <= e.timestamp < end]
        buckets.append({
            "label": end.strftime("%H:%M"),
            "events": len(rows),
            "high_risk": sum(1 for e in rows if e.detection.threat_score >= 70),
            "critical": sum(1 for e in rows if e.detection.severity == "critical"),
        })
    return buckets


def detection_coverage() -> dict:
    rule_hits = Counter(hit for e in EVENTS for hit in e.detection.rule_hits)
    sigma_hits = Counter(hit for e in EVENTS for hit in e.detection.sigma_hits)
    sensors = Counter(e.sensor for e in EVENTS)
    types = Counter(e.event_type for e in EVENTS)
    return {
        "top_rules": rule_hits.most_common(10),
        "top_sigma": sigma_hits.most_common(10),
        "sensors": sensors.most_common(12),
        "event_types": types.most_common(12),
    }


def system_snapshot(bus_status: dict) -> dict:
    return {
        "version": "1.0.0",
        "events_in_memory": len(EVENTS),
        "incidents_in_memory": len(INCIDENTS),
        "event_bus": bus_status,
        "features": {
            "database_hydration": True,
            "sigma": True,
            "ueba": True,
            "threat_intel": True,
            "attack_graph": True,
            "approval_gated_soar": True,
            "live_websocket": True,
        },
    }

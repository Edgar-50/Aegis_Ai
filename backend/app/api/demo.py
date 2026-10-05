from datetime import datetime, timedelta, timezone
from fastapi import APIRouter
from app.api.events import ingest_event
from app.models.schemas import SecurityEventIn

router = APIRouter(prefix="/demo", tags=["demo"])

SCENARIOS = [
    dict(source_ip="185.71.67.12", destination_ip="10.0.0.25", event_type="authentication_failure", failed_attempts=18, destination_port=22, country="RU", username="finance.admin", sensor="edge-fw-01"),
    dict(source_ip="203.0.113.41", destination_ip="10.0.0.17", event_type="port_scan", destination_port=445, country="US", sensor="ids-core-02"),
    dict(source_ip="10.0.4.33", destination_ip="198.51.100.18", event_type="malware_c2", process_name="mimikatz", bytes_sent=92000000, country="GB", hostname="FIN-WS-044", username="cfo", sensor="edr-west"),
    dict(source_ip="198.51.100.77", destination_ip="10.0.0.8", event_type="authentication_failure", failed_attempts=24, destination_port=3389, country="DE", username="svc-backup", sensor="vpn-gateway"),
    dict(source_ip="192.0.2.44", destination_ip="10.0.0.44", event_type="privilege_escalation", process_name="powershell", country="NL", hostname="ENG-WS-014", username="build.agent", sensor="edr-east"),
    dict(source_ip="203.0.113.92", destination_ip="10.0.2.12", event_type="login_success", country="FR", username="j.smith", sensor="idp-cloud"),
]

@router.post("/seed")
async def seed(count: int = 18):
    created = []
    now = datetime.now(timezone.utc)
    for idx in range(min(max(count, 1), 60)):
        row = dict(SCENARIOS[idx % len(SCENARIOS)])
        row["timestamp"] = now - timedelta(minutes=(count - idx) * 4)
        created.append((await ingest_event(SecurityEventIn(**row))).id)
    return {"created": len(created), "event_ids": created}

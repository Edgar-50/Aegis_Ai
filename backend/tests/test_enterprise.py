from app.models.schemas import SecurityEventIn
from app.services.detection import detect
from app.core.auth import create_token, decode_token


def test_sigma_and_intel_raise_credential_attack():
    result = detect(SecurityEventIn(
        source_ip="185.71.67.12", destination_ip="10.0.0.25",
        event_type="authentication_failure", failed_attempts=18,
        destination_port=22, country="RU",
    ))
    assert result.threat_score >= 70
    assert result.sigma_hits
    assert result.threat_intel.reputation == "malicious"
    assert any("T1110" in t for t in result.mitre_techniques)


def test_jwt_roundtrip():
    token = create_token("analyst", "analyst")
    payload = decode_token(token)
    assert payload["sub"] == "analyst"
    assert payload["role"] == "analyst"


def test_v06_entity_profile_and_attack_graph():
    from datetime import datetime, timezone
    from app.models.schemas import SecurityEventIn, SecurityEventOut
    from app.services.detection import detect
    from app.services.incidents import correlate
    from app.services.store import EVENTS, INCIDENTS
    from app.services.v06 import entity_profiles, attack_graph
    from uuid import uuid4

    EVENTS.clear(); INCIDENTS.clear()
    raw = SecurityEventIn(source_ip="198.51.100.77", destination_ip="10.0.0.8", event_type="authentication_failure", failed_attempts=20, country="DE", timestamp=datetime.now(timezone.utc))
    event = SecurityEventOut(id=str(uuid4()), **raw.model_dump(), detection=detect(raw))
    EVENTS.appendleft(event)
    incident = correlate(event)
    assert incident is not None
    profiles = entity_profiles()
    assert profiles[0]["value"] == "198.51.100.77"
    graph = attack_graph(incident)
    assert len(graph["nodes"]) >= 2
    assert len(graph["edges"]) >= 1


def test_v10_response_fails_closed_without_provider():
    import asyncio
    from app.models.schemas import Incident
    from app.services.v06 import RESPONSE_ACTIONS, request_response, approve_response
    from app.core.config import settings
    from datetime import datetime, timezone
    RESPONSE_ACTIONS.clear()
    settings.soar_provider = "disabled"
    now = datetime.now(timezone.utc)
    incident = Incident(id="i1", title="case", severity="high", threat_score=80, source_ip="203.0.113.9", first_seen=now, last_seen=now, summary="x")
    action = request_response(incident, "contain-source", "analyst")
    assert action["status"] == "pending_approval"
    executed = asyncio.run(approve_response(action["id"], "admin"))
    assert executed["status"] == "execution_failed"
    assert executed["execution_mode"] == "provider"
    assert "disabled" in executed["result"].lower()


def test_v07_playbooks_target_identity_and_endpoint():
    from datetime import datetime, timezone
    from uuid import uuid4
    from app.models.schemas import SecurityEventIn, SecurityEventOut
    from app.services.detection import detect
    from app.services.incidents import correlate
    from app.services.store import EVENTS, INCIDENTS
    from app.services.v06 import RESPONSE_ACTIONS, request_response

    EVENTS.clear(); INCIDENTS.clear(); RESPONSE_ACTIONS.clear()
    raw = SecurityEventIn(source_ip="198.51.100.90", destination_ip="10.0.0.21", event_type="malware_c2", process_name="mimikatz", username="finance.admin", hostname="FIN-WS-021", timestamp=datetime.now(timezone.utc))
    event = SecurityEventOut(id=str(uuid4()), **raw.model_dump(), detection=detect(raw))
    EVENTS.appendleft(event)
    incident = correlate(event)
    assert incident is not None
    assert request_response(incident, "credential-lockdown", "analyst")["target"] == "finance.admin"
    assert request_response(incident, "endpoint-isolation", "analyst")["target"] == "FIN-WS-021"


def test_v07_trend_and_coverage_reflect_runtime_events():
    from datetime import datetime, timezone
    from uuid import uuid4
    from app.models.schemas import SecurityEventIn, SecurityEventOut
    from app.services.detection import detect
    from app.services.store import EVENTS
    from app.services.v07 import event_trend, detection_coverage

    EVENTS.clear()
    raw = SecurityEventIn(source_ip="185.71.67.12", event_type="authentication_failure", failed_attempts=14, sensor="vpn-gateway", timestamp=datetime.now(timezone.utc))
    EVENTS.appendleft(SecurityEventOut(id=str(uuid4()), **raw.model_dump(), detection=detect(raw)))
    trend = event_trend(2)
    coverage = detection_coverage()
    assert sum(x["events"] for x in trend) >= 1
    assert coverage["sensors"][0][0] == "vpn-gateway"


def test_v10_audit_chain_detects_integrity():
    import tempfile
    from pathlib import Path
    import app.services.audit as audit
    audit.AUDIT_LOG.clear()
    audit.AUDIT_PATH = Path(tempfile.mkdtemp()) / "audit.jsonl"
    audit.append_audit("analyst", "case_opened", "inc-1", {"risk": 80})
    audit.append_audit("admin", "case_reviewed", "inc-1")
    result = audit.verify_chain()
    assert result["valid"] is True
    assert result["records"] == 2


def test_v10_local_evidence_storage_hashes_bytes():
    import tempfile
    from app.core.config import settings
    from app.services.evidence_store import store_bytes
    settings.evidence_backend = "local"
    settings.evidence_local_dir = tempfile.mkdtemp()
    stored = store_bytes(b"forensic-artifact", "sample.bin", "inc-1")
    assert stored["bytes"] == len(b"forensic-artifact")
    assert len(stored["sha256"]) == 64

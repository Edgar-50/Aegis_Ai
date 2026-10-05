from app.models.schemas import SecurityEventIn
from app.services.detection import detect


def test_bruteforce_event_scores_high():
    result = detect(SecurityEventIn(source_ip="10.0.0.4", destination_ip="10.0.0.8", event_type="authentication_failure", failed_attempts=20, destination_port=22))
    assert result.threat_score >= 45
    assert "T1110 - Brute Force" in result.mitre_techniques


def test_clean_event_is_low_risk():
    result = detect(SecurityEventIn(source_ip="10.0.0.4", event_type="login_success"))
    assert result.threat_score < 20
    assert result.severity == "normal"


def test_malware_and_exfiltration_is_critical():
    result = detect(SecurityEventIn(source_ip="203.0.113.9", destination_ip="10.0.0.2", event_type="malware_c2", process_name="mimikatz.exe", bytes_sent=180_000_000))
    assert result.threat_score >= 90
    assert result.severity == "critical"
    assert result.recommended_actions

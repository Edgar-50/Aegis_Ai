from app.models.schemas import DetectionResult, SecurityEventIn
from app.services.anomaly import ANOMALY_DETECTOR
from app.services.sigma import SIGMA
from app.services.threat_intel import enrich

SUSPICIOUS_PORTS = {21, 22, 23, 445, 3389, 4444, 5900}
LOLBINS = {"powershell", "pwsh", "cmd.exe", "wmic", "rundll32", "regsvr32", "mshta", "certutil"}
OFFENSIVE_TOOLS = {"mimikatz", "psexec", "nc.exe", "netcat", "nmap", "rubeus", "bloodhound"}


def _severity(score: int) -> str:
    if score >= 90: return "critical"
    if score >= 70: return "high"
    if score >= 45: return "medium"
    if score >= 20: return "low"
    return "normal"


def detect(event: SecurityEventIn) -> DetectionResult:
    score = 0
    hits: list[str] = []
    mitre: list[str] = []
    phases: list[str] = []
    actions: list[str] = []
    sigma_hits: list[str] = []
    event_type = event.event_type.lower()
    action = (event.action or "").lower()
    process = (event.process_name or "").lower()

    if event.failed_attempts >= 5:
        score += min(40, 12 + event.failed_attempts * 2)
        hits.append("Repeated authentication failures")
        mitre.append("T1110 - Brute Force")
        phases.append("Credential Access")
        actions.append("Temporarily block source IP and review targeted accounts")

    if any(token in event_type for token in ("port_scan", "scan", "recon")):
        score += 45
        hits.append("Network reconnaissance behaviour")
        mitre.append("T1046 - Network Service Discovery")
        phases.append("Discovery")
        actions.append("Inspect source host and affected network segment")

    if event.destination_port in SUSPICIOUS_PORTS:
        score += 10
        hits.append(f"Sensitive destination port {event.destination_port}")

    if any(token in process for token in OFFENSIVE_TOOLS):
        score += 45
        hits.append("Known offensive security tooling observed")
        mitre += ["T1059 - Command and Scripting Interpreter", "T1003 - OS Credential Dumping"]
        phases += ["Execution", "Credential Access"]
        actions.append("Isolate endpoint and preserve volatile evidence")
    elif any(token in process for token in LOLBINS):
        score += 28
        hits.append("Living-off-the-land binary execution")
        mitre.append("T1059 - Command and Scripting Interpreter")
        phases.append("Execution")
        actions.append("Review command line, parent process and user context")

    if "privilege" in event_type or "escalation" in event_type:
        score += 40
        hits.append("Privilege escalation indicator")
        mitre.append("TA0004 - Privilege Escalation")
        phases.append("Privilege Escalation")
        actions.append("Validate newly elevated identities and revoke suspicious tokens")

    if any(token in event_type for token in ("malware", "ransomware", "c2", "command_control")):
        score += 55
        hits.append("Malware or command-and-control indicator")
        mitre.append("TA0011 - Command and Control")
        phases.append("Command and Control")
        actions.append("Isolate host and block related indicators")

    if action in {"deny", "blocked", "drop"}:
        score += 6

    if event.bytes_sent > 50_000_000:
        score += 28
        hits.append("Large outbound transfer")
        mitre.append("T1041 - Exfiltration Over C2 Channel")
        phases.append("Exfiltration")
        actions.append("Validate destination and suspend abnormal outbound transfer")

    for rule in SIGMA.match(event):
        sigma_hits.append(f"{rule['id']} · {rule['title']}")
        hits.append(f"Sigma: {rule['title']}")
        if rule.get("mitre"):
            mitre.append(rule["mitre"])
        score += {"critical": 22, "high": 15, "medium": 8, "low": 4}.get(rule.get("level", "medium"), 6)

    intel = enrich(event)
    if intel.score >= 80:
        score += 20
        hits.append("Threat-intelligence match: malicious source")
        actions.append("Block indicator at perimeter controls and hunt for related activity")
    elif intel.score >= 35:
        score += 8
        hits.append("Threat-intelligence match: suspicious source")

    anomaly = ANOMALY_DETECTOR.score(event)
    if anomaly >= 0.65:
        score += 22
        hits.append("Behavioural anomaly detected")
        actions.append("Compare entity behaviour against recent baseline")
    elif anomaly >= 0.4:
        score += 10

    score = min(score, 100)
    confidence = min(0.99, 0.42 + 0.08 * len(hits) + anomaly * 0.2 + min(intel.score, 80) / 500)
    severity = _severity(score)
    summary = "No material threat indicators detected" if not hits else "; ".join(hits[:5])

    return DetectionResult(
        threat_score=score,
        severity=severity,
        confidence=round(confidence, 2),
        rule_hits=list(dict.fromkeys(hits)),
        sigma_hits=list(dict.fromkeys(sigma_hits)),
        anomaly_score=anomaly,
        mitre_techniques=list(dict.fromkeys(mitre)),
        kill_chain_phases=list(dict.fromkeys(phases)),
        recommended_actions=list(dict.fromkeys(actions)),
        threat_intel=intel,
        summary=summary,
    )

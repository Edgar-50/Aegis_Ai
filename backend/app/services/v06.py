from __future__ import annotations
from collections import Counter, defaultdict
from datetime import datetime, timezone
from hashlib import sha256
from uuid import uuid4
from app.models.schemas import Incident, SecurityEventOut
from app.services.store import EVENTS, INCIDENTS

TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
]


def entity_profiles() -> list[dict]:
    profiles: dict[str, dict] = {}
    for event in EVENTS:
        keys = [("ip", event.source_ip)]
        if event.username:
            keys.append(("user", event.username))
        if event.hostname:
            keys.append(("host", event.hostname))
        for kind, value in keys:
            key = f"{kind}:{value}"
            p = profiles.setdefault(key, {
                "id": key,
                "kind": kind,
                "value": value,
                "risk_score": 0,
                "events": 0,
                "critical_events": 0,
                "techniques": set(),
                "last_seen": event.timestamp,
                "intel_reputation": "unknown",
            })
            p["events"] += 1
            p["risk_score"] = max(p["risk_score"], event.detection.threat_score)
            p["critical_events"] += int(event.detection.severity == "critical")
            p["techniques"].update(event.detection.mitre_techniques)
            if event.timestamp > p["last_seen"]:
                p["last_seen"] = event.timestamp
            if event.detection.threat_intel.reputation in {"malicious", "suspicious"}:
                p["intel_reputation"] = event.detection.threat_intel.reputation
    result = []
    for p in profiles.values():
        p["techniques"] = sorted(p["techniques"])
        p["risk_score"] = min(100, p["risk_score"] + min(15, p["critical_events"] * 5))
        result.append(p)
    return sorted(result, key=lambda x: (x["risk_score"], x["events"]), reverse=True)


def attack_graph(incident: Incident) -> dict:
    event_map = {e.id: e for e in EVENTS}
    ordered = [event_map[eid] for eid in incident.event_ids if eid in event_map]
    ordered.sort(key=lambda e: e.timestamp)
    nodes: list[dict] = []
    edges: list[dict] = []
    seen: set[str] = set()

    def add_node(node_id: str, label: str, kind: str, risk: int = 0, meta: dict | None = None):
        if node_id in seen:
            return
        seen.add(node_id)
        nodes.append({"id": node_id, "label": label, "kind": kind, "risk": risk, "meta": meta or {}})

    for e in ordered:
        src = f"ip:{e.source_ip}"
        add_node(src, e.source_ip, "source", e.detection.threat_score, {"country": e.country})
        target_value = e.hostname or e.destination_ip or "unknown-target"
        target = f"target:{target_value}"
        add_node(target, target_value, "target", e.detection.threat_score)
        edges.append({"source": src, "target": target, "label": e.event_type, "risk": e.detection.threat_score})
        for technique in e.detection.mitre_techniques:
            tid = technique.split(" - ")[0]
            tnode = f"technique:{tid}"
            add_node(tnode, technique, "technique", e.detection.threat_score)
            edges.append({"source": src, "target": tnode, "label": "uses", "risk": e.detection.threat_score})
            edges.append({"source": tnode, "target": target, "label": "targets", "risk": e.detection.threat_score})
    return {"incident_id": incident.id, "nodes": nodes, "edges": edges}


def attack_heatmap() -> dict:
    technique_counts = Counter()
    tactic_counts = Counter()
    severity_by_technique: dict[str, int] = defaultdict(int)
    for event in EVENTS:
        for technique in event.detection.mitre_techniques:
            technique_counts[technique] += 1
            severity_by_technique[technique] = max(severity_by_technique[technique], event.detection.threat_score)
        for tactic in event.detection.kill_chain_phases:
            tactic_counts[tactic] += 1
    return {
        "tactics": [{"name": t, "count": tactic_counts[t]} for t in TACTIC_ORDER if tactic_counts[t]],
        "techniques": [
            {"technique": t, "count": c, "max_risk": severity_by_technique[t]}
            for t, c in technique_counts.most_common(30)
        ],
    }


def geo_activity() -> list[dict]:
    counts: dict[str, dict] = {}
    for e in EVENTS:
        country = (e.country or "UN").upper()
        row = counts.setdefault(country, {"country": country, "events": 0, "high_risk": 0, "max_risk": 0})
        row["events"] += 1
        row["high_risk"] += int(e.detection.threat_score >= 70)
        row["max_risk"] = max(row["max_risk"], e.detection.threat_score)
    return sorted(counts.values(), key=lambda x: (x["high_risk"], x["events"]), reverse=True)


def incident_report(incident: Incident) -> dict:
    timeline = sorted(incident.timeline, key=lambda x: x.timestamp)
    phases = " → ".join(incident.kill_chain_phases) or "No mapped phase"
    techniques = ", ".join(incident.mitre_techniques) or "No mapped techniques"
    executive = (
        f"AegisAI correlated {incident.event_count} security events from {incident.source_ip}. "
        f"The case reached a peak risk score of {incident.threat_score}/100 and is currently {incident.status}. "
        f"Observed attack progression: {phases}."
    )
    findings = [
        f"Source entity: {incident.source_ip}",
        f"MITRE ATT&CK techniques: {techniques}",
        f"First observed: {incident.first_seen.isoformat()}",
        f"Last observed: {incident.last_seen.isoformat()}",
    ]
    actions = [
        "Validate the affected identity/endpoint and preserve volatile evidence.",
        "Block or rate-limit confirmed malicious infrastructure using an approved response action.",
        "Reset credentials and revoke active sessions if credential access is confirmed.",
        "Hunt for the same techniques and indicators across adjacent systems.",
    ]
    report_id = sha256(f"{incident.id}:{incident.last_seen.isoformat()}".encode()).hexdigest()[:16]
    return {
        "report_id": report_id,
        "generated_at": datetime.now(timezone.utc),
        "incident_id": incident.id,
        "title": f"AegisAI Incident Report — {incident.title}",
        "executive_summary": executive,
        "findings": findings,
        "timeline": [x.model_dump(mode="json") for x in timeline],
        "recommended_actions": actions,
        "integrity_sha256": sha256((executive + "|" + "|".join(findings)).encode()).hexdigest(),
    }


PLAYBOOKS = {
    "contain-source": {
        "name": "Contain malicious source",
        "description": "Block a confirmed malicious source using the configured firewall provider after admin approval.",
        "steps": ["Validate IOC confidence", "Request admin approval", "Execute provider firewall block", "Record provider result and audit evidence"],
        "action": "block_source_ip",
    },
    "credential-lockdown": {
        "name": "Credential lockdown",
        "description": "Revoke sessions for a confirmed compromised identity using the configured identity provider.",
        "steps": ["Identify targeted account", "Request admin approval", "Execute identity-provider session revocation", "Record provider result"],
        "action": "revoke_identity_sessions",
    },
    "endpoint-isolation": {
        "name": "Endpoint isolation",
        "description": "Contain an endpoint using the configured EDR provider while preserving SOC visibility.",
        "steps": ["Confirm endpoint/provider device ID", "Request admin approval", "Execute EDR containment", "Start forensic collection"],
        "action": "isolate_endpoint",
    },
}

RESPONSE_ACTIONS: list[dict] = []


def _playbook_target(incident: Incident, playbook_id: str) -> str:
    event_map = {e.id: e for e in EVENTS}
    linked = [event_map[eid] for eid in incident.event_ids if eid in event_map]
    if playbook_id == "credential-lockdown":
        return next((e.username for e in reversed(linked) if e.username), incident.source_ip)
    if playbook_id == "endpoint-isolation":
        return next((e.hostname or e.destination_ip for e in reversed(linked) if e.hostname or e.destination_ip), incident.source_ip)
    return incident.source_ip


def request_response(incident: Incident, playbook_id: str, requested_by: str) -> dict:
    if playbook_id not in PLAYBOOKS:
        raise KeyError(playbook_id)
    action = {
        "id": str(uuid4()),
        "incident_id": incident.id,
        "playbook_id": playbook_id,
        "action": PLAYBOOKS[playbook_id]["action"],
        "target": _playbook_target(incident, playbook_id),
        "status": "pending_approval",
        "requested_by": requested_by,
        "requested_at": datetime.now(timezone.utc),
        "approved_by": None,
        "approved_at": None,
        "execution_mode": "provider",
        "result": "Awaiting administrator approval",
        "provider_result": None,
    }
    RESPONSE_ACTIONS.insert(0, action)
    return action


async def approve_response(action_id: str, approved_by: str) -> dict | None:
    from app.services.integrations import execute_soar
    from app.services.audit import append_audit
    for action in RESPONSE_ACTIONS:
        if action["id"] == action_id:
            if action["status"] != "pending_approval":
                return action
            action["approved_by"] = approved_by
            action["approved_at"] = datetime.now(timezone.utc)
            action["status"] = "executing"
            append_audit(approved_by, "soar_approved", action_id, {"action": action["action"], "target": action["target"], "incident_id": action["incident_id"]})
            try:
                provider_result = await execute_soar(action["action"], action["target"], action["incident_id"])
                action["status"] = "executed"
                action["provider_result"] = provider_result
                action["result"] = f"Provider execution succeeded via {provider_result.get('provider', 'configured provider')}"
                append_audit(approved_by, "soar_executed", action_id, provider_result)
            except Exception as exc:
                action["status"] = "execution_failed"
                action["result"] = str(exc)
                append_audit(approved_by, "soar_failed", action_id, {"error": str(exc)})
            return action
    return None

def reject_response(action_id: str, rejected_by: str, reason: str) -> dict | None:
    for action in RESPONSE_ACTIONS:
        if action["id"] == action_id:
            if action["status"] != "pending_approval":
                return action
            action["status"] = "rejected"
            action["approved_by"] = rejected_by
            action["approved_at"] = datetime.now(timezone.utc)
            action["result"] = reason
            return action
    return None

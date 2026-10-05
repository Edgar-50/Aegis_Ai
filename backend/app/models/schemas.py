from datetime import datetime, timezone
from typing import Any, Literal
from pydantic import BaseModel, Field

Severity = Literal["normal", "low", "medium", "high", "critical"]
IncidentStatus = Literal["open", "investigating", "contained", "closed"]


class ThreatIntel(BaseModel):
    reputation: Literal["trusted", "unknown", "suspicious", "malicious"] = "unknown"
    score: int = Field(default=0, ge=0, le=100)
    provider: str = "Aegis Local Intel"
    reasons: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class SecurityEventIn(BaseModel):
    source_ip: str
    destination_ip: str | None = None
    event_type: str
    username: str | None = None
    hostname: str | None = None
    action: str | None = None
    bytes_sent: int = 0
    bytes_received: int = 0
    failed_attempts: int = 0
    destination_port: int | None = None
    process_name: str | None = None
    country: str | None = None
    sensor: str = "default"
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DetectionResult(BaseModel):
    threat_score: int = Field(ge=0, le=100)
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    rule_hits: list[str] = Field(default_factory=list)
    sigma_hits: list[str] = Field(default_factory=list)
    anomaly_score: float = Field(ge=0, le=1, default=0.0)
    mitre_techniques: list[str] = Field(default_factory=list)
    kill_chain_phases: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    threat_intel: ThreatIntel = Field(default_factory=ThreatIntel)
    summary: str


class SecurityEventOut(SecurityEventIn):
    id: str
    detection: DetectionResult
    incident_id: str | None = None


class TimelineEntry(BaseModel):
    event_id: str
    timestamp: datetime
    event_type: str
    severity: Severity
    technique: str | None = None
    phase: str | None = None


class IncidentNote(BaseModel):
    id: str
    author: str
    body: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EvidenceItem(BaseModel):
    id: str
    label: str
    kind: str
    value: str
    sha256: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Incident(BaseModel):
    id: str
    title: str
    status: IncidentStatus = "open"
    severity: Severity
    threat_score: int
    source_ip: str
    event_ids: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    kill_chain_phases: list[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    event_count: int = 1
    assignee: str | None = None
    summary: str
    timeline: list[TimelineEntry] = Field(default_factory=list)
    notes: list[IncidentNote] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


class CopilotQuery(BaseModel):
    query: str = Field(min_length=3, max_length=500)


class CopilotResponse(BaseModel):
    answer: str
    filters: dict[str, Any] = Field(default_factory=dict)
    matched_events: int = 0
    matched_incidents: int = 0
    recommended_followups: list[str] = Field(default_factory=list)

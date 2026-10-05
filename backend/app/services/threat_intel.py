import ipaddress
import re
from datetime import datetime, timezone
from threading import RLock
from app.models.schemas import SecurityEventIn, ThreatIntel

# Built-in seed intelligence keeps local/offline detections useful. Real MISP/TAXII
# synchronisation is merged into this registry at runtime.
KNOWN_BAD = {
    "185.71.67.12": (92, ["credential-attacks", "scanner"]),
    "198.51.100.18": (88, ["command-and-control", "exfiltration"]),
    "203.0.113.41": (76, ["reconnaissance", "scanner"]),
}
FEED_IOCS: dict[str, dict] = {}
_LOCK = RLock()


def ingest_indicators(rows: list[dict], provider: str) -> int:
    count = 0
    now = datetime.now(timezone.utc).isoformat()
    with _LOCK:
        for row in rows:
            value = str(row.get("value") or "").strip()
            kind = str(row.get("type") or "indicator")
            if not value:
                continue
            FEED_IOCS[value] = {
                "provider": provider,
                "type": kind,
                "tags": list(row.get("tags") or []),
                "comment": row.get("comment") or "",
                "updated_at": now,
                "score": int(row.get("score") or 90),
            }
            count += 1
    return count


def ingest_stix_objects(objects: list[dict], provider: str = "TAXII") -> int:
    rows = []
    for obj in objects:
        if obj.get("type") != "indicator":
            continue
        pattern = str(obj.get("pattern") or "")
        # Extract exact observable literals from common STIX 2.1 indicator patterns.
        for observable, value in re.findall(r"\[(ipv4-addr|ipv6-addr|domain-name|url):value\s*=\s*'([^']+)'\]", pattern):
            rows.append({"type": observable, "value": value, "tags": obj.get("labels", []), "comment": obj.get("name", ""), "score": 90})
    return ingest_indicators(rows, provider)


def feed_status() -> dict:
    by_provider: dict[str, int] = {}
    with _LOCK:
        for ioc in FEED_IOCS.values():
            p = ioc.get("provider", "unknown")
            by_provider[p] = by_provider.get(p, 0) + 1
        return {"indicators": len(FEED_IOCS), "providers": by_provider}


def enrich(event: SecurityEventIn) -> ThreatIntel:
    reasons: list[str] = []
    tags: list[str] = []
    score = 0
    provider = "Aegis Built-in Intel"
    try:
        ip = ipaddress.ip_address(event.source_ip)
        if ip.is_private:
            reasons.append("Private/internal source address")
            return ThreatIntel(reputation="trusted", score=5, reasons=reasons, tags=["internal"])
        if ip.is_loopback or ip.is_link_local:
            reasons.append("Non-routable source address")
            return ThreatIntel(reputation="trusted", score=0, reasons=reasons, tags=["local"])
    except ValueError:
        reasons.append("Source is not a valid IP literal")
        return ThreatIntel(reputation="suspicious", score=35, reasons=reasons, tags=["invalid-ip"])

    with _LOCK:
        feed_match = FEED_IOCS.get(event.source_ip)
    if feed_match:
        score = max(score, int(feed_match.get("score", 90)))
        tags.extend(feed_match.get("tags", []))
        provider = feed_match.get("provider", "External Threat Feed")
        reasons.append(f"Matched synchronized {provider} indicator")
    if event.source_ip in KNOWN_BAD:
        local_score, local_tags = KNOWN_BAD[event.source_ip]
        score = max(score, local_score)
        tags.extend(local_tags)
        reasons.append("Matched built-in threat-intelligence indicator")
    if event.destination_port in {22, 23, 445, 3389, 4444}:
        score = min(100, score + 8)
        reasons.append("Targeting a frequently abused service")

    reputation = "malicious" if score >= 80 else "suspicious" if score >= 35 else "unknown"
    return ThreatIntel(reputation=reputation, score=score, provider=provider, reasons=reasons, tags=list(dict.fromkeys(tags)))

from __future__ import annotations
from app.core.config import settings

class GraphStore:
    def __init__(self):
        self.driver = None
        self.last_error: str | None = None

    async def start(self):
        if not settings.neo4j_enabled:
            return
        try:
            from neo4j import AsyncGraphDatabase
            self.driver = AsyncGraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password))
            await self.driver.verify_connectivity()
            self.last_error = None
        except Exception as exc:
            self.driver = None
            self.last_error = str(exc)

    async def stop(self):
        if self.driver:
            await self.driver.close()

    async def persist_event(self, event):
        if not self.driver:
            return
        techniques = event.detection.mitre_techniques or []
        target = event.hostname or event.destination_ip or "unknown-target"
        query = """
        MERGE (s:Source {value:$source})
        SET s.country=$country, s.last_seen=$timestamp, s.risk=$risk
        MERGE (t:Target {value:$target})
        SET t.last_seen=$timestamp, t.risk=$risk
        MERGE (e:SecurityEvent {id:$event_id})
        SET e.type=$event_type, e.timestamp=$timestamp, e.risk=$risk, e.severity=$severity, e.incident_id=$incident_id
        MERGE (s)-[:EMITTED]->(e)
        MERGE (e)-[:TARGETED]->(t)
        WITH e
        UNWIND $techniques AS technique
        MERGE (m:Technique {name:technique})
        MERGE (e)-[:MAPPED_TO]->(m)
        """
        try:
            async with self.driver.session() as session:
                await session.run(query, source=event.source_ip, country=event.country, timestamp=event.timestamp.isoformat(), risk=event.detection.threat_score, target=target, event_id=event.id, event_type=event.event_type, severity=event.detection.severity, incident_id=event.incident_id, techniques=techniques)
            self.last_error = None
        except Exception as exc:
            self.last_error = str(exc)

    async def incident_subgraph(self, incident_id: str, limit: int = 250) -> dict | None:
        if not self.driver:
            return None
        query = """
        MATCH (s:Source)-[:EMITTED]->(e:SecurityEvent {incident_id:$incident_id})-[:TARGETED]->(t:Target)
        OPTIONAL MATCH (e)-[:MAPPED_TO]->(m:Technique)
        RETURN s.value AS source, e.id AS event_id, e.type AS event_type, e.risk AS risk,
               t.value AS target, collect(DISTINCT m.name) AS techniques
        ORDER BY e.risk DESC LIMIT $limit
        """
        rows=[]
        async with self.driver.session() as session:
            result=await session.run(query, incident_id=incident_id, limit=limit)
            async for r in result:
                rows.append(dict(r))
        return {"incident_id": incident_id, "rows": rows, "backend": "neo4j"}

    def status(self):
        return {"neo4j": "connected" if self.driver else ("disabled" if not settings.neo4j_enabled else "degraded"), "error": self.last_error}

GRAPH = GraphStore()

from sqlalchemy import JSON, DateTime, Integer, String, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from datetime import datetime
from app.core.config import settings


class Base(DeclarativeBase):
    pass


class EventRecord(Base):
    __tablename__ = "security_events"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source_ip: Mapped[str] = mapped_column(String(64), index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_type: Mapped[str] = mapped_column(String(128), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    threat_score: Mapped[int] = mapped_column(Integer, index=True)
    incident_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    payload: Mapped[dict] = mapped_column(JSON)


class IncidentRecord(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source_ip: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    threat_score: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(32), index=True)
    payload: Mapped[dict] = mapped_column(JSON)


class ResponseActionRecord(Base):
    __tablename__ = "response_actions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    payload: Mapped[dict] = mapped_column(JSON)


engine = create_async_engine(settings.database_url, future=True, pool_pre_ping=True)
SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def persist_event(event) -> None:
    payload = event.model_dump(mode="json")
    async with SessionLocal() as session:
        await session.merge(EventRecord(
            id=event.id,
            timestamp=event.timestamp,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            event_type=event.event_type,
            severity=event.detection.severity,
            threat_score=event.detection.threat_score,
            incident_id=event.incident_id,
            payload=payload,
        ))
        await session.commit()


async def persist_incident(incident) -> None:
    async with SessionLocal() as session:
        await session.merge(IncidentRecord(
            id=incident.id,
            first_seen=incident.first_seen,
            last_seen=incident.last_seen,
            source_ip=incident.source_ip,
            severity=incident.severity,
            threat_score=incident.threat_score,
            status=incident.status,
            payload=incident.model_dump(mode="json"),
        ))
        await session.commit()


async def persist_response_action(action: dict) -> None:
    async with SessionLocal() as session:
        await session.merge(ResponseActionRecord(
            id=action["id"],
            incident_id=action["incident_id"],
            status=action["status"],
            requested_at=action["requested_at"],
            payload={k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in action.items()},
        ))
        await session.commit()


async def hydrate_runtime_state() -> dict:
    """Restore the in-memory command-center state from durable storage after API restart."""
    from app.models.schemas import SecurityEventOut, Incident
    from app.services.store import EVENTS, INCIDENTS
    from app.services.v06 import RESPONSE_ACTIONS

    loaded = {"events": 0, "incidents": 0, "actions": 0}
    async with SessionLocal() as session:
        event_rows = (await session.execute(
            select(EventRecord).order_by(EventRecord.timestamp.desc()).limit(5000)
        )).scalars().all()
        incident_rows = (await session.execute(
            select(IncidentRecord).order_by(IncidentRecord.last_seen.desc()).limit(1000)
        )).scalars().all()
        action_rows = (await session.execute(
            select(ResponseActionRecord).order_by(ResponseActionRecord.requested_at.desc()).limit(500)
        )).scalars().all()

    EVENTS.clear()
    for row in reversed(event_rows):
        try:
            EVENTS.appendleft(SecurityEventOut.model_validate(row.payload))
            loaded["events"] += 1
        except Exception:
            continue

    INCIDENTS.clear()
    for row in reversed(incident_rows):
        try:
            INCIDENTS.appendleft(Incident.model_validate(row.payload))
            loaded["incidents"] += 1
        except Exception:
            continue

    RESPONSE_ACTIONS.clear()
    for row in action_rows:
        payload = dict(row.payload)
        for key in ("requested_at", "approved_at"):
            if payload.get(key) and isinstance(payload[key], str):
                try:
                    payload[key] = datetime.fromisoformat(payload[key])
                except ValueError:
                    pass
        RESPONSE_ACTIONS.append(payload)
        loaded["actions"] += 1
    return loaded

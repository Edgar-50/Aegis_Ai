from __future__ import annotations
import asyncio, json
from app.core.config import settings
from app.models.schemas import SecurityEventIn
from app.services.pipeline import process_event

class RawKafkaIngestor:
    def __init__(self):
        self.consumer = None
        self.task: asyncio.Task | None = None
        self.processed = 0
        self.failed = 0
        self.last_error: str | None = None

    async def start(self):
        if not settings.kafka_enabled:
            return
        try:
            from aiokafka import AIOKafkaConsumer
            self.consumer = AIOKafkaConsumer(settings.kafka_raw_topic, bootstrap_servers=settings.kafka_bootstrap_servers, group_id=settings.kafka_consumer_group, enable_auto_commit=False, auto_offset_reset="latest")
            await self.consumer.start()
            self.task = asyncio.create_task(self._run())
        except Exception as exc:
            self.consumer = None
            self.last_error = str(exc)

    async def _run(self):
        try:
            async for msg in self.consumer:
                try:
                    raw=json.loads(msg.value.decode())
                    await process_event(SecurityEventIn.model_validate(raw), origin="kafka")
                    await self.consumer.commit()
                    self.processed += 1
                    self.last_error = None
                except Exception as exc:
                    self.failed += 1
                    self.last_error = str(exc)
        except asyncio.CancelledError:
            pass

    async def stop(self):
        if self.task:
            self.task.cancel()
            try: await self.task
            except asyncio.CancelledError: pass
        if self.consumer:
            await self.consumer.stop()

    def status(self):
        return {"consumer": "connected" if self.consumer else ("disabled" if not settings.kafka_enabled else "degraded"), "topic": settings.kafka_raw_topic, "group": settings.kafka_consumer_group, "processed": self.processed, "failed": self.failed, "last_error": self.last_error}

RAW_INGEST = RawKafkaIngestor()

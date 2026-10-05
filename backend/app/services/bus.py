import json
from app.core.config import settings


class EventBus:
    def __init__(self):
        self.producer = None
        self.redis = None

    async def start(self):
        if settings.kafka_enabled:
            try:
                from aiokafka import AIOKafkaProducer
                self.producer = AIOKafkaProducer(bootstrap_servers=settings.kafka_bootstrap_servers)
                await self.producer.start()
            except Exception:
                self.producer = None
        if settings.redis_enabled:
            try:
                from redis.asyncio import from_url
                self.redis = from_url(settings.redis_url, decode_responses=True)
                await self.redis.ping()
            except Exception:
                self.redis = None

    async def stop(self):
        if self.producer:
            await self.producer.stop()
        if self.redis:
            await self.redis.aclose()

    async def publish(self, topic: str, payload: dict):
        raw = json.dumps(payload).encode()
        if self.producer:
            await self.producer.send_and_wait(topic, raw)
        if self.redis:
            await self.redis.publish(topic, raw.decode())

    def status(self) -> dict:
        return {
            "kafka": "connected" if self.producer else ("disabled" if not settings.kafka_enabled else "degraded"),
            "redis": "connected" if self.redis else ("disabled" if not settings.redis_enabled else "degraded"),
        }


BUS = EventBus()

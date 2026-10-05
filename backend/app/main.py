from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.events import router as events_router
from app.api.analytics import router as analytics_router
from app.api.incidents import router as incidents_router
from app.api.websocket import router as websocket_router
from app.api.auth import router as auth_router
from app.api.intelligence import router as intelligence_router
from app.api.copilot import router as copilot_router
from app.api.hunting import router as hunting_router
from app.api.response import router as response_router
from app.api.reports import router as reports_router
from app.api.system import router as system_router
from app.api.demo import router as demo_router
from app.api.enterprise import router as enterprise_router
from app.api.metrics import router as metrics_router
from app.core.config import settings
from app.core.database import init_db, hydrate_runtime_state
from app.services.bus import BUS
from app.services.graphdb import GRAPH
from app.services.kafka_ingest import RAW_INGEST
from app.services.telemetry import configure_telemetry


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    app.state.hydrated = await hydrate_runtime_state()
    await BUS.start()
    await GRAPH.start()
    await RAW_INGEST.start()
    yield
    await RAW_INGEST.stop()
    await GRAPH.stop()
    await BUS.stop()


app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    description="AI-assisted cyber threat intelligence, SIEM, UEBA and SOC incident correlation platform",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
for router in (events_router, analytics_router, incidents_router, websocket_router, auth_router, intelligence_router, copilot_router, hunting_router, response_router, reports_router, system_router, demo_router, enterprise_router, metrics_router):
    app.include_router(router, prefix="/api/v1")


@app.get("/health")
async def health() -> dict:
    return {
        "status": "ok",
        "service": settings.app_name,
        "version": "1.0.0",
        "engine": "rules+sigma+ueba+threat-intel+attack-graph+real-provider-soar+evidence-storage+tamper-evident-audit+persistent-runtime",
        "hydrated": getattr(app.state, "hydrated", {}),
        "event_bus": BUS.status(),
        "graph": GRAPH.status(),
        "raw_ingest": RAW_INGEST.status(),
    }


configure_telemetry(app)

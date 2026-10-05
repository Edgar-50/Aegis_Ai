from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from app.core.auth import require_roles
from app.core.config import settings
from app.services.audit import AUDIT_LOG, append_audit, verify_chain
from app.services.evidence_store import store_bytes
from app.services.integrations import fetch_misp_iocs, fetch_taxii_objects
from app.services.store import INCIDENTS
from app.services.threat_intel import ingest_indicators, ingest_stix_objects, feed_status

router = APIRouter(prefix="/enterprise", tags=["enterprise"])

@router.get("/integrations")
async def integrations(user: dict = Depends(require_roles("analyst", "admin"))):
    return {
        "misp": {"configured": bool(settings.misp_url and settings.misp_api_key), "url": settings.misp_url},
        "taxii": {"configured": bool(settings.taxii_collection_url), "collection": settings.taxii_collection_url},
        "oidc": {"configured": settings.oidc_enabled and bool(settings.oidc_issuer), "issuer": settings.oidc_issuer},
        "evidence": {"backend": settings.evidence_backend, "bucket": settings.s3_bucket if settings.evidence_backend == "s3" else None},
        "soar": {"provider": settings.soar_provider, "configured": settings.soar_provider != "disabled"},
        "threat_registry": feed_status(),
    }

@router.post("/feeds/misp/sync")
async def sync_misp(user: dict = Depends(require_roles("admin"))):
    try:
        rows = await fetch_misp_iocs()
    except Exception as exc:
        raise HTTPException(502, str(exc))
    ingested = ingest_indicators([{**x, "score": 90} for x in rows], "MISP")
    append_audit(user["sub"], "threat_feed_sync", "misp", {"objects": len(rows), "ingested": ingested})
    return {"provider": "misp", "objects": len(rows), "ingested": ingested, "registry": feed_status(), "sample": rows[:25]}

@router.post("/feeds/taxii/sync")
async def sync_taxii(user: dict = Depends(require_roles("admin"))):
    try:
        rows = await fetch_taxii_objects()
    except Exception as exc:
        raise HTTPException(502, str(exc))
    ingested = ingest_stix_objects(rows, "TAXII")
    append_audit(user["sub"], "threat_feed_sync", "taxii", {"objects": len(rows), "ingested": ingested})
    return {"provider": "taxii", "objects": len(rows), "ingested": ingested, "registry": feed_status(), "sample": rows[:25]}

@router.post("/incidents/{incident_id}/evidence-file")
async def upload_evidence(incident_id: str, file: UploadFile = File(...), user: dict = Depends(require_roles("analyst", "admin"))):
    incident = next((i for i in INCIDENTS if i.id == incident_id), None)
    if not incident:
        raise HTTPException(404, "incident not found")
    data = await file.read()
    if len(data) > 50 * 1024 * 1024:
        raise HTTPException(413, "evidence file exceeds 50 MiB limit")
    stored = store_bytes(data, file.filename or "evidence.bin", incident_id)
    append_audit(user["sub"], "evidence_upload", incident_id, {"filename": file.filename, **stored})
    return stored

@router.get("/audit")
async def audit(limit: int = 200, user: dict = Depends(require_roles("admin"))):
    return {"verification": verify_chain(), "records": AUDIT_LOG[-max(1, min(limit, 1000)):]}

@router.get("/audit/verify")
async def audit_verify(user: dict = Depends(require_roles("analyst", "admin"))):
    return verify_chain()

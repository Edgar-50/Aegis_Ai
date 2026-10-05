from __future__ import annotations
from hashlib import sha256
from pathlib import Path
from uuid import uuid4
from app.core.config import settings


def _safe_name(name: str) -> str:
    return "".join(c for c in name if c.isalnum() or c in "._-")[:160] or "evidence.bin"


def store_bytes(data: bytes, filename: str, incident_id: str) -> dict:
    digest = sha256(data).hexdigest()
    object_key = f"{incident_id}/{digest[:12]}-{uuid4().hex[:8]}-{_safe_name(filename)}"
    if settings.evidence_backend == "s3":
        import boto3
        client = boto3.client(
            "s3",
            endpoint_url=settings.s3_endpoint_url or None,
            aws_access_key_id=settings.s3_access_key or None,
            aws_secret_access_key=settings.s3_secret_key or None,
            region_name=settings.s3_region,
        )
        try:
            client.head_bucket(Bucket=settings.s3_bucket)
        except Exception:
            client.create_bucket(Bucket=settings.s3_bucket)
        client.put_object(Bucket=settings.s3_bucket, Key=object_key, Body=data)
        uri = f"s3://{settings.s3_bucket}/{object_key}"
    else:
        root = Path(settings.evidence_local_dir)
        path = root / object_key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        uri = str(path)
    return {"object_key": object_key, "uri": uri, "sha256": digest, "bytes": len(data)}

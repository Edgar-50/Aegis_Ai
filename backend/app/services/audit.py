from __future__ import annotations
from datetime import datetime, timezone
from hashlib import sha256
import json, os
from pathlib import Path
from threading import RLock

AUDIT_PATH = Path(os.getenv("AUDIT_LOG_PATH", "/tmp/aegis-audit/audit.jsonl"))
AUDIT_LOG: list[dict] = []
_LOCK = RLock()


def _load() -> None:
    if AUDIT_LOG or not AUDIT_PATH.exists():
        return
    for line in AUDIT_PATH.read_text(encoding="utf-8").splitlines():
        try:
            AUDIT_LOG.append(json.loads(line))
        except Exception:
            continue


def append_audit(actor: str, action: str, resource: str, details: dict | None = None) -> dict:
    with _LOCK:
        _load()
        prev_hash = AUDIT_LOG[-1]["hash"] if AUDIT_LOG else "GENESIS"
        record = {
            "sequence": len(AUDIT_LOG) + 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "action": action,
            "resource": resource,
            "details": details or {},
            "prev_hash": prev_hash,
        }
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
        record["hash"] = sha256(canonical.encode()).hexdigest()
        AUDIT_LOG.append(record)
        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, separators=(",", ":"), default=str) + "\n")
            f.flush()
            os.fsync(f.fileno())
        return record


def verify_chain() -> dict:
    with _LOCK:
        _load()
        prev = "GENESIS"
        for i, record in enumerate(AUDIT_LOG, start=1):
            copy = {k: v for k, v in record.items() if k != "hash"}
            if copy["prev_hash"] != prev:
                return {"valid": False, "failed_sequence": i, "reason": "previous hash mismatch"}
            digest = sha256(json.dumps(copy, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
            if digest != record["hash"]:
                return {"valid": False, "failed_sequence": i, "reason": "record hash mismatch"}
            prev = record["hash"]
        return {"valid": True, "records": len(AUDIT_LOG), "head": prev}

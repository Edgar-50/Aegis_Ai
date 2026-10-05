from __future__ import annotations
import base64
import httpx
from app.core.config import settings

TIMEOUT = 20.0


async def fetch_misp_iocs(limit: int = 500) -> list[dict]:
    if not settings.misp_url or not settings.misp_api_key:
        raise RuntimeError("MISP_URL and MISP_API_KEY are not configured")
    headers = {"Authorization": settings.misp_api_key, "Accept": "application/json", "Content-Type": "application/json"}
    payload = {"returnFormat": "json", "limit": limit, "published": True, "to_ids": True}
    async with httpx.AsyncClient(verify=settings.misp_verify_tls, timeout=TIMEOUT) as client:
        r = await client.post(f"{settings.misp_url.rstrip('/')}/attributes/restSearch", headers=headers, json=payload)
        r.raise_for_status()
        data = r.json()
    attrs = data.get("response", {}).get("Attribute", data.get("Attribute", []))
    return [{"type": a.get("type"), "value": a.get("value"), "category": a.get("category"), "comment": a.get("comment", "")} for a in attrs]


async def fetch_taxii_objects(limit: int = 500) -> list[dict]:
    if not settings.taxii_collection_url:
        raise RuntimeError("TAXII_COLLECTION_URL is not configured")
    headers = {"Accept": "application/taxii+json;version=2.1"}
    auth = None
    if settings.taxii_username:
        auth = (settings.taxii_username, settings.taxii_password)
    url = settings.taxii_collection_url.rstrip("/") + f"/objects/?limit={limit}"
    async with httpx.AsyncClient(timeout=TIMEOUT, auth=auth) as client:
        r = await client.get(url, headers=headers)
        r.raise_for_status()
        data = r.json()
    return data.get("objects", [])


async def cloudflare_block_ip(ip: str, note: str) -> dict:
    if not settings.cloudflare_api_token or not settings.cloudflare_account_id:
        raise RuntimeError("Cloudflare provider is not fully configured")
    headers = {"Authorization": f"Bearer {settings.cloudflare_api_token}", "Content-Type": "application/json"}
    url = f"https://api.cloudflare.com/client/v4/accounts/{settings.cloudflare_account_id}/firewall/access_rules/rules"
    payload = {"mode": "block", "configuration": {"target": "ip", "value": ip}, "notes": note}
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        r = await client.post(url, headers=headers, json=payload)
        r.raise_for_status()
        return r.json()


async def crowdstrike_isolate_host(device_id: str) -> dict:
    if not settings.crowdstrike_client_id or not settings.crowdstrike_client_secret:
        raise RuntimeError("CrowdStrike provider is not fully configured")
    base = settings.crowdstrike_base_url.rstrip("/")
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        token = await client.post(f"{base}/oauth2/token", data={"client_id": settings.crowdstrike_client_id, "client_secret": settings.crowdstrike_client_secret})
        token.raise_for_status()
        bearer = token.json()["access_token"]
        r = await client.post(f"{base}/devices/entities/devices-actions/v2", params={"action_name": "contain"}, headers={"Authorization": f"Bearer {bearer}"}, json={"ids": [device_id]})
        r.raise_for_status()
        return r.json()


async def msgraph_revoke_sessions(user_id: str) -> dict:
    if not settings.msgraph_access_token:
        raise RuntimeError("MSGRAPH_ACCESS_TOKEN is not configured")
    url = f"https://graph.microsoft.com/v1.0/users/{user_id}/revokeSignInSessions"
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        r = await client.post(url, headers={"Authorization": f"Bearer {settings.msgraph_access_token}"})
        r.raise_for_status()
        return r.json() if r.content else {"value": True}


async def execute_soar(action: str, target: str, incident_id: str) -> dict:
    provider = settings.soar_provider.lower()
    if provider == "disabled":
        raise RuntimeError("SOAR_PROVIDER is disabled; configure a supported defensive provider")
    if action == "block_source_ip":
        if provider != "cloudflare":
            raise RuntimeError("block_source_ip currently requires SOAR_PROVIDER=cloudflare")
        raw = await cloudflare_block_ip(target, f"AegisAI incident {incident_id}")
        return {"provider": "cloudflare", "remote_id": raw.get("result", {}).get("id"), "raw_success": raw.get("success", True)}
    if action == "isolate_endpoint":
        if provider != "crowdstrike":
            raise RuntimeError("isolate_endpoint currently requires SOAR_PROVIDER=crowdstrike")
        raw = await crowdstrike_isolate_host(target)
        return {"provider": "crowdstrike", "resources": raw.get("resources", [])}
    if action == "revoke_identity_sessions":
        if provider != "msgraph":
            raise RuntimeError("revoke_identity_sessions currently requires SOAR_PROVIDER=msgraph")
        raw = await msgraph_revoke_sessions(target)
        return {"provider": "msgraph", "result": raw}
    raise RuntimeError(f"Unsupported SOAR action: {action}")

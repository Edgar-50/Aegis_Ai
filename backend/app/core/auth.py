import base64
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from fastapi import Depends, Header, HTTPException
from app.core.config import settings


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def create_token(username: str, role: str) -> str:
    now = int(time.time())
    payload = {"sub": username, "role": role, "iat": now, "exp": now + settings.access_token_minutes * 60}
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64(json.dumps(header, separators=(",", ":")).encode())
    p = _b64(json.dumps(payload, separators=(",", ":")).encode())
    signature = hmac.new(settings.jwt_secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64(signature)}"


def decode_token(token: str) -> dict:
    try:
        h, p, sig = token.split(".")
        expected = hmac.new(settings.jwt_secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _unb64(sig)):
            raise ValueError("signature")
        payload = json.loads(_unb64(p))
        if int(payload.get("exp", 0)) < int(time.time()):
            raise ValueError("expired")
        return payload
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired access token") from exc


def authenticate(username: str, password: str) -> dict | None:
    users = {
        settings.admin_username: (settings.admin_password, "admin"),
        settings.analyst_username: (settings.analyst_password, "analyst"),
    }
    record = users.get(username)
    if not record or not hmac.compare_digest(record[0], password):
        return None
    return {"username": username, "role": record[1]}


async def current_user(authorization: str | None = Header(default=None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    return decode_token(authorization.split(" ", 1)[1])


def require_roles(*roles: str):
    async def dependency(user: dict = Depends(current_user)) -> dict:
        if user.get("role") not in roles:
            raise HTTPException(status_code=403, detail=f"Requires one of roles: {', '.join(roles)}")
        return user
    return dependency


def verify_oidc_token(token: str) -> dict:
    if not settings.oidc_enabled or not settings.oidc_jwks_url or not settings.oidc_client_id:
        raise HTTPException(status_code=503, detail="OIDC is not configured")
    try:
        import jwt
        jwks = jwt.PyJWKClient(settings.oidc_jwks_url)
        signing_key = jwks.get_signing_key_from_jwt(token)
        payload = jwt.decode(token, signing_key.key, algorithms=["RS256", "ES256"], audience=settings.oidc_client_id, issuer=settings.oidc_issuer or None)
        groups = payload.get("groups", []) or payload.get("roles", []) or []
        role = "admin" if any(str(g).lower() in {"admin", "aegis-admin", "security-admin"} for g in groups) else "analyst"
        return {"sub": payload.get("preferred_username") or payload.get("email") or payload.get("sub"), "role": role, "oidc": True}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid OIDC token") from exc

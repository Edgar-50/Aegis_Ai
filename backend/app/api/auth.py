import asyncio
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.core.auth import authenticate, create_token, verify_oidc_token
from app.models.schemas import LoginRequest, TokenResponse
from app.services.audit import append_audit

router = APIRouter(prefix="/auth", tags=["auth"])

class OIDCExchange(BaseModel):
    id_token: str

@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest):
    user = authenticate(payload.username, payload.password)
    if not user:
        append_audit(payload.username, "login_failed", "local-auth")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    append_audit(user["username"], "login_success", "local-auth", {"role": user["role"]})
    return TokenResponse(access_token=create_token(user["username"], user["role"]), role=user["role"])

@router.post("/oidc/exchange", response_model=TokenResponse)
async def oidc_exchange(payload: OIDCExchange):
    user = await asyncio.to_thread(verify_oidc_token, payload.id_token)
    append_audit(user["sub"], "login_success", "oidc", {"role": user["role"]})
    return TokenResponse(access_token=create_token(user["sub"], user["role"]), role=user["role"])

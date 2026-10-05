from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from app.core.auth import require_roles
from app.core.database import persist_response_action
from app.services.audit import append_audit
from app.services.store import INCIDENTS
from app.services.v06 import PLAYBOOKS, RESPONSE_ACTIONS, approve_response, reject_response, request_response

router = APIRouter(prefix="/response", tags=["response"])

class ResponseRequest(BaseModel):
    incident_id: str
    playbook_id: str

class RejectRequest(BaseModel):
    reason: str = "Rejected by administrator"

@router.get("/playbooks")
async def playbooks():
    return [{"id": key, **value} for key, value in PLAYBOOKS.items()]

@router.get("/actions")
async def actions():
    return RESPONSE_ACTIONS[:100]

@router.post("/actions")
async def request_action(payload: ResponseRequest, user: dict = Depends(require_roles("analyst", "admin"))):
    incident = next((i for i in INCIDENTS if i.id == payload.incident_id), None)
    if not incident:
        raise HTTPException(404, "incident not found")
    try:
        action = request_response(incident, payload.playbook_id, user["sub"])
        append_audit(user["sub"], "soar_requested", action["id"], {"incident_id": incident.id, "playbook_id": payload.playbook_id, "target": action["target"]})
        await persist_response_action(action)
        return action
    except KeyError:
        raise HTTPException(400, "unknown playbook")

@router.post("/actions/{action_id}/approve")
async def approve(action_id: str, user: dict = Depends(require_roles("admin"))):
    action = await approve_response(action_id, user["sub"])
    if not action:
        raise HTTPException(404, "response action not found")
    await persist_response_action(action)
    return action

@router.post("/actions/{action_id}/reject")
async def reject(action_id: str, payload: RejectRequest, user: dict = Depends(require_roles("admin"))):
    action = reject_response(action_id, user["sub"], payload.reason)
    if not action:
        raise HTTPException(404, "response action not found")
    append_audit(user["sub"], "soar_rejected", action_id, {"reason": payload.reason})
    await persist_response_action(action)
    return action

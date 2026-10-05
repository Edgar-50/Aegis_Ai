from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.services.websocket import manager

router = APIRouter(tags=["stream"])


@router.websocket("/ws/events")
async def events_socket(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        await websocket.send_json({"type": "system", "data": {"message": "AegisAI live stream connected"}})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

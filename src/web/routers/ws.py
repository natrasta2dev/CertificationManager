"""WebSocket et SSE pour alertes temps réel."""

import asyncio
import json
from typing import Set

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse

from ...core.users import User
from ..auth_deps import RequireViewer
from ..dependencies import get_managers

router = APIRouter()

_connections: Set[WebSocket] = set()


async def _alert_payload() -> dict:
    managers = get_managers()
    alerts = managers.alert_manager.check_certificates(include_expired=True)
    return {
        "type": "alerts",
        "count": len(alerts),
        "data": [a.to_dict() for a in alerts],
    }


@router.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """Flux WebSocket des alertes (rafraîchissement toutes les 30 s)."""
    await websocket.accept()
    _connections.add(websocket)
    try:
        while True:
            payload = await _alert_payload()
            await websocket.send_json(payload)
            await asyncio.sleep(30)
    except WebSocketDisconnect:
        pass
    finally:
        _connections.discard(websocket)


@router.get("/events/alerts")
async def sse_alerts_stream(_: User = Depends(RequireViewer)):
    """Server-Sent Events pour les alertes (évite conflit avec /alerts/{cert_id})."""

    async def event_generator():
        while True:
            payload = await _alert_payload()
            yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
            await asyncio.sleep(30)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )

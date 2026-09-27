"""WebSocket endpoint for realtime analysis status, progression, and event streaming."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from app.db.models.capture import AnalysisRun
from app.db.session import get_session_factory

logger = logging.getLogger(__name__)

router = APIRouter(tags=["WebSocket"])


class AnalysisConnectionManager:
    """Tracks active WebSockets grouped by analysis ID and coordinates broadcasts."""

    def __init__(self) -> None:
        self.active_connections: dict[uuid.UUID, set[WebSocket]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, analysis_id: uuid.UUID, websocket: WebSocket) -> None:
        """Register a new active WebSocket connection."""
        await websocket.accept()
        async with self._lock:
            if analysis_id not in self.active_connections:
                self.active_connections[analysis_id] = set()
            self.active_connections[analysis_id].add(websocket)
        logger.debug(f"Client connected to WebSocket for analysis '{analysis_id}'")

    async def disconnect(self, analysis_id: uuid.UUID, websocket: WebSocket) -> None:
        """Deregister an active WebSocket connection."""
        async with self._lock:
            if analysis_id in self.active_connections:
                self.active_connections[analysis_id].discard(websocket)
                if not self.active_connections[analysis_id]:
                    del self.active_connections[analysis_id]
        logger.debug(f"Client disconnected from WebSocket for analysis '{analysis_id}'")

    async def broadcast_to_analysis(
        self, analysis_id: uuid.UUID, event_type: str, payload: dict[str, Any]
    ) -> None:
        """Broadcast typed JSON message to all subscribers of a specific analysis run."""
        message = json.dumps(
            {
                "type": event_type,
                "analysis_id": str(analysis_id),
                "payload": payload,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
        async with self._lock:
            sockets = list(self.active_connections.get(analysis_id, set()))

        for ws in sockets:
            try:
                await ws.send_text(message)
            except Exception as exc:
                logger.debug(f"Failed to push WebSocket message to subscriber: {exc}")


ws_manager = AnalysisConnectionManager()


@router.websocket("/ws")
async def general_websocket_endpoint(websocket: WebSocket) -> None:
    """General status and heartbeat WebSocket endpoint."""
    await websocket.accept()
    try:
        await websocket.send_text(
            json.dumps(
                {
                    "type": "CONNECTED",
                    "service": "TunnelTrace AI Realtime Stream",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
        )
        while True:
            data = await websocket.receive_text()
            if data.strip().upper() == "PING" or '"PING"' in data:
                await websocket.send_text(
                    json.dumps(
                        {
                            "type": "PONG",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }
                    )
                )
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.debug(f"General WebSocket closed: {exc}")


@router.websocket("/ws/analyses/{analysis_id}")
async def analysis_websocket_endpoint(websocket: WebSocket, analysis_id: uuid.UUID) -> None:
    """Stream realtime stage transitions, counter updates, and completion notifications."""
    await ws_manager.connect(analysis_id, websocket)

    # 1. Emit Initial State Snapshot on Connect
    try:
        session_factory = get_session_factory()
        async with session_factory() as db:
            res = await db.execute(select(AnalysisRun).where(AnalysisRun.id == analysis_id))
            run = res.scalar_one_or_none()
            if run:
                initial_msg = json.dumps(
                    {
                        "type": "ANALYSIS_STATE",
                        "analysis_id": str(analysis_id),
                        "payload": {
                            "status": run.status,
                            "current_stage": run.current_stage,
                            "started_at": run.started_at.isoformat() if run.started_at else None,
                            "completed_at": run.completed_at.isoformat() if run.completed_at else None,
                            "error_code": run.error_code,
                            "error_message": run.error_message,
                        },
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
                await websocket.send_text(initial_msg)
    except Exception as exc:
        logger.warning(f"Error sending initial WebSocket state: {exc}")

    # 2. Maintain connection and handle client ping/heartbeats
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "PING":
                    await websocket.send_text(
                        json.dumps(
                            {
                                "type": "PONG",
                                "analysis_id": str(analysis_id),
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            }
                        )
                    )
            except Exception:
                # Simple ping text fallback
                if data.strip().upper() == "PING":
                    await websocket.send_text("PONG")
    except WebSocketDisconnect:
        await ws_manager.disconnect(analysis_id, websocket)
    except Exception as exc:
        logger.debug(f"WebSocket connection closed with error: {exc}")
        await ws_manager.disconnect(analysis_id, websocket)

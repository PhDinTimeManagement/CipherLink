from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any

from fastapi import WebSocket


class WebSocketManager:
    def __init__(self) -> None:
        self._connections: dict[int, set[WebSocket]] = defaultdict(set)
        self._lock = asyncio.Lock()

    async def connect(self, user_id: int, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections[user_id].add(websocket)

    async def disconnect(self, user_id: int, websocket: WebSocket) -> None:
        async with self._lock:
            connections = self._connections.get(user_id)
            if not connections:
                return
            connections.discard(websocket)
            if not connections:
                self._connections.pop(user_id, None)

    async def send_to_user(self, user_id: int, event_type: str, payload: dict[str, Any]) -> bool:
        async with self._lock:
            targets = list(self._connections.get(user_id, set()))
        if not targets:
            return False
        stale: list[WebSocket] = []
        for websocket in targets:
            try:
                await websocket.send_json({"type": event_type, "payload": payload})
            except Exception:
                stale.append(websocket)
        if stale:
            async with self._lock:
                existing = self._connections.get(user_id, set())
                for websocket in stale:
                    existing.discard(websocket)
                if not existing:
                    self._connections.pop(user_id, None)
        return True

    async def close_user_connections(self, user_id: int, code: int = 4001, reason: str = "Session closed") -> None:
        async with self._lock:
            targets = list(self._connections.get(user_id, set()))
            self._connections.pop(user_id, None)
        for websocket in targets:
            try:
                await websocket.close(code=code, reason=reason)
            except Exception:
                continue

    async def is_online(self, user_id: int) -> bool:
        async with self._lock:
            return bool(self._connections.get(user_id))

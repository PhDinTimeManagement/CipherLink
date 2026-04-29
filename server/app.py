from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager, suppress
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from server.config import Settings
from server.db import Database
from server.dependencies import Services
from server.otp_utils import OTPManager
from server.rate_limit import SlidingWindowRateLimiter
from server.repositories import Repository
from server.routes import auth, contacts, keys, messages
from server.security import SecurityManager
from server.ws_manager import WebSocketManager

logger = logging.getLogger("cipherlink_server")


async def _periodic_purge(app: FastAPI) -> None:
    services: Services = app.state.services
    while True:
        try:
            purged = services.repo.purge_expired_and_old_messages(
                services.settings.pending_retention_hours,
                services.settings.consumed_retention_hours,
            )
            if purged:
                logger.info("Purged %s expired/retained ciphertext rows.", purged)
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.exception("Ciphertext purge task failed: %s", exc)
        await asyncio.sleep(30)



def build_services(settings: Settings | None = None) -> Services:
    settings = settings or Settings.from_env()
    settings.ensure_directories()
    db = Database(settings.db_path, settings.schema_path)
    db.initialize()
    services = Services(
        settings=settings,
        db=db,
        repo=Repository(db),
        security=SecurityManager(settings.master_key_path, settings.session_lifetime_hours),
        otp=OTPManager(settings.app_name),
        rate_limiter=SlidingWindowRateLimiter(),
        ws_manager=WebSocketManager(),
    )
    return services



def create_app(settings: Settings | None = None) -> FastAPI:
    services = build_services(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.services = services
        app.state.purge_task = asyncio.create_task(_periodic_purge(app))
        try:
            yield
        finally:
            task = app.state.purge_task
            if task is not None:
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task

    app = FastAPI(title="CipherLink Server", version="1.0.0", lifespan=lifespan)

    # Restrictive by default. This CLI deployment does not require browser origins, so CORS stays locked down.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[],
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )

    app.include_router(auth.router)
    app.include_router(keys.router)
    app.include_router(contacts.router)
    app.include_router(messages.router)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.websocket("/api/v1/ws")
    async def websocket_endpoint(websocket: WebSocket) -> None:
        token = websocket.query_params.get("token")
        if not token:
            await websocket.close(code=4401, reason="Missing token")
            return
        token_hash = services.security.hash_token(token)
        user = services.repo.get_user_for_token(token_hash)
        if user is None:
            await websocket.close(code=4401, reason="Invalid or expired session")
            return
        await services.ws_manager.connect(user.id, websocket)
        await services.ws_manager.send_to_user(
            user.id,
            "connected",
            {"username": user.username, "pending_messages": services.repo.pending_message_count(user.id)},
        )
        try:
            while True:
                data: Any = await websocket.receive_json()
                if isinstance(data, dict) and data.get("type") == "ping":
                    current = services.repo.get_user_for_token(token_hash)
                    if current is None:
                        await websocket.close(code=4401, reason="Session expired")
                        break
                    await websocket.send_json({"type": "pong", "payload": {}})
        except WebSocketDisconnect:
            await services.ws_manager.disconnect(user.id, websocket)
        except Exception:
            await services.ws_manager.disconnect(user.id, websocket)
            with suppress(Exception):
                await websocket.close(code=1011, reason="WebSocket error")

    return app

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.api.dependencies import (
    get_api_container,
)
from app.auth.authentication import (
    AuthenticationError,
)
from app.auth.authorization import (
    PermissionDenied,
)
from .manager import ConnectionManager


router = APIRouter(
    tags=["websocket"],
)


def get_connection_manager(
    websocket: WebSocket,
) -> ConnectionManager:
    manager = getattr(
        websocket.app.state,
        "websocket_manager",
        None,
    )

    if not isinstance(
        manager,
        ConnectionManager,
    ):
        raise RuntimeError(
            "WebSocket manager is not configured",
        )

    return manager


def get_api_container_from_websocket(
    websocket: WebSocket,
):
    return get_api_container(
        websocket,  # type: ignore[arg-type]
    )


def extract_authentication_token(
    message: dict[str, Any],
) -> str | None:
    action = message.get("action")

    if action != "authenticate":
        return None

    token = message.get("token")

    if not isinstance(token, str):
        return None

    normalized = token.strip()

    return normalized or None


@router.websocket("/ws")
async def websocket_stream(
    websocket: WebSocket,
) -> None:
    manager = get_connection_manager(
        websocket,
    )

    connection_id = await manager.connect(
        websocket,
    )

    authenticated = False

    try:
        await websocket.send_json(
            {
                "type": "connected",
                "connection_id": connection_id,
                "authentication_required": True,
            },
        )

        while True:
            message = await websocket.receive_json()

            if not isinstance(
                message,
                dict,
            ):
                await websocket.send_json(
                    {
                        "type": "error",
                        "code": "INVALID_MESSAGE",
                    },
                )
                continue

            action = message.get("action")

            # --------------------------------------------------------------
            # Authentication
            # --------------------------------------------------------------

            if action == "authenticate":
                token = extract_authentication_token(
                    message,
                )

                if token is None:
                    await websocket.send_json(
                        {
                            "type": "authentication_failed",
                            "code": "INVALID_TOKEN",
                        },
                    )
                    await websocket.close(
                        code=1008,
                        reason="authentication failed",
                    )
                    return

                container = get_api_container_from_websocket(
                    websocket,
                )

                if container.postgres_session_manager is None:
                    await websocket.send_json(
                        {
                            "type": "authentication_failed",
                            "code": "AUTHENTICATION_UNAVAILABLE",
                        },
                    )
                    await websocket.close(
                        code=1011,
                        reason="authentication service unavailable",
                    )
                    return

                from app.api.dependencies import (
                    _build_authentication_service,
                )

                async with container.postgres_session_manager.session() as session:
                    authentication = (
                        _build_authentication_service(
                            session=session,
                            container=container,
                        )
                    )

                    try:
                        principal = (
                            await authentication.authenticate_token(
                                token,
                            )
                        )

                    except AuthenticationError:
                        await websocket.send_json(
                            {
                                "type": "authentication_failed",
                                "code": "INVALID_TOKEN",
                            },
                        )
                        await websocket.close(
                            code=1008,
                            reason="authentication failed",
                        )
                        return

                await manager.authenticate(
                    connection_id,
                    user_id=principal.user_id,
                    username=principal.username,
                    roles=principal.roles,
                    permissions=principal.permissions,
                )

                authenticated = True

                await websocket.send_json(
                    {
                        "type": "authenticated",
                        "connection_id": connection_id,
                        "user": {
                            "user_id": str(principal.user_id),
                            "username": principal.username,
                            "roles": sorted(principal.roles),
                            "permissions": sorted(principal.permissions),
                        },
                    },
                )

                continue

            # --------------------------------------------------------------
            # Authentication required for all other actions
            # --------------------------------------------------------------

            if not authenticated:
                await websocket.send_json(
                    {
                        "type": "error",
                        "code": "AUTHENTICATION_REQUIRED",
                    },
                )
                continue

            # --------------------------------------------------------------
            # Ping
            # --------------------------------------------------------------

            if action == "ping":
                await websocket.send_json(
                    {
                        "type": "pong",
                    },
                )
                continue

            # --------------------------------------------------------------
            # Channel subscription
            # --------------------------------------------------------------

            if action == "subscribe":
                channels = message.get(
                    "channels",
                    [],
                )

                if (
                    not isinstance(channels, list)
                    or not all(
                        isinstance(channel, str)
                        for channel in channels
                    )
                ):
                    await websocket.send_json(
                        {
                            "type": "error",
                            "code": "INVALID_SUBSCRIPTION",
                        },
                    )
                    continue

                try:
                    active_channels = (
                        await manager.update_channels(
                            connection_id,
                            set(channels),
                        )
                    )

                except PermissionError:
                    await websocket.send_json(
                        {
                            "type": "error",
                            "code": "PERMISSION_DENIED",
                        },
                    )
                    continue

                await websocket.send_json(
                    {
                        "type": "subscribed",
                        "channels": list(active_channels),
                    },
                )
                continue

            await websocket.send_json(
                {
                    "type": "error",
                    "code": "UNSUPPORTED_ACTION",
                },
            )

    except WebSocketDisconnect:
        pass

    finally:
        await manager.disconnect(
            connection_id,
        )
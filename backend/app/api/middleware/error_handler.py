from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from fastapi import Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


async def api_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    request_id = getattr(request.state, "request_id", None)
    if isinstance(exc, KeyError):
        status = 404
        code = "RESOURCE_NOT_FOUND"
        message = str(exc).strip("'")
    elif isinstance(exc, ValueError):
        status = 400
        code = "INVALID_REQUEST"
        message = str(exc)
    else:
        status = 500
        code = "INTERNAL_ERROR"
        message = "An internal server error occurred."
        logger.exception("Unhandled API exception", exc_info=exc)

    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message, "request_id": request_id}},
    )

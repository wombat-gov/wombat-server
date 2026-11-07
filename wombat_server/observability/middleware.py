"""Request correlation and structured request logging."""
from __future__ import annotations

import logging
import re
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from wombat_server.observability.logging import request_id_var

log = logging.getLogger("wombat_server.request")

# Correlation IDs are not a security boundary, but they must not be able to
# inject newlines or arbitrary text into logs. Accept a sane token; otherwise
# generate one.
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,128}$")

# Health and scrape paths are noisy; log them at DEBUG.
_QUIET_PATHS = {"/health", "/livez", "/readyz", "/metrics"}


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        incoming = request.headers.get("x-request-id", "")
        request_id = incoming if _REQUEST_ID_RE.match(incoming) else uuid.uuid4().hex
        token = request_id_var.set(request_id)
        request.state.request_id = request_id
        start = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
        except Exception:
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            log.exception(
                "request failed",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status": status,
                    "duration_ms": duration_ms,
                    "user_id": getattr(request.state, "user_id", ""),
                },
            )
            raise
        finally:
            request_id_var.reset(token)

        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        response.headers.setdefault("X-Request-ID", request_id)
        level = logging.DEBUG if request.url.path in _QUIET_PATHS else logging.INFO
        log.log(
            level,
            "request",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status": status,
                "duration_ms": duration_ms,
                "user_id": getattr(request.state, "user_id", ""),
            },
        )
        return response

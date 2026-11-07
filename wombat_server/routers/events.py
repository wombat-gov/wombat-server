"""Server-Sent Events stream for the dashboard and the desktop app.

    GET /api/v1/events

Cookie or Bearer auth; the stream is filtered by the caller's mandate context
and supports ``Last-Event-ID`` replay from the in-process buffer.
"""
from __future__ import annotations

import asyncio
import json
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.responses import StreamingResponse

from wombat_server.auth.deps import AuthContext, get_auth_context
from wombat_server.config import settings
from wombat_server.events import get_event_bus

router = APIRouter(prefix="/events", tags=["events"])

HEARTBEAT_SECONDS = 20


@router.get("")
async def stream_events(
    request: Request,
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    last_event_id: Annotated[str | None, Header(alias="Last-Event-ID")] = None,
) -> StreamingResponse:
    if not settings.wombat_events_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The event stream is disabled (WOMBAT_EVENTS_ENABLED=false).",
        )

    bus = get_event_bus()
    mandate_id = auth.mandant_id

    async def generate():
        replay, queue = bus.subscribe(mandate_id, last_event_id)
        try:
            ready = {"mandate_id": str(mandate_id) if mandate_id else None}
            yield f"event: ready\ndata: {json.dumps(ready, separators=(',', ':'))}\n\n"
            for event in replay:
                yield event.to_sse()

            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=HEARTBEAT_SECONDS)
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
                    continue
                yield event.to_sse()
        finally:
            bus.unsubscribe(queue)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )

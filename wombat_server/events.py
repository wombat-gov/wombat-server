"""In-process event bus for Server-Sent Events (SSE).

Wave A is deliberately single-process: one asyncio queue per subscriber and a
bounded replay buffer. Multi-replica deployments can back this with Redis
pub/sub later without changing the router or the event payloads.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_BUFFER_SIZE = 500
DEFAULT_QUEUE_SIZE = 200


@dataclass(frozen=True)
class BusEvent:
    id: str
    type: str
    data: dict[str, Any]
    mandate_id: str | None = None
    created_at: float = field(default_factory=time.time)

    def to_sse(self) -> str:
        payload = json.dumps(self.data, default=str, separators=(",", ":"))
        return f"id: {self.id}\nevent: {self.type}\ndata: {payload}\n\n"


def _visible_to(event: BusEvent, mandate_id: str | None) -> bool:
    """Global events are visible to everyone; mandate events only to that
    mandate (or to a subscriber without a mandate context, e.g. a holding
    admin's full view)."""
    if mandate_id is None:
        return True
    return event.mandate_id is None or event.mandate_id == str(mandate_id)


class EventBus:
    def __init__(self, buffer_size: int = DEFAULT_BUFFER_SIZE, queue_size: int = DEFAULT_QUEUE_SIZE):
        self._buffer: deque[BusEvent] = deque(maxlen=buffer_size)
        self._subscribers: dict[asyncio.Queue[BusEvent], str | None] = {}
        self._queue_size = queue_size
        self._sequence = 0
        self._lock = asyncio.Lock()

    async def publish(
        self,
        event_type: str,
        data: dict[str, Any],
        mandate_id: Any | None = None,
    ) -> BusEvent:
        async with self._lock:
            self._sequence += 1
            event = BusEvent(
                id=str(self._sequence),
                type=event_type,
                data=data,
                mandate_id=str(mandate_id) if mandate_id is not None else None,
            )
            self._buffer.append(event)
            subscribers = list(self._subscribers.items())

        for queue, subscriber_mandate in subscribers:
            if not _visible_to(event, subscriber_mandate):
                continue
            if queue.full():
                # A slow client must not stall publishers; drop its oldest event.
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                pass
        return event

    def subscribe(
        self,
        mandate_id: Any | None = None,
        last_event_id: str | None = None,
    ) -> tuple[list[BusEvent], asyncio.Queue[BusEvent]]:
        mandate = str(mandate_id) if mandate_id is not None else None
        last_sequence: int | None = None
        if last_event_id:
            try:
                last_sequence = int(last_event_id)
            except (TypeError, ValueError):
                last_sequence = None

        replay = [
            event
            for event in list(self._buffer)
            if _visible_to(event, mandate)
            and (last_sequence is None or int(event.id) > last_sequence)
        ]
        queue: asyncio.Queue[BusEvent] = asyncio.Queue(maxsize=self._queue_size)
        self._subscribers[queue] = mandate
        return replay, queue

    def unsubscribe(self, queue: asyncio.Queue[BusEvent]) -> None:
        self._subscribers.pop(queue, None)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


_bus = EventBus()


def get_event_bus() -> EventBus:
    return _bus


def new_event_id() -> str:
    """Fallback id helper for clients/tests that need a synthetic id."""
    return f"{int(time.time() * 1000)}-{uuid.uuid4().hex[:8]}"


async def publish_event(event_type: str, data: dict[str, Any], mandate_id: Any | None = None) -> None:
    """Publish an event; never let event delivery break a write request."""
    try:
        await _bus.publish(event_type, data, mandate_id)
    except Exception:  # pragma: no cover - defensive
        logger.exception("Failed to publish event %s", event_type)

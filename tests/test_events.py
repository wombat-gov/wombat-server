"""Wave A: in-process event bus tests (no database required)."""
from __future__ import annotations

import asyncio

import pytest

from wombat_server.events import EventBus


@pytest.mark.asyncio
async def test_event_bus_filters_by_mandate_and_replays() -> None:
    bus = EventBus(buffer_size=10)

    replay, queue = bus.subscribe("mandate-1")
    assert replay == []
    assert bus.subscriber_count == 1

    first = await bus.publish("run.created", {"id": "1"}, mandate_id="mandate-1")
    await bus.publish("run.created", {"id": "2"}, mandate_id="mandate-2")
    global_event = await bus.publish("notification.created", {"id": "3"})

    received = [
        await asyncio.wait_for(queue.get(), timeout=1),
        await asyncio.wait_for(queue.get(), timeout=1),
    ]
    assert [event.data["id"] for event in received] == ["1", "3"]

    # Replay after the first event: the mandate-2 event must stay invisible,
    # the global event must be included.
    replay, second_queue = bus.subscribe("mandate-1", last_event_id=first.id)
    assert [event.id for event in replay] == [global_event.id]

    # A subscriber with no mandate context sees everything.
    all_replay, all_queue = bus.subscribe(None, last_event_id=None)
    assert [event.data["id"] for event in all_replay] == ["1", "2", "3"]

    bus.unsubscribe(queue)
    bus.unsubscribe(second_queue)
    bus.unsubscribe(all_queue)
    assert bus.subscriber_count == 0


@pytest.mark.asyncio
async def test_event_bus_sse_format() -> None:
    bus = EventBus()
    event = await bus.publish("waiver.changed", {"action": "upsert", "id": "W-1"})
    payload = event.to_sse()
    assert f"id: {event.id}\n" in payload
    assert "event: waiver.changed\n" in payload
    assert 'data: {"action":"upsert","id":"W-1"}\n\n' in payload


@pytest.mark.asyncio
async def test_event_bus_drops_old_events_for_slow_subscribers() -> None:
    bus = EventBus(queue_size=1)
    _, queue = bus.subscribe(None)
    await bus.publish("run.created", {"id": "1"})
    await bus.publish("run.created", {"id": "2"})
    remaining = await asyncio.wait_for(queue.get(), timeout=1)
    assert remaining.data["id"] == "2"
    bus.unsubscribe(queue)

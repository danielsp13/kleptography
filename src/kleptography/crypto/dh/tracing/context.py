from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from src.kleptography.crypto.dh.tracing.events import (
    Actor,
    ProtocolEvent,
    ProtocolEventType,
)
from src.kleptography.crypto.dh.tracing.observer import OperationObserver


@dataclass(slots=True)
class ProtocolExecutionContext(OperationObserver):
    """Collects observed operations as an ordered protocol timeline."""

    _events: list[ProtocolEvent] = field(default_factory=list)

    def observe(
        self,
        event_type: ProtocolEventType,
        *,
        actor: Actor,
        data: Mapping[str, object] | None = None,
    ) -> None:
        """Record an observed operation as a protocol event."""
        self._events.append(
            ProtocolEvent(
                sequence=len(self._events) + 1,
                event_type=event_type,
                actor=actor,
                data={} if data is None else data,
            )
        )

    @property
    def events(self) -> tuple[ProtocolEvent, ...]:
        """Return the immutable execution timeline."""
        return tuple(self._events)

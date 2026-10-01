"""An observer that records protocol events as an ordered timeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from kleptography.crypto.dh.tracing.events import (
    Actor,
    ProtocolEvent,
    ProtocolEventType,
)
from kleptography.crypto.dh.tracing.observer import OperationObserver


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
        """Record an observed operation as a protocol event.

        Args:
            event_type: The semantic step that took place.
            actor: The entity responsible for the step.
            data: The values involved in the step, if any.
        """
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

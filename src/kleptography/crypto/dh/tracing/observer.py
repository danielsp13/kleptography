from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Mapping

from src.kleptography.crypto.dh.tracing.events import Actor, ProtocolEventType


class OperationObserver(ABC):
    """Interface for observing cryptographic and protocol operations."""

    @abstractmethod
    def observe(
        self,
        event_type: ProtocolEventType,
        *,
        actor: Actor,
        data: Mapping[str, object] | None = None,
    ) -> None:
        """Observe an operation without defining how it is represented."""
        raise NotImplementedError

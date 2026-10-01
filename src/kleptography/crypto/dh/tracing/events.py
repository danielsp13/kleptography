"""Value objects describing the events of a Diffie-Hellman execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Mapping


class Actor(StrEnum):
    """Entity responsible for a protocol event."""

    SYSTEM = "system"
    ALICE = "alice"
    BOB = "bob"


class ProtocolEventType(StrEnum):
    """Semantic events emitted during a Diffie-Hellman execution."""

    PARAMETERS_SELECTED = "parameters_selected"
    PARAMETERS_VALIDATED = "parameters_validated"

    PRIVATE_KEY_GENERATED = "private_key_generated"
    PRIVATE_KEY_PROVIDED = "private_key_provided"
    PUBLIC_KEY_COMPUTED = "public_key_computed"

    PUBLIC_KEY_SENT = "public_key_sent"
    PUBLIC_KEY_RECEIVED = "public_key_received"

    SHARED_SECRET_COMPUTED = "shared_secret_computed"
    SHARED_SECRET_VERIFIED = "shared_secret_verified"

    MODULAR_EXPONENTIATION_STARTED = "modular_exponentiation_started"
    MODULAR_EXPONENTIATION_STEP = "modular_exponentiation_step"
    MODULAR_EXPONENTIATION_COMPLETED = "modular_exponentiation_completed"


@dataclass(frozen=True, slots=True)
class ProtocolEvent:
    """Immutable, presentation-agnostic description of a protocol event."""

    sequence: int
    event_type: ProtocolEventType
    actor: Actor
    data: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate the sequence number and freeze the event data."""
        if self.sequence < 1:
            raise ValueError("Protocol event sequence must be greater than zero.")

        object.__setattr__(
            self,
            "data",
            MappingProxyType(dict(self.data)),
        )

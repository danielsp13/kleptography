from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from kleptography.crypto.aead.records import EncryptedMessage
from kleptography.crypto.channel.records import SessionTranscript, TranscriptMessage
from kleptography.crypto.channel.setup.exceptions import InvalidChannelInterception
from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.setup.records import SetupCandidates, SetupRecovery
from kleptography.crypto.dh.tracing.events import Actor
from kleptography.crypto.kdf.records import KeyDerivation


class InterceptionOutcome(StrEnum):
    # Session 1: there is no previous public key, so a1 never leaks.
    NOT_RECOVERABLE = "not_recoverable"
    # No candidate reproduces A_i: A_i was not derived from A_{i-1} by this
    # SETUP (for example, an honest Alice).
    RECOVERY_FAILED = "recovery_failed"
    RECOVERED = "recovered"


@dataclass(frozen=True, slots=True)
class InterceptedMessage:
    transcript: TranscriptMessage
    # None when the session key is unknown or the GCM tag rejects it.
    plaintext: str | None

    @property
    def sender(self) -> Actor:
        return self.transcript.sender

    @property
    def encrypted(self) -> EncryptedMessage:
        return self.transcript.encrypted

    @property
    def readable(self) -> bool:
        return self.plaintext is not None


@dataclass(frozen=True, slots=True)
class InterceptedSession:
    transcript: SessionTranscript
    outcome: InterceptionOutcome
    # Every session but the first has candidates, even when none matches.
    candidates: SetupCandidates | None
    recovery: SetupRecovery | None
    shared_secret: int | None
    key_derivation: KeyDerivation | None
    messages: tuple[InterceptedMessage, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, InterceptionOutcome):
            raise InvalidChannelInterception("Unknown interception outcome.")
        if (self.number == 1) != (self.outcome is InterceptionOutcome.NOT_RECOVERABLE):
            raise InvalidChannelInterception(
                "Only session 1, and every session 1, is not recoverable."
            )
        if (self.number == 1) != (self.candidates is None):
            raise InvalidChannelInterception(
                "Every session but the first has SETUP candidates."
            )
        if tuple(message.transcript for message in self.messages) != (
            self.transcript.messages
        ):
            raise InvalidChannelInterception(
                "The intercepted messages must be those of the session transcript."
            )

        if self.outcome is InterceptionOutcome.RECOVERED:
            self._validate_recovered()
        else:
            self._validate_not_recovered()

    @property
    def number(self) -> int:
        return self.transcript.number

    @property
    def recovered(self) -> bool:
        return self.outcome is InterceptionOutcome.RECOVERED

    @property
    def readable(self) -> bool:
        return self.recovered and all(message.readable for message in self.messages)

    def _validate_recovered(self) -> None:
        if (
            self.recovery is None
            or self.shared_secret is None
            or self.key_derivation is None
        ):
            raise InvalidChannelInterception(
                "A recovered session needs its recovery, shared secret and key."
            )
        candidates = self.candidates
        if candidates is None or (
            self.recovery.first_public_key,
            self.recovery.r,
            self.recovery.z_candidates,
            self.recovery.private_key_candidates,
        ) != (
            candidates.first_public_key,
            candidates.r,
            candidates.z_candidates,
            candidates.private_key_candidates,
        ):
            raise InvalidChannelInterception(
                "The recovery must come from the session's candidates."
            )
        if self.recovery.second_public_key != self.transcript.alice_public_key:
            raise InvalidChannelInterception(
                "The recovery must target this session's public key from Alice."
            )
        if self.key_derivation.shared_secret != self.shared_secret:
            raise InvalidChannelInterception(
                "The session key must be derived from the recovered shared secret."
            )

    def _validate_not_recovered(self) -> None:
        if (
            self.recovery is not None
            or self.shared_secret is not None
            or self.key_derivation is not None
            or any(message.readable for message in self.messages)
        ):
            raise InvalidChannelInterception(
                "A session that was not recovered reveals nothing."
            )


@dataclass(frozen=True, slots=True)
class ChannelInterception:
    parameters: DiffieHellmanParameters
    sessions: tuple[InterceptedSession, ...]

    def __post_init__(self) -> None:
        numbers = [session.number for session in self.sessions]
        if not numbers or numbers != list(range(1, len(numbers) + 1)):
            raise InvalidChannelInterception(
                "Sessions must be numbered 1, 2, ... in order."
            )

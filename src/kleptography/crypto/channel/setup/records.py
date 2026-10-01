"""Value objects exposing what the attacker reads from a channel transcript.

Every intermediate value (candidates, recovery, shared secret, key and
plaintexts) is kept, so the demonstration can show each step, including the
work of a failed recovery.
"""

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
    """What the attacker achieved on one session."""

    # Session 1: there is no previous public key, so a1 never leaks.
    NOT_RECOVERABLE = "not_recoverable"
    # No candidate reproduces A_i: A_i was not derived from A_{i-1} by this
    # SETUP (for example, an honest Alice).
    RECOVERY_FAILED = "recovery_failed"
    RECOVERED = "recovered"


@dataclass(frozen=True, slots=True)
class InterceptedMessage:
    """One encrypted message as the attacker sees it.

    Attributes:
        transcript: The message as it travelled over the network.
        plaintext: The decrypted text, or ``None`` if it could not be read.
    """

    transcript: TranscriptMessage
    # None when the session key is unknown or the GCM tag rejects it.
    plaintext: str | None

    @property
    def sender(self) -> Actor:
        """Return who sent the message."""
        return self.transcript.sender

    @property
    def encrypted(self) -> EncryptedMessage:
        """Return the nonce, ciphertext and tag of the message."""
        return self.transcript.encrypted

    @property
    def readable(self) -> bool:
        """Return whether the attacker read the message."""
        return self.plaintext is not None


@dataclass(frozen=True, slots=True)
class InterceptedSession:
    """One session as the attacker sees it, with every intermediate value.

    Attributes:
        transcript: The public transcript of the session.
        outcome: What the attacker achieved.
        candidates: The SETUP candidates from the previous public key of
            Alice, or ``None`` for session 1.
        recovery: The successful recovery of Alice's exponent, if any.
        shared_secret: The recovered shared secret, if any.
        key_derivation: The session key derived from that secret, if any.
        messages: The session's messages, decrypted when possible.

    Raises:
        InvalidChannelInterception: If the record is inconsistent, for
            example a recovered session without a key, or a session that
            was not recovered but reveals a plaintext.
    """

    transcript: SessionTranscript
    outcome: InterceptionOutcome
    # Every session but the first has candidates, even when none matches.
    candidates: SetupCandidates | None
    recovery: SetupRecovery | None
    shared_secret: int | None
    key_derivation: KeyDerivation | None
    messages: tuple[InterceptedMessage, ...]

    def __post_init__(self) -> None:
        """Check that the outcome agrees with what the session reveals."""
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
        """Return the position of the session in the channel."""
        return self.transcript.number

    @property
    def recovered(self) -> bool:
        """Return whether the attacker recovered Alice's exponent."""
        return self.outcome is InterceptionOutcome.RECOVERED

    @property
    def readable(self) -> bool:
        """Return whether the attacker read every message of the session."""
        return self.recovered and all(message.readable for message in self.messages)

    def _validate_recovered(self) -> None:
        """Check that a recovered session holds a consistent recovery and key."""
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
        """Check that a session that was not recovered reveals nothing."""
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
    """Everything the attacker reads from a channel transcript.

    Attributes:
        parameters: The Diffie-Hellman group of the channel.
        sessions: The intercepted sessions, numbered 1, 2, ... in order.

    Raises:
        InvalidChannelInterception: If there are no sessions or they are
            not numbered in order.
    """

    parameters: DiffieHellmanParameters
    sessions: tuple[InterceptedSession, ...]

    def __post_init__(self) -> None:
        """Check that the sessions are numbered 1, 2, ... in order."""
        numbers = [session.number for session in self.sessions]
        if not numbers or numbers != list(range(1, len(numbers) + 1)):
            raise InvalidChannelInterception(
                "Sessions must be numbered 1, 2, ... in order."
            )

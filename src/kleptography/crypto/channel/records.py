"""Value objects for the encrypted channel.

There are two views of the same communication:

- The **private view** (``ChannelMessage``, ``ChannelSession``, ``ChannelRun``)
  holds everything Alice and Bob know: shared secrets, derived keys and
  plaintexts. It exists so the demonstration can show every step.
- The **public view** (``TranscriptMessage``, ``SessionTranscript``,
  ``ChannelTranscript``) holds only what travels over the network: public
  keys and encrypted messages. It is everything an eavesdropper, or an
  attacker, gets to see.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from kleptography.crypto.aead.records import EncryptedMessage
from kleptography.crypto.channel.exceptions import (
    InvalidChannelMessage,
    InvalidChannelSessions,
)
from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.tracing.events import Actor, ProtocolEvent
from kleptography.crypto.kdf.records import KeyDerivation

MAX_MESSAGE_LENGTH = 140
"""Maximum number of characters of a message."""

PARTIES = (Actor.ALICE, Actor.BOB)
"""The two parties that can send messages over the channel."""


@dataclass(frozen=True, slots=True)
class PlainMessage:
    """A message that one party wants to send, before encryption.

    Messages are short, human-readable texts: printable ASCII (letters,
    digits, punctuation and spaces), between 1 and 140 characters.

    Attributes:
        sender: ``Actor.ALICE`` or ``Actor.BOB``. The recipient is the other one.
        text: The message text.

    Raises:
        InvalidChannelMessage: If the sender is not Alice or Bob, or the text
            is empty, longer than 140 characters, or not printable ASCII.
    """

    sender: Actor
    text: str

    def __post_init__(self) -> None:
        _validate_sender(self.sender)
        if not isinstance(self.text, str):
            raise InvalidChannelMessage("The message text must be a string.")
        if not 1 <= len(self.text) <= MAX_MESSAGE_LENGTH:
            raise InvalidChannelMessage(
                f"The message must have between 1 and {MAX_MESSAGE_LENGTH} characters."
            )
        if not (self.text.isascii() and self.text.isprintable()):
            raise InvalidChannelMessage("The message must be printable ASCII text.")

    @property
    def recipient(self) -> Actor:
        """Return the party that receives the message."""
        return _peer_of(self.sender)


@dataclass(frozen=True, slots=True)
class TranscriptMessage:
    """A message as it travels over the network: only its sender is visible.

    Attributes:
        sender: ``Actor.ALICE`` or ``Actor.BOB``.
        encrypted: The nonce, ciphertext and tag.

    Raises:
        InvalidChannelMessage: If the sender is not Alice or Bob.
    """

    sender: Actor
    encrypted: EncryptedMessage

    def __post_init__(self) -> None:
        _validate_sender(self.sender)

    @property
    def recipient(self) -> Actor:
        """Return the party that receives the message."""
        return _peer_of(self.sender)


@dataclass(frozen=True, slots=True)
class SessionTranscript:
    """The public view of one session: the DH public keys and the ciphertexts.

    Attributes:
        number: The position of the session in the channel, starting at 1.
        alice_public_key: Alice's ephemeral public value for this session.
        bob_public_key: Bob's ephemeral public value for this session.
        messages: The encrypted messages, in the order they were sent.

    Raises:
        InvalidChannelSessions: If ``number`` is lower than 1.
    """

    number: int
    alice_public_key: int
    bob_public_key: int
    messages: tuple[TranscriptMessage, ...]

    def __post_init__(self) -> None:
        _validate_session_number(self.number)


@dataclass(frozen=True, slots=True)
class ChannelTranscript:
    """The public view of the whole channel: what an eavesdropper records.

    The group is public too: it is agreed before any session starts.

    Attributes:
        parameters: The DH group used by every session.
        sessions: The session transcripts, numbered 1, 2, ... in order.

    Raises:
        InvalidChannelSessions: If there are no sessions or they are not
            numbered consecutively from 1.
    """

    parameters: DiffieHellmanParameters
    sessions: tuple[SessionTranscript, ...]

    def __post_init__(self) -> None:
        _validate_session_sequence(self.sessions)


@dataclass(frozen=True, slots=True)
class ChannelMessage:
    """The private view of one message: plaintext, ciphertext and what arrived.

    Attributes:
        sender: ``Actor.ALICE`` or ``Actor.BOB``.
        plaintext: The text the sender encrypted.
        encrypted: The nonce, ciphertext and tag sent over the network.
        received_plaintext: The text the recipient decrypted with its own key.

    Raises:
        InvalidChannelMessage: If the sender is not Alice or Bob.
    """

    sender: Actor
    plaintext: str
    encrypted: EncryptedMessage
    received_plaintext: str

    def __post_init__(self) -> None:
        _validate_sender(self.sender)

    @property
    def recipient(self) -> Actor:
        """Return the party that receives the message."""
        return _peer_of(self.sender)

    @property
    def delivered(self) -> bool:
        """Return whether the recipient read exactly what the sender wrote."""
        return self.plaintext == self.received_plaintext

    @property
    def transcript(self) -> TranscriptMessage:
        """Return the public view of the message."""
        return TranscriptMessage(sender=self.sender, encrypted=self.encrypted)


@dataclass(frozen=True, slots=True)
class ChannelSession:
    """The private view of one session: ephemeral DH, key derivation and messages.

    Each party derives its own key from its own shared secret, and each
    recipient decrypts with its own key, so a successful session shows that
    both sides really ended up with the same key.

    Attributes:
        number: The position of the session in the channel, starting at 1.
        events: The timeline of the session's DH exchange.
        alice_public_key: Alice's ephemeral public value.
        bob_public_key: Bob's ephemeral public value.
        alice_key_derivation: Alice's shared secret and derived key.
        bob_key_derivation: Bob's shared secret and derived key.
        messages: The messages, in the order they were sent.

    Raises:
        InvalidChannelSessions: If ``number`` is lower than 1.
    """

    number: int
    events: tuple[ProtocolEvent, ...] = field(repr=False)
    alice_public_key: int
    bob_public_key: int
    alice_key_derivation: KeyDerivation
    bob_key_derivation: KeyDerivation
    messages: tuple[ChannelMessage, ...]

    def __post_init__(self) -> None:
        _validate_session_number(self.number)

    @property
    def keys_match(self) -> bool:
        """Return whether Alice and Bob derived the same session key."""
        return self.alice_key_derivation.key == self.bob_key_derivation.key

    @property
    def transcript(self) -> SessionTranscript:
        """Return the public view of the session."""
        return SessionTranscript(
            number=self.number,
            alice_public_key=self.alice_public_key,
            bob_public_key=self.bob_public_key,
            messages=tuple(message.transcript for message in self.messages),
        )


@dataclass(frozen=True, slots=True)
class ChannelRun:
    """The private view of the whole channel, from which the transcript is built.

    Attributes:
        parameters: The DH group used by every session.
        sessions: The sessions, numbered 1, 2, ... in order.

    Raises:
        InvalidChannelSessions: If there are no sessions or they are not
            numbered consecutively from 1.
    """

    parameters: DiffieHellmanParameters
    sessions: tuple[ChannelSession, ...]

    def __post_init__(self) -> None:
        _validate_session_sequence(self.sessions)

    @property
    def transcript(self) -> ChannelTranscript:
        """Return the public view of the channel."""
        return ChannelTranscript(
            parameters=self.parameters,
            sessions=tuple(session.transcript for session in self.sessions),
        )


def _validate_sender(sender: Actor) -> None:
    """Check that the sender is Alice or Bob."""
    if not isinstance(sender, Actor) or sender not in PARTIES:
        raise InvalidChannelMessage("The sender must be Alice or Bob.")


def _peer_of(sender: Actor) -> Actor:
    """Return the other party of the channel."""
    return Actor.BOB if sender is Actor.ALICE else Actor.ALICE


def _validate_session_number(number: int) -> None:
    """Check that a session number is an integer of at least 1."""
    if isinstance(number, bool) or not isinstance(number, int) or number < 1:
        raise InvalidChannelSessions("Session numbers start at 1.")


def _validate_session_sequence(
    sessions: Sequence[SessionTranscript] | Sequence[ChannelSession],
) -> None:
    """Check that there are sessions and they are numbered 1, 2, ... in order."""
    if not sessions:
        raise InvalidChannelSessions("A channel needs at least one session.")
    numbers = [session.number for session in sessions]
    if numbers != list(range(1, len(sessions) + 1)):
        raise InvalidChannelSessions("Sessions must be numbered 1, 2, ... in order.")

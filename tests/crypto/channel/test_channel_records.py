from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from kleptography.crypto.aead.records import EncryptedMessage
from kleptography.crypto.channel.exceptions import (
    InvalidChannelMessage,
    InvalidChannelSessions,
)
from kleptography.crypto.channel.records import (
    MAX_MESSAGE_LENGTH,
    ChannelMessage,
    ChannelRun,
    ChannelSession,
    ChannelTranscript,
    PlainMessage,
    SessionTranscript,
    TranscriptMessage,
)
from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.tracing.events import Actor
from kleptography.crypto.kdf.one_step import derive_key

ENCRYPTED = EncryptedMessage(nonce=bytes(12), ciphertext=b"abc", tag=bytes(16))


@pytest.fixture
def parameters() -> DiffieHellmanParameters:
    return DiffieHellmanParameters(prime=23, generator=2, subgroup_order=11)


def _channel_message(sender: Actor = Actor.ALICE) -> ChannelMessage:
    return ChannelMessage(
        sender=sender,
        plaintext="abc",
        encrypted=ENCRYPTED,
        received_plaintext="abc",
    )


def _channel_session(number: int, *, bob_secret: int = 6) -> ChannelSession:
    # Toy reference exchange: A = 18, B = 13, shared secret 6.
    return ChannelSession(
        number=number,
        events=(),
        alice_public_key=18,
        bob_public_key=13,
        alice_key_derivation=derive_key(6, secret_length=1),
        bob_key_derivation=derive_key(bob_secret, secret_length=1),
        messages=(_channel_message(Actor.ALICE), _channel_message(Actor.BOB)),
    )


def _session_transcript(number: int) -> SessionTranscript:
    return SessionTranscript(
        number=number,
        alice_public_key=18,
        bob_public_key=13,
        messages=(),
    )


def test_max_message_length_is_140() -> None:
    """Messages are short, like an SMS or an old tweet."""
    assert MAX_MESSAGE_LENGTH == 140


@pytest.mark.parametrize(
    ("sender", "recipient"),
    [(Actor.ALICE, Actor.BOB), (Actor.BOB, Actor.ALICE)],
)
def test_plain_message_recipient_is_the_other_party(
    sender: Actor,
    recipient: Actor,
) -> None:
    """The recipient of a message is always the party that did not send it."""
    message = PlainMessage(sender=sender, text="Hello")

    assert message.recipient is recipient


@pytest.mark.parametrize(
    "text",
    ["a", "Hello, Bob! See you at 10:30.", " ", "~" * MAX_MESSAGE_LENGTH],
    ids=["one-char", "sentence", "space", "max-length"],
)
def test_plain_message_accepts_printable_ascii(text: str) -> None:
    """Short human-readable ASCII texts are valid messages."""
    assert PlainMessage(sender=Actor.ALICE, text=text).text == text


@pytest.mark.parametrize(
    "text",
    ["", "a" * (MAX_MESSAGE_LENGTH + 1), "Hola, señor", "line\nbreak", "tab\t", "\x00"],
    ids=["empty", "too-long", "non-ascii", "newline", "tab", "control"],
)
def test_plain_message_rejects_invalid_text(text: str) -> None:
    """Empty, too long, non-ASCII or non-printable texts are rejected."""
    with pytest.raises(InvalidChannelMessage):
        PlainMessage(sender=Actor.ALICE, text=text)


def test_plain_message_rejects_non_string_text() -> None:
    """The text must be a string, not bytes."""
    with pytest.raises(InvalidChannelMessage):
        PlainMessage(sender=Actor.ALICE, text=b"Hello")  # ty: ignore[invalid-argument-type]


@pytest.mark.parametrize("sender", [Actor.SYSTEM, "alice", None])
def test_records_reject_invalid_sender(sender: object) -> None:
    """Only Alice and Bob (as ``Actor`` members) can send messages."""
    with pytest.raises(InvalidChannelMessage):
        PlainMessage(sender=sender, text="Hello")  # ty: ignore[invalid-argument-type]
    with pytest.raises(InvalidChannelMessage):
        TranscriptMessage(sender=sender, encrypted=ENCRYPTED)  # ty: ignore[invalid-argument-type]
    with pytest.raises(InvalidChannelMessage):
        _channel_message(sender)  # ty: ignore[invalid-argument-type]


def test_plain_message_is_frozen() -> None:
    """A message cannot be modified after creation."""
    message = PlainMessage(sender=Actor.ALICE, text="Hello")

    with pytest.raises(FrozenInstanceError):
        message.text = "Bye"  # ty: ignore[invalid-assignment]


def test_transcript_message_recipient() -> None:
    """The public view also tells who receives the message."""
    message = TranscriptMessage(sender=Actor.BOB, encrypted=ENCRYPTED)

    assert message.recipient is Actor.ALICE


def test_channel_message_public_view_has_only_sender_and_ciphertext() -> None:
    """The transcript of a message drops both plaintexts."""
    message = _channel_message(Actor.BOB)

    assert message.recipient is Actor.ALICE
    assert message.transcript == TranscriptMessage(
        sender=Actor.BOB, encrypted=ENCRYPTED
    )


@pytest.mark.parametrize(
    ("received", "delivered"),
    [("abc", True), ("abd", False)],
)
def test_channel_message_delivered(received: str, delivered: bool) -> None:
    """A message is delivered when the recipient reads what was sent."""
    message = ChannelMessage(
        sender=Actor.ALICE,
        plaintext="abc",
        encrypted=ENCRYPTED,
        received_plaintext=received,
    )

    assert message.delivered is delivered


@pytest.mark.parametrize(("bob_secret", "keys_match"), [(6, True), (7, False)])
def test_channel_session_keys_match(bob_secret: int, keys_match: bool) -> None:
    """Keys match only when both parties derived them from the same secret."""
    assert _channel_session(1, bob_secret=bob_secret).keys_match is keys_match


def test_channel_session_public_view() -> None:
    """The transcript of a session keeps public keys and ciphertexts only."""
    transcript = _channel_session(2).transcript

    assert transcript == SessionTranscript(
        number=2,
        alice_public_key=18,
        bob_public_key=13,
        messages=(
            TranscriptMessage(sender=Actor.ALICE, encrypted=ENCRYPTED),
            TranscriptMessage(sender=Actor.BOB, encrypted=ENCRYPTED),
        ),
    )


@pytest.mark.parametrize("number", [0, -1, True, 1.0])
def test_sessions_reject_invalid_number(number: object) -> None:
    """Session numbers are integers starting at 1."""
    with pytest.raises(InvalidChannelSessions):
        _channel_session(number)  # ty: ignore[invalid-argument-type]
    with pytest.raises(InvalidChannelSessions):
        _session_transcript(number)  # ty: ignore[invalid-argument-type]


def test_channel_run_public_view(parameters: DiffieHellmanParameters) -> None:
    """The transcript of a run has the group and one transcript per session."""
    run = ChannelRun(
        parameters=parameters,
        sessions=(_channel_session(1), _channel_session(2)),
    )

    assert run.transcript == ChannelTranscript(
        parameters=parameters,
        sessions=(_channel_session(1).transcript, _channel_session(2).transcript),
    )


@pytest.mark.parametrize(
    "numbers",
    [(), (2,), (1, 3), (2, 1), (1, 1)],
    ids=["empty", "starts-at-2", "gap", "unordered", "repeated"],
)
def test_channel_records_reject_invalid_session_sequence(
    parameters: DiffieHellmanParameters,
    numbers: tuple[int, ...],
) -> None:
    """Sessions must be numbered 1, 2, ... in order, with at least one."""
    with pytest.raises(InvalidChannelSessions):
        ChannelRun(
            parameters=parameters,
            sessions=tuple(_channel_session(number) for number in numbers),
        )
    with pytest.raises(InvalidChannelSessions):
        ChannelTranscript(
            parameters=parameters,
            sessions=tuple(_session_transcript(number) for number in numbers),
        )


def test_channel_session_hides_events_from_repr() -> None:
    """The timeline, full of private values, does not clutter the repr."""
    assert "events" not in repr(_channel_session(1))

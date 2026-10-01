"""
Records are built by hand from the toy group vectors: session 2 with
A1 = 18, A2 = 16, B2 = 13, a2 = 4 and s2 = 18.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import FrozenInstanceError, replace

import pytest

from kleptography.crypto.aead.aes_gcm import encrypt
from kleptography.crypto.channel.records import SessionTranscript, TranscriptMessage
from kleptography.crypto.channel.setup.exceptions import InvalidChannelInterception
from kleptography.crypto.channel.setup.records import (
    ChannelInterception,
    InterceptedMessage,
    InterceptedSession,
    InterceptionOutcome,
)
from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.setup.records import SetupRecovery
from kleptography.crypto.dh.tracing.events import Actor
from kleptography.crypto.kdf.one_step import derive_key
from kleptography.crypto.kdf.records import KeyDerivation

KEY_DERIVATION = derive_key(18, secret_length=1)
RECOVERY = SetupRecovery(
    first_public_key=18,
    second_public_key=16,
    r=8,
    z_candidates=(3, 9),
    private_key_candidates=(4, 10),
    correction_bit=0,
    private_key=4,
)
TRANSCRIPT_MESSAGE = TranscriptMessage(
    sender=Actor.BOB,
    encrypted=encrypt(KEY_DERIVATION.key, b"Hello", nonce=bytes(12)),
)


@pytest.fixture
def parameters() -> DiffieHellmanParameters:
    return DiffieHellmanParameters(prime=23, generator=2, subgroup_order=11)


def session_transcript(number: int) -> SessionTranscript:
    return SessionTranscript(
        number=number,
        alice_public_key=18 if number == 1 else 16,
        bob_public_key=13,
        messages=(TRANSCRIPT_MESSAGE,),
    )


def recovered_session(number: int = 2) -> InterceptedSession:
    return InterceptedSession(
        transcript=session_transcript(number),
        outcome=InterceptionOutcome.RECOVERED,
        recovery=RECOVERY,
        shared_secret=18,
        key_derivation=KEY_DERIVATION,
        messages=(
            InterceptedMessage(transcript=TRANSCRIPT_MESSAGE, plaintext="Hello"),
        ),
    )


def hidden_session(number: int, outcome: InterceptionOutcome) -> InterceptedSession:
    return InterceptedSession(
        transcript=session_transcript(number),
        outcome=outcome,
        recovery=None,
        shared_secret=None,
        key_derivation=None,
        messages=(InterceptedMessage(transcript=TRANSCRIPT_MESSAGE, plaintext=None),),
    )


def test_outcome_values() -> None:
    assert [outcome.value for outcome in InterceptionOutcome] == [
        "not_recoverable",
        "recovery_failed",
        "recovered",
    ]


def test_intercepted_message_exposes_its_transcript() -> None:
    message = InterceptedMessage(transcript=TRANSCRIPT_MESSAGE, plaintext="Hello")

    assert message.sender is Actor.BOB
    assert message.encrypted == TRANSCRIPT_MESSAGE.encrypted
    assert message.readable
    assert not replace(message, plaintext=None).readable


def test_intercepted_message_is_frozen() -> None:
    message = InterceptedMessage(transcript=TRANSCRIPT_MESSAGE, plaintext=None)

    with pytest.raises(FrozenInstanceError):
        message.plaintext = "Hello"  # ty: ignore[invalid-assignment]


def test_recovered_session_properties() -> None:
    session = recovered_session()

    assert session.number == 2
    assert session.recovered
    assert session.readable


def test_recovered_session_with_unreadable_message_is_not_readable() -> None:
    session = replace(
        recovered_session(),
        messages=(InterceptedMessage(transcript=TRANSCRIPT_MESSAGE, plaintext=None),),
    )

    assert session.recovered
    assert not session.readable


@pytest.mark.parametrize(
    ("number", "outcome"),
    [
        (1, InterceptionOutcome.NOT_RECOVERABLE),
        (2, InterceptionOutcome.RECOVERY_FAILED),
    ],
)
def test_hidden_session_properties(number: int, outcome: InterceptionOutcome) -> None:
    session = hidden_session(number, outcome)

    assert session.number == number
    assert not session.recovered
    assert not session.readable


def test_outcome_must_be_an_interception_outcome() -> None:
    with pytest.raises(InvalidChannelInterception):
        replace(recovered_session(), outcome="recovered")


@pytest.mark.parametrize(
    "session",
    [
        lambda: replace(
            hidden_session(1, InterceptionOutcome.NOT_RECOVERABLE),
            outcome=InterceptionOutcome.RECOVERY_FAILED,
        ),
        lambda: hidden_session(2, InterceptionOutcome.NOT_RECOVERABLE),
        lambda: recovered_session(1),
    ],
    ids=["first-failed", "second-not-recoverable", "first-recovered"],
)
def test_only_the_first_session_is_not_recoverable(
    session: Callable[[], InterceptedSession],
) -> None:
    with pytest.raises(InvalidChannelInterception):
        session()


@pytest.mark.parametrize(
    "messages",
    [(), (InterceptedMessage(transcript=TRANSCRIPT_MESSAGE, plaintext="Hello"),) * 2],
    ids=["missing", "extra"],
)
def test_messages_must_match_the_transcript(
    messages: tuple[InterceptedMessage, ...],
) -> None:
    with pytest.raises(InvalidChannelInterception):
        replace(recovered_session(), messages=messages)


@pytest.mark.parametrize("field", ["recovery", "shared_secret", "key_derivation"])
def test_recovered_session_needs_every_value(field: str) -> None:
    with pytest.raises(InvalidChannelInterception):
        replace(recovered_session(), **{field: None})


def test_recovery_must_target_the_session_public_key() -> None:
    with pytest.raises(InvalidChannelInterception):
        replace(recovered_session(), recovery=replace(RECOVERY, second_public_key=12))


def test_key_must_come_from_the_recovered_secret() -> None:
    other: KeyDerivation = derive_key(16, secret_length=1)

    with pytest.raises(InvalidChannelInterception):
        replace(recovered_session(), key_derivation=other)


@pytest.mark.parametrize(
    "changes",
    [
        {"recovery": RECOVERY},
        {"shared_secret": 18},
        {"key_derivation": KEY_DERIVATION},
        {
            "messages": (
                InterceptedMessage(transcript=TRANSCRIPT_MESSAGE, plaintext="Hello"),
            )
        },
    ],
    ids=["recovery", "shared-secret", "key", "plaintext"],
)
@pytest.mark.parametrize(
    ("number", "outcome"),
    [
        (1, InterceptionOutcome.NOT_RECOVERABLE),
        (2, InterceptionOutcome.RECOVERY_FAILED),
    ],
)
def test_hidden_session_reveals_nothing(
    number: int, outcome: InterceptionOutcome, changes: dict[str, object]
) -> None:
    with pytest.raises(InvalidChannelInterception):
        replace(hidden_session(number, outcome), **changes)


def test_channel_interception_keeps_its_sessions(
    parameters: DiffieHellmanParameters,
) -> None:
    sessions = (
        hidden_session(1, InterceptionOutcome.NOT_RECOVERABLE),
        recovered_session(),
    )

    interception = ChannelInterception(parameters=parameters, sessions=sessions)

    assert interception.parameters == parameters
    assert interception.sessions == sessions


@pytest.mark.parametrize(
    "numbers",
    [(), (2,), (1, 1), (1, 3)],
    ids=["empty", "not-from-one", "repeated", "gap"],
)
def test_channel_interception_sessions_are_numbered_in_order(
    parameters: DiffieHellmanParameters,
    numbers: tuple[int, ...],
) -> None:
    sessions = tuple(
        hidden_session(1, InterceptionOutcome.NOT_RECOVERABLE)
        if number == 1
        else hidden_session(number, InterceptionOutcome.RECOVERY_FAILED)
        for number in numbers
    )

    with pytest.raises(InvalidChannelInterception):
        ChannelInterception(parameters=parameters, sessions=sessions)

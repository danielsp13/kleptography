"""Tests for ``run_session``, one session of the encrypted channel.

They check that both parties derive the same key, that keys are always
ephemeral, that every message is delivered under a fresh nonce, that the
public view hides keys and plaintexts, that the device is a drop-in
replacement for Alice, and that different groups fail before any key.

Toy group p = 23, g = 2, q = 11. Private keys are fixed by patching the
honest generator, so a = 6, b = 7 gives A = 18, B = 13 and the secret 6.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from kleptography.crypto.aead.aes_gcm import decrypt
from kleptography.crypto.channel.exceptions import InvalidChannelSessions
from kleptography.crypto.channel.records import PlainMessage
from kleptography.crypto.channel.session import run_session
from kleptography.crypto.dh.exceptions import DiffieHellmanParametersMismatch
from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.participant import DiffieHellmanParticipant
from kleptography.crypto.dh.setup.attacker import YoungYungAttacker
from kleptography.crypto.dh.setup.participant import (
    YoungYungDiffieHellmanParticipant,
)
from kleptography.crypto.dh.tracing.events import Actor, ProtocolEventType
from kleptography.crypto.kdf.one_step import derive_key

MESSAGES = (
    PlainMessage(sender=Actor.ALICE, text="Hi Bob, meet at 10:30?"),
    PlainMessage(sender=Actor.BOB, text="OK, see you there."),
    PlainMessage(sender=Actor.ALICE, text="Bring the documents."),
)


@pytest.fixture
def parameters() -> DiffieHellmanParameters:
    """Return the toy group p = 23, g = 2, q = 11."""
    return DiffieHellmanParameters(prime=23, generator=2, subgroup_order=11)


def fix_private_keys(monkeypatch: pytest.MonkeyPatch, *keys: int) -> None:
    """Make honest key generation return ``keys`` in order."""
    sequence: Iterator[int] = iter(keys)

    def next_key(self: DiffieHellmanParticipant) -> int:
        return next(sequence)

    monkeypatch.setattr(DiffieHellmanParticipant, "_generate_private_key", next_key)


def test_session_matches_the_reference_exchange(
    parameters: DiffieHellmanParameters,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With a = 6 and b = 7, both parties derive the key of the secret 6."""
    fix_private_keys(monkeypatch, 6, 7)
    session = run_session(
        DiffieHellmanParticipant(parameters),
        DiffieHellmanParticipant(parameters),
        MESSAGES,
        number=1,
    )

    assert session.number == 1
    assert session.alice_public_key == 18
    assert session.bob_public_key == 13
    assert session.alice_key_derivation == derive_key(6, secret_length=1)
    assert session.bob_key_derivation == derive_key(6, secret_length=1)
    assert session.keys_match


def test_session_encodes_the_secret_with_the_length_of_p(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Z has the byte length of p, even when the secret is much smaller."""
    # p = 263 = 2 * 131 + 1 needs 2 bytes; g = 4 generates the subgroup.
    parameters = DiffieHellmanParameters(prime=263, generator=4, subgroup_order=131)
    fix_private_keys(monkeypatch, 1, 1)
    session = run_session(
        DiffieHellmanParticipant(parameters),
        DiffieHellmanParticipant(parameters),
        (),
        number=1,
    )

    assert session.alice_key_derivation.encoded_secret == b"\x00\x04"


def test_session_always_generates_fresh_keys(
    parameters: DiffieHellmanParameters,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ephemeral DH: key pairs loaded before the session are replaced."""
    alice = DiffieHellmanParticipant(parameters)
    bob = DiffieHellmanParticipant(parameters)
    alice.load_private_key(2)
    bob.load_private_key(3)
    fix_private_keys(monkeypatch, 6, 7)

    session = run_session(alice, bob, (), number=1)

    assert alice.private_key == 6
    assert bob.private_key == 7
    assert (session.alice_public_key, session.bob_public_key) == (18, 13)


def test_session_timeline_traces_the_exchange(
    parameters: DiffieHellmanParameters,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The exchange keeps its 13-event timeline; keys exist before it starts."""
    fix_private_keys(monkeypatch, 6, 7)
    session = run_session(
        DiffieHellmanParticipant(parameters),
        DiffieHellmanParticipant(parameters),
        (),
        number=1,
    )

    assert [event.event_type for event in session.events] == [
        ProtocolEventType.PARAMETERS_SELECTED,
        ProtocolEventType.PARAMETERS_VALIDATED,
        ProtocolEventType.PRIVATE_KEY_PROVIDED,
        ProtocolEventType.PUBLIC_KEY_COMPUTED,
        ProtocolEventType.PRIVATE_KEY_PROVIDED,
        ProtocolEventType.PUBLIC_KEY_COMPUTED,
        ProtocolEventType.PUBLIC_KEY_SENT,
        ProtocolEventType.PUBLIC_KEY_RECEIVED,
        ProtocolEventType.PUBLIC_KEY_SENT,
        ProtocolEventType.PUBLIC_KEY_RECEIVED,
        ProtocolEventType.SHARED_SECRET_COMPUTED,
        ProtocolEventType.SHARED_SECRET_COMPUTED,
        ProtocolEventType.SHARED_SECRET_VERIFIED,
    ]
    sent = [
        event.data["public_key"]
        for event in session.events
        if event.event_type is ProtocolEventType.PUBLIC_KEY_SENT
    ]
    assert sent == [session.alice_public_key, session.bob_public_key]


def test_session_delivers_every_message(
    parameters: DiffieHellmanParameters,
) -> None:
    """Every recipient decrypts exactly what the sender wrote, in order."""
    session = run_session(
        DiffieHellmanParticipant(parameters),
        DiffieHellmanParticipant(parameters),
        MESSAGES,
        number=1,
    )

    assert [message.sender for message in session.messages] == [
        Actor.ALICE,
        Actor.BOB,
        Actor.ALICE,
    ]
    assert [message.plaintext for message in session.messages] == [
        message.text for message in MESSAGES
    ]
    assert all(message.delivered for message in session.messages)


def test_session_encrypts_under_the_session_key(
    parameters: DiffieHellmanParameters,
) -> None:
    """Ciphertexts hide the text and decrypt with the derived key."""
    session = run_session(
        DiffieHellmanParticipant(parameters),
        DiffieHellmanParticipant(parameters),
        MESSAGES,
        number=1,
    )
    key = session.alice_key_derivation.key

    for message in session.messages:
        plaintext = message.plaintext.encode("ascii")
        assert message.encrypted.ciphertext != plaintext
        assert len(message.encrypted.ciphertext) == len(plaintext)
        assert decrypt(key, message.encrypted) == plaintext


def test_session_nonces_are_unique(parameters: DiffieHellmanParameters) -> None:
    """Every message gets its own random nonce."""
    session = run_session(
        DiffieHellmanParticipant(parameters),
        DiffieHellmanParticipant(parameters),
        MESSAGES,
        number=1,
    )

    nonces = {message.encrypted.nonce for message in session.messages}
    assert len(nonces) == len(MESSAGES)


def test_session_without_messages(parameters: DiffieHellmanParameters) -> None:
    """A session may only agree on a key."""
    session = run_session(
        DiffieHellmanParticipant(parameters),
        DiffieHellmanParticipant(parameters),
        (),
        number=3,
    )

    assert session.number == 3
    assert session.messages == ()
    assert session.keys_match


def test_session_transcript_has_no_private_values(
    parameters: DiffieHellmanParameters,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The public view has public keys and ciphertexts, never keys or texts."""
    fix_private_keys(monkeypatch, 6, 7)
    session = run_session(
        DiffieHellmanParticipant(parameters),
        DiffieHellmanParticipant(parameters),
        MESSAGES,
        number=1,
    )
    transcript = session.transcript

    assert (transcript.alice_public_key, transcript.bob_public_key) == (18, 13)
    assert [message.encrypted for message in transcript.messages] == [
        message.encrypted for message in session.messages
    ]
    assert not hasattr(transcript, "events")
    assert not hasattr(transcript.messages[0], "plaintext")


def test_session_with_compromised_device(parameters: DiffieHellmanParameters) -> None:
    """The device is a drop-in replacement: Bob still reads every message."""
    attacker = YoungYungAttacker.generate(parameters)
    device = YoungYungDiffieHellmanParticipant(
        parameters, attacker.generate_configuration()
    )

    session = run_session(
        device, DiffieHellmanParticipant(parameters), MESSAGES, number=1
    )

    assert session.keys_match
    assert all(message.delivered for message in session.messages)


def test_session_rejects_parameter_mismatch(
    parameters: DiffieHellmanParameters,
) -> None:
    """Different groups fail before any key is generated."""
    alice = DiffieHellmanParticipant(parameters)
    bob = DiffieHellmanParticipant(
        DiffieHellmanParameters(prime=47, generator=2, subgroup_order=23)
    )

    with pytest.raises(DiffieHellmanParametersMismatch):
        run_session(alice, bob, MESSAGES, number=1)

    assert not alice.has_keypair
    assert not bob.has_keypair


def test_session_rejects_invalid_number(parameters: DiffieHellmanParameters) -> None:
    """Session numbers start at 1."""
    with pytest.raises(InvalidChannelSessions):
        run_session(
            DiffieHellmanParticipant(parameters),
            DiffieHellmanParticipant(parameters),
            (),
            number=0,
        )

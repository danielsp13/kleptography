"""Tests for ``run_channel``, a sequence of sessions.

They check the numbering of sessions, fresh keys and session keys for each
one, the transcript of the whole channel, that the device's public keys
pass the same validation as honest ones, and the rejected inputs.

Toy group p = 23, g = 2, q = 11. Honest private keys are fixed by patching the
honest generator; the device's later keys come from the SETUP vectors of
``test_setup_construction.py`` (c1 = 6, t = 0 gives c2 = 4).
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from kleptography.crypto.channel.exceptions import InvalidChannelSessions
from kleptography.crypto.channel.protocol import run_channel
from kleptography.crypto.channel.records import ChannelTranscript, PlainMessage
from kleptography.crypto.dh.exceptions import DiffieHellmanParametersMismatch
from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.participant import DiffieHellmanParticipant
from kleptography.crypto.dh.setup.configuration import YoungYungConfiguration
from kleptography.crypto.dh.setup.participant import (
    YoungYungDiffieHellmanParticipant,
)
from kleptography.crypto.dh.tracing.events import Actor
from kleptography.crypto.dh.validation import validate_public_key
from kleptography.math.modular import mod_pow

SESSIONS = (
    (
        PlainMessage(sender=Actor.ALICE, text="Session one, from Alice."),
        PlainMessage(sender=Actor.BOB, text="Session one, from Bob."),
    ),
    (),
    (PlainMessage(sender=Actor.BOB, text="Session three, from Bob."),),
)


def toy_hash(value: int, *, parameters: DiffieHellmanParameters) -> int:
    """Insecure, readable H for hand-computed test vectors."""
    return value % (parameters.subgroup_order - 1) + 1


@pytest.fixture
def parameters() -> DiffieHellmanParameters:
    """Return the toy group p = 23, g = 2, q = 11."""
    return DiffieHellmanParameters(prime=23, generator=2, subgroup_order=11)


@pytest.fixture
def configuration(parameters: DiffieHellmanParameters) -> YoungYungConfiguration:
    """Return the test-vector configuration with the readable toy H."""
    return YoungYungConfiguration(
        parameters=parameters,
        attacker_public_key=8,
        multiplier_a=2,
        offset_b=2,
        correction_w=3,
        hash_function=toy_hash,
    )


def fix_private_keys(monkeypatch: pytest.MonkeyPatch, *keys: int) -> None:
    """Make honest key generation return ``keys`` in order."""
    sequence: Iterator[int] = iter(keys)

    def next_key(self: DiffieHellmanParticipant) -> int:
        return next(sequence)

    monkeypatch.setattr(DiffieHellmanParticipant, "_generate_private_key", next_key)


def test_channel_runs_one_session_per_entry(
    parameters: DiffieHellmanParameters,
) -> None:
    """Sessions are numbered from 1 and keep their own messages."""
    run = run_channel(
        DiffieHellmanParticipant(parameters),
        DiffieHellmanParticipant(parameters),
        SESSIONS,
    )

    assert run.parameters == parameters
    assert [session.number for session in run.sessions] == [1, 2, 3]
    assert [len(session.messages) for session in run.sessions] == [2, 0, 1]
    assert all(session.keys_match for session in run.sessions)
    assert all(
        message.delivered for session in run.sessions for message in session.messages
    )


def test_channel_uses_fresh_keys_per_session(
    parameters: DiffieHellmanParameters,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each session gets new ephemeral keys, and therefore a new session key."""
    # (a, b) per session: (6, 7) -> s = 6; (2, 3) -> s = 2^6 = 18;
    # (5, 9) -> s = 6^5 = 2.
    fix_private_keys(monkeypatch, 6, 7, 2, 3, 5, 9)
    run = run_channel(
        DiffieHellmanParticipant(parameters),
        DiffieHellmanParticipant(parameters),
        SESSIONS,
    )

    assert [session.alice_public_key for session in run.sessions] == [18, 4, 9]
    assert [session.bob_public_key for session in run.sessions] == [13, 8, 6]
    assert [session.alice_key_derivation.shared_secret for session in run.sessions] == [
        6,
        18,
        2,
    ]
    keys = {session.alice_key_derivation.key for session in run.sessions}
    assert len(keys) == 3


def test_channel_transcript_is_the_public_view(
    parameters: DiffieHellmanParameters,
) -> None:
    """The transcript gathers the public view of every session."""
    run = run_channel(
        DiffieHellmanParticipant(parameters),
        DiffieHellmanParticipant(parameters),
        SESSIONS,
    )

    assert run.transcript == ChannelTranscript(
        parameters=parameters,
        sessions=tuple(session.transcript for session in run.sessions),
    )


def test_channel_with_compromised_device(
    parameters: DiffieHellmanParameters,
    configuration: YoungYungConfiguration,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The device chains its exponents, yet Bob reads every message."""
    fix_private_keys(monkeypatch, 6, 7, 3)
    monkeypatch.setattr(
        YoungYungDiffieHellmanParticipant,
        "_sample_correction_bit",
        lambda self: 0,
    )
    device = YoungYungDiffieHellmanParticipant(parameters, configuration)

    run = run_channel(device, DiffieHellmanParticipant(parameters), SESSIONS[:2])

    # c1 = 6 is honest (m1 = 18); c2 = H(z) = 4 comes from the SETUP (m2 = 16).
    assert [session.alice_public_key for session in run.sessions] == [18, 16]
    derivation = device.last_derivation
    assert derivation is not None
    assert (derivation.previous_private_key, derivation.private_key) == (6, 4)
    assert all(session.keys_match for session in run.sessions)
    assert all(
        message.delivered for session in run.sessions for message in session.messages
    )


def test_device_transcript_passes_honest_validation(
    parameters: DiffieHellmanParameters,
    configuration: YoungYungConfiguration,
) -> None:
    """Device public keys are valid group elements, like honest ones."""
    device = YoungYungDiffieHellmanParticipant(parameters, configuration)

    transcript = run_channel(
        device, DiffieHellmanParticipant(parameters), SESSIONS
    ).transcript

    for session in transcript.sessions:
        for public_key in (session.alice_public_key, session.bob_public_key):
            validate_public_key(
                public_key,
                prime=parameters.prime,
                subgroup_order=parameters.subgroup_order,
            )
            assert mod_pow(public_key, parameters.subgroup_order, parameters.prime) == 1


def test_channel_rejects_no_sessions(parameters: DiffieHellmanParameters) -> None:
    """A channel needs at least one session."""
    with pytest.raises(InvalidChannelSessions):
        run_channel(
            DiffieHellmanParticipant(parameters),
            DiffieHellmanParticipant(parameters),
            (),
        )


def test_channel_rejects_parameter_mismatch(
    parameters: DiffieHellmanParameters,
) -> None:
    """Different groups fail before any session runs."""
    alice = DiffieHellmanParticipant(parameters)
    bob = DiffieHellmanParticipant(
        DiffieHellmanParameters(prime=47, generator=2, subgroup_order=23)
    )

    with pytest.raises(DiffieHellmanParametersMismatch):
        run_channel(alice, bob, SESSIONS)

    assert not alice.has_keypair
    assert not bob.has_keypair

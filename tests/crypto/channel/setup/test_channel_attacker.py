"""
Toy group p = 23, g = 2, q = 11; Y = 8 (X = 3), a = 2, b = 2, W = 3,
H(v) = v mod 10 + 1. Honest keys are fixed by patching the honest generator
(Alice, then Bob, per session); with t = 0 the device chains c1 = 6 → c2 = 4
→ c3 = 4 (A = 18, 16, 16). With Bob's b = 7 (B = 13), s2 = s3 = 13^4 = 18.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import replace

import pytest

from kleptography.crypto.channel.protocol import run_channel
from kleptography.crypto.channel.records import (
    ChannelTranscript,
    PlainMessage,
    SessionTranscript,
)
from kleptography.crypto.channel.setup.attacker import intercept_channel
from kleptography.crypto.channel.setup.records import InterceptionOutcome
from kleptography.crypto.dh.exceptions import (
    DiffieHellmanParametersMismatch,
    InvalidPublicKey,
)
from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.participant import DiffieHellmanParticipant
from kleptography.crypto.dh.setup.attacker import YoungYungAttacker
from kleptography.crypto.dh.setup.configuration import YoungYungConfiguration
from kleptography.crypto.dh.setup.exceptions import InvalidSetupConfiguration
from kleptography.crypto.dh.setup.participant import (
    YoungYungDiffieHellmanParticipant,
)
from kleptography.crypto.dh.tracing.events import Actor
from kleptography.crypto.kdf.one_step import OTHER_INFO

SESSIONS = (
    (
        PlainMessage(sender=Actor.ALICE, text="Session one, from Alice."),
        PlainMessage(sender=Actor.BOB, text="Session one, from Bob."),
    ),
    (
        PlainMessage(sender=Actor.ALICE, text="Session two, from Alice."),
        PlainMessage(sender=Actor.BOB, text="Session two, from Bob."),
    ),
    (),
    (PlainMessage(sender=Actor.BOB, text="Session four, from Bob."),),
)


def toy_hash(value: int, *, parameters: DiffieHellmanParameters) -> int:
    """Insecure, readable H for hand-computed test vectors."""
    return value % (parameters.subgroup_order - 1) + 1


@pytest.fixture
def parameters() -> DiffieHellmanParameters:
    return DiffieHellmanParameters(prime=23, generator=2, subgroup_order=11)


@pytest.fixture
def attacker(parameters: DiffieHellmanParameters) -> YoungYungAttacker:
    return YoungYungAttacker(parameters, 3)


@pytest.fixture
def configuration(parameters: DiffieHellmanParameters) -> YoungYungConfiguration:
    return YoungYungConfiguration(
        parameters=parameters,
        attacker_public_key=8,
        multiplier_a=2,
        offset_b=2,
        correction_w=3,
        hash_function=toy_hash,
    )


def fix_private_keys(monkeypatch: pytest.MonkeyPatch, *keys: int) -> None:
    sequence: Iterator[int] = iter(keys)

    def next_key(self: DiffieHellmanParticipant) -> int:
        return next(sequence)

    monkeypatch.setattr(DiffieHellmanParticipant, "_generate_private_key", next_key)


def force_correction_bit(monkeypatch: pytest.MonkeyPatch, correction_bit: int) -> None:
    monkeypatch.setattr(
        YoungYungDiffieHellmanParticipant,
        "_sample_correction_bit",
        lambda self: correction_bit,
    )


def test_attacker_reads_every_session_but_the_first(
    parameters: DiffieHellmanParameters,
    attacker: YoungYungAttacker,
    configuration: YoungYungConfiguration,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fix_private_keys(monkeypatch, 6, 7, 7, 7)
    force_correction_bit(monkeypatch, 0)
    device = YoungYungDiffieHellmanParticipant(parameters, configuration)

    run = run_channel(device, DiffieHellmanParticipant(parameters), SESSIONS[:3])
    interception = intercept_channel(
        run.transcript, attacker=attacker, configuration=configuration
    )

    assert interception.parameters == parameters
    assert [session.outcome for session in interception.sessions] == [
        InterceptionOutcome.NOT_RECOVERABLE,
        InterceptionOutcome.RECOVERED,
        InterceptionOutcome.RECOVERED,
    ]
    first, second, third = interception.sessions
    assert first.recovery is None
    assert [message.plaintext for message in first.messages] == [None, None]

    assert second.recovery is not None
    assert second.recovery.private_key == 4
    assert second.recovery.correction_bit == 0
    assert second.shared_secret == 18
    assert second.key_derivation is not None
    expected_key = hashlib.sha256(b"\x00\x00\x00\x01" + bytes([18]) + OTHER_INFO)
    assert second.key_derivation.key == expected_key.digest()
    assert [message.plaintext for message in second.messages] == [
        "Session two, from Alice.",
        "Session two, from Bob.",
    ]

    # Session 3 has no messages, but its key is recovered all the same.
    assert third.recovery is not None
    assert third.recovery.private_key == 4
    assert third.messages == ()
    assert third.readable


def test_attacker_matches_the_device_and_alice_with_a_real_hash() -> None:
    """Every recovered value is the one the device and Alice really used."""
    parameters = DiffieHellmanParameters.generate_toy(32)
    attacker = YoungYungAttacker.generate(parameters)
    configuration = attacker.generate_configuration()
    device = YoungYungDiffieHellmanParticipant(parameters, configuration)

    run = run_channel(device, DiffieHellmanParticipant(parameters), SESSIONS)
    interception = intercept_channel(
        run.transcript, attacker=attacker, configuration=configuration
    )

    assert not interception.sessions[0].recovered
    for number, (session, intercepted) in enumerate(
        zip(run.sessions[1:], interception.sessions[1:]), start=2
    ):
        derivation = device.derivations[number - 2]
        assert intercepted.recovery is not None
        assert intercepted.recovery.private_key == derivation.private_key
        assert intercepted.recovery.correction_bit == derivation.correction_bit
        assert intercepted.key_derivation == session.alice_key_derivation
        assert [message.plaintext for message in intercepted.messages] == [
            message.plaintext for message in session.messages
        ]
        assert intercepted.readable


def test_attacker_reads_nothing_from_an_honest_alice(
    parameters: DiffieHellmanParameters,
    attacker: YoungYungAttacker,
    configuration: YoungYungConfiguration,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Alice's keys 6, 5, 9: neither 5 nor 9 is a SETUP candidate of the last."""
    fix_private_keys(monkeypatch, 6, 7, 5, 7, 9, 7)

    run = run_channel(
        DiffieHellmanParticipant(parameters),
        DiffieHellmanParticipant(parameters),
        SESSIONS[:3],
    )
    interception = intercept_channel(
        run.transcript, attacker=attacker, configuration=configuration
    )

    assert [session.outcome for session in interception.sessions] == [
        InterceptionOutcome.NOT_RECOVERABLE,
        InterceptionOutcome.RECOVERY_FAILED,
        InterceptionOutcome.RECOVERY_FAILED,
    ]
    # The candidates are still computed: they just do not reproduce A_i.
    second = interception.sessions[1]
    assert second.candidates is not None
    assert second.candidates.private_key_candidates == (4, 10)
    assert interception.sessions[0].candidates is None
    assert interception.sessions[2].candidates is not None
    for session in interception.sessions:
        assert session.recovery is None
        assert session.shared_secret is None
        assert session.key_derivation is None
        assert not any(message.readable for message in session.messages)


def test_honest_alice_in_a_toy_group_can_match_by_chance(
    parameters: DiffieHellmanParameters,
    attacker: YoungYungAttacker,
    configuration: YoungYungConfiguration,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With q = 11, an honest a2 = 10 equals a candidate of a1 = 6 (t = 1).

    A matching candidate is a2 itself, so the attacker really reads the
    session: in a toy group, the SETUP and luck are indistinguishable.
    """
    fix_private_keys(monkeypatch, 6, 7, 10, 7)

    run = run_channel(
        DiffieHellmanParticipant(parameters),
        DiffieHellmanParticipant(parameters),
        SESSIONS[:2],
    )
    second = intercept_channel(
        run.transcript, attacker=attacker, configuration=configuration
    ).sessions[1]

    assert second.recovered
    assert second.recovery is not None
    assert second.recovery.correction_bit == 1
    assert second.key_derivation == run.sessions[1].alice_key_derivation
    assert second.readable


def test_tampered_message_is_not_readable(
    parameters: DiffieHellmanParameters,
    attacker: YoungYungAttacker,
    configuration: YoungYungConfiguration,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The key is recovered, but the GCM tag rejects a modified ciphertext."""
    fix_private_keys(monkeypatch, 6, 7, 7)
    force_correction_bit(monkeypatch, 0)
    device = YoungYungDiffieHellmanParticipant(parameters, configuration)
    transcript = run_channel(
        device, DiffieHellmanParticipant(parameters), SESSIONS[:2]
    ).transcript

    second = transcript.sessions[1]
    first_message = second.messages[0]
    ciphertext = bytes([first_message.encrypted.ciphertext[0] ^ 1])
    tampered = replace(
        first_message,
        encrypted=replace(
            first_message.encrypted,
            ciphertext=ciphertext + first_message.encrypted.ciphertext[1:],
        ),
    )
    transcript = replace(
        transcript,
        sessions=(
            transcript.sessions[0],
            replace(second, messages=(tampered, *second.messages[1:])),
        ),
    )

    intercepted = intercept_channel(
        transcript, attacker=attacker, configuration=configuration
    ).sessions[1]

    assert intercepted.recovered
    assert [message.plaintext for message in intercepted.messages] == [
        None,
        "Session two, from Bob.",
    ]
    assert not intercepted.readable


def test_single_session_channel_reveals_nothing(
    parameters: DiffieHellmanParameters,
    attacker: YoungYungAttacker,
    configuration: YoungYungConfiguration,
) -> None:
    device = YoungYungDiffieHellmanParticipant(parameters, configuration)
    transcript = run_channel(
        device, DiffieHellmanParticipant(parameters), SESSIONS[:1]
    ).transcript

    interception = intercept_channel(
        transcript, attacker=attacker, configuration=configuration
    )

    assert len(interception.sessions) == 1
    assert interception.sessions[0].outcome is InterceptionOutcome.NOT_RECOVERABLE


def test_configuration_of_another_attacker_is_rejected(
    parameters: DiffieHellmanParameters,
    configuration: YoungYungConfiguration,
) -> None:
    """Checked before any session, even when there is nothing to recover."""
    transcript = ChannelTranscript(
        parameters=parameters,
        sessions=(
            SessionTranscript(
                number=1, alice_public_key=18, bob_public_key=13, messages=()
            ),
        ),
    )

    with pytest.raises(InvalidSetupConfiguration):
        intercept_channel(
            transcript,
            attacker=YoungYungAttacker(parameters, 4),
            configuration=configuration,
        )


def test_configuration_for_another_group_is_rejected(
    parameters: DiffieHellmanParameters,
    configuration: YoungYungConfiguration,
) -> None:
    other = DiffieHellmanParameters(prime=47, generator=2, subgroup_order=23)
    other_attacker = YoungYungAttacker(other, 3)
    transcript = ChannelTranscript(
        parameters=parameters,
        sessions=(
            SessionTranscript(
                number=1, alice_public_key=18, bob_public_key=13, messages=()
            ),
        ),
    )

    with pytest.raises(InvalidSetupConfiguration):
        intercept_channel(
            transcript, attacker=other_attacker, configuration=configuration
        )


def test_transcript_of_another_group_is_rejected(
    attacker: YoungYungAttacker,
    configuration: YoungYungConfiguration,
) -> None:
    other = DiffieHellmanParameters(prime=47, generator=2, subgroup_order=23)
    transcript = ChannelTranscript(
        parameters=other,
        sessions=(
            SessionTranscript(
                number=1, alice_public_key=2, bob_public_key=4, messages=()
            ),
        ),
    )

    with pytest.raises(DiffieHellmanParametersMismatch):
        intercept_channel(transcript, attacker=attacker, configuration=configuration)


@pytest.mark.parametrize(
    ("alice_public_keys", "bob_public_key"),
    [((18, 16), 1), ((18, 16), 5), ((18, 5), 13), ((5, 16), 13)],
    ids=["bob-one", "bob-outside-subgroup", "alice-second", "alice-first"],
)
def test_invalid_public_keys_are_rejected(
    parameters: DiffieHellmanParameters,
    attacker: YoungYungAttacker,
    configuration: YoungYungConfiguration,
    alice_public_keys: tuple[int, int],
    bob_public_key: int,
) -> None:
    """5 is not a quadratic residue mod 23, so it is outside the subgroup."""
    transcript = ChannelTranscript(
        parameters=parameters,
        sessions=(
            SessionTranscript(
                number=1,
                alice_public_key=alice_public_keys[0],
                bob_public_key=13,
                messages=(),
            ),
            SessionTranscript(
                number=2,
                alice_public_key=alice_public_keys[1],
                bob_public_key=bob_public_key,
                messages=(),
            ),
        ),
    )

    with pytest.raises(InvalidPublicKey):
        intercept_channel(transcript, attacker=attacker, configuration=configuration)

"""
Test vectors: see ``test_setup_construction.py``.

Toy group p = 23, g = 2, q = 11; X = 3, Y = 8, a = 2, b = 2, W = 3,
H(v) = v mod 10 + 1. m1 = 18. t = 0 gives c2 = 4 (m2 = 16) and t = 1 gives
c2 = 10 (m2 = 12). Honest peer b = 7, B = 13: B^4 = 18 and B^10 = 16.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from kleptography.crypto.dh.exceptions import InvalidPrivateKey, InvalidPublicKey
from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.participant import DiffieHellmanParticipant
from kleptography.crypto.dh.protocol import perform_key_exchange
from kleptography.crypto.dh.setup.attacker import YoungYungAttacker
from kleptography.crypto.dh.setup.configuration import YoungYungConfiguration
from kleptography.crypto.dh.setup.exceptions import (
    InvalidSetupConfiguration,
    SetupRecoveryError,
)
from kleptography.crypto.dh.setup.participant import (
    YoungYungDiffieHellmanParticipant,
)
from kleptography.crypto.dh.tracing.context import ProtocolExecutionContext
from kleptography.crypto.dh.tracing.events import Actor, ProtocolEventType


def toy_hash(value: int, *, parameters: DiffieHellmanParameters) -> int:
    """Insecure, readable H for hand-computed test vectors."""
    return value % (parameters.subgroup_order - 1) + 1


@pytest.fixture
def parameters() -> DiffieHellmanParameters:
    return DiffieHellmanParameters(prime=23, generator=2, subgroup_order=11)


@pytest.fixture
def attacker(parameters: DiffieHellmanParameters) -> YoungYungAttacker:
    return YoungYungAttacker(parameters, 3)


def build_configuration(
    parameters: DiffieHellmanParameters,
    attacker_public_key: int = 8,
) -> YoungYungConfiguration:
    return YoungYungConfiguration(
        parameters=parameters,
        attacker_public_key=attacker_public_key,
        multiplier_a=2,
        offset_b=2,
        correction_w=3,
        hash_function=toy_hash,
    )


@pytest.fixture
def configuration(parameters: DiffieHellmanParameters) -> YoungYungConfiguration:
    return build_configuration(parameters)


def test_attacker_public_key(attacker: YoungYungAttacker) -> None:
    assert attacker.private_key == 3
    assert attacker.public_key == 8


@pytest.mark.parametrize("private_key", [0, 11, -1])
def test_attacker_rejects_invalid_private_key(
    parameters: DiffieHellmanParameters,
    private_key: int,
) -> None:
    with pytest.raises(InvalidPrivateKey):
        YoungYungAttacker(parameters, private_key)


def test_attacker_repr_hides_private_key(attacker: YoungYungAttacker) -> None:
    assert "private_key" not in repr(attacker)


def test_attacker_is_frozen(attacker: YoungYungAttacker) -> None:
    with pytest.raises(FrozenInstanceError):
        attacker.private_key = 4  # ty: ignore[invalid-assignment]


def test_generate_attacker() -> None:
    parameters = DiffieHellmanParameters.generate_toy(bits=32)

    attacker = YoungYungAttacker.generate(parameters)
    other = YoungYungAttacker.generate(parameters)

    assert attacker.parameters is parameters
    assert 1 <= attacker.private_key < parameters.subgroup_order
    assert attacker.public_key == pow(
        parameters.generator, attacker.private_key, parameters.prime
    )
    assert attacker.private_key != other.private_key


@pytest.mark.parametrize(("second_public_key", "expected_key"), [(16, 4), (12, 10)])
def test_recover_private_key_matches_test_vector(
    attacker: YoungYungAttacker,
    configuration: YoungYungConfiguration,
    second_public_key: int,
    expected_key: int,
) -> None:
    """Both branches of the recovery: t = 0 (z1) and t = 1 (z2)."""
    private_key = attacker.recover_private_key(
        first_public_key=18,
        second_public_key=second_public_key,
        configuration=configuration,
    )

    assert private_key == expected_key


def test_recover_private_key_fails_for_unrelated_output(
    attacker: YoungYungAttacker,
    configuration: YoungYungConfiguration,
) -> None:
    """m2 = 2 = g^1 was not derived from m1 = 18."""
    with pytest.raises(SetupRecoveryError):
        attacker.recover_private_key(
            first_public_key=18,
            second_public_key=2,
            configuration=configuration,
        )


@pytest.mark.parametrize(
    ("first_public_key", "second_public_key"),
    [(1, 16), (5, 16), (18, 0), (18, 22)],
)
def test_recover_private_key_rejects_invalid_public_keys(
    attacker: YoungYungAttacker,
    configuration: YoungYungConfiguration,
    first_public_key: int,
    second_public_key: int,
) -> None:
    with pytest.raises(InvalidPublicKey):
        attacker.recover_private_key(
            first_public_key=first_public_key,
            second_public_key=second_public_key,
            configuration=configuration,
        )


def test_recover_private_key_rejects_foreign_configuration(
    attacker: YoungYungAttacker,
    parameters: DiffieHellmanParameters,
) -> None:
    """A device built with another attacker key (Y = 4) is not ours."""
    foreign_configuration = build_configuration(parameters, attacker_public_key=4)

    with pytest.raises(InvalidSetupConfiguration):
        attacker.recover_private_key(
            first_public_key=18,
            second_public_key=16,
            configuration=foreign_configuration,
        )


@pytest.mark.parametrize(
    ("second_public_key", "expected_secret"),
    [(16, 18), (12, 16)],
)
def test_recover_shared_secret_matches_test_vector(
    attacker: YoungYungAttacker,
    configuration: YoungYungConfiguration,
    second_public_key: int,
    expected_secret: int,
) -> None:
    shared_secret = attacker.recover_shared_secret(
        first_public_key=18,
        second_public_key=second_public_key,
        peer_public_key=13,
        configuration=configuration,
    )

    assert shared_secret == expected_secret


def test_recover_shared_secret_rejects_invalid_peer_key(
    attacker: YoungYungAttacker,
    configuration: YoungYungConfiguration,
) -> None:
    with pytest.raises(InvalidPublicKey):
        attacker.recover_shared_secret(
            first_public_key=18,
            second_public_key=16,
            peer_public_key=5,
            configuration=configuration,
        )


def sent_public_keys(context: ProtocolExecutionContext) -> dict[Actor, int]:
    """Public values seen on the channel, as an eavesdropper sees them."""
    public_keys: dict[Actor, int] = {}
    for event in context.events:
        if event.event_type is ProtocolEventType.PUBLIC_KEY_SENT:
            public_key = event.data["public_key"]
            assert isinstance(public_key, int)
            public_keys[event.actor] = public_key
    return public_keys


@pytest.mark.parametrize("repetition", range(10))
def test_attacker_recovers_second_exchange_from_channel(repetition: int) -> None:
    """
    End to end with the default H: the attacker only reads the channel.

    Ten repetitions exercise both values of t with high probability.
    """
    parameters = DiffieHellmanParameters.generate_toy(bits=32)
    attacker = YoungYungAttacker.generate(parameters)
    configuration = YoungYungConfiguration(
        parameters=parameters,
        attacker_public_key=attacker.public_key,
        multiplier_a=7,
        offset_b=11,
        correction_w=3,
    )
    device = YoungYungDiffieHellmanParticipant(parameters, configuration)

    first_context = ProtocolExecutionContext()
    perform_key_exchange(
        device, DiffieHellmanParticipant(parameters), observer=first_context
    )
    device.generate_keypair()
    second_context = ProtocolExecutionContext()
    second = perform_key_exchange(
        device, DiffieHellmanParticipant(parameters), observer=second_context
    )

    first_channel = sent_public_keys(first_context)
    second_channel = sent_public_keys(second_context)

    recovered_key = attacker.recover_private_key(
        first_public_key=first_channel[Actor.ALICE],
        second_public_key=second_channel[Actor.ALICE],
        configuration=configuration,
    )
    recovered_secret = attacker.recover_shared_secret(
        first_public_key=first_channel[Actor.ALICE],
        second_public_key=second_channel[Actor.ALICE],
        peer_public_key=second_channel[Actor.BOB],
        configuration=configuration,
    )

    assert recovered_key == device.private_key
    assert recovered_secret == second.alice_shared_secret == second.bob_shared_secret


def test_attacker_cannot_recover_from_honest_participant() -> None:
    """
    Without the SETUP, consecutive exponents are independent.

    The recovery only succeeds by chance (probability about 2 / q).
    """
    parameters = DiffieHellmanParameters.generate_toy(bits=32)
    attacker = YoungYungAttacker.generate(parameters)
    configuration = YoungYungConfiguration(
        parameters=parameters,
        attacker_public_key=attacker.public_key,
        multiplier_a=7,
        offset_b=11,
        correction_w=3,
    )
    honest = DiffieHellmanParticipant(parameters)

    honest.generate_keypair()
    first_public_key = honest.public_key
    honest.generate_keypair()
    second_public_key = honest.public_key

    assert first_public_key is not None
    assert second_public_key is not None

    with pytest.raises(SetupRecoveryError):
        attacker.recover_private_key(
            first_public_key=first_public_key,
            second_public_key=second_public_key,
            configuration=configuration,
        )

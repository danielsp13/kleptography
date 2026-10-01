"""Tests for ``YoungYungAttacker``, who holds the trapdoor X.

They check the key pair, generated configurations, the recovery of c2 and
of the second shared secret with all its intermediate values, an
end-to-end run with random parameters, and every rejected input.

Test vectors: see ``test_setup_construction.py``.

Toy group p = 23, g = 2, q = 11; X = 3, Y = 8, a = 2, b = 2, W = 3,
H(v) = v mod 10 + 1. m1 = 18. t = 0 gives c2 = 4 (m2 = 16) and t = 1 gives
c2 = 10 (m2 = 12). Honest peer b = 7, B = 13: B^4 = 18 and B^10 = 16.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from kleptography.crypto.dh.exceptions import InvalidPrivateKey, InvalidPublicKey
from kleptography.crypto.dh.groups.rfc7919 import ffdhe2048
from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.participant import DiffieHellmanParticipant
from kleptography.crypto.dh.protocol import perform_key_exchange
from kleptography.crypto.dh.setup.attacker import YoungYungAttacker
from kleptography.crypto.dh.setup.configuration import YoungYungConfiguration
from kleptography.crypto.dh.setup.exceptions import (
    InvalidSetupConfiguration,
    SetupRecoveryError,
)
from kleptography.crypto.dh.setup.hashing import hash_to_exponent
from kleptography.crypto.dh.setup.participant import (
    YoungYungDiffieHellmanParticipant,
)
from kleptography.crypto.dh.setup.records import SetupCandidates, SetupRecovery
from kleptography.crypto.dh.tracing.context import ProtocolExecutionContext
from kleptography.crypto.dh.tracing.events import Actor, ProtocolEventType


def toy_hash(value: int, *, parameters: DiffieHellmanParameters) -> int:
    """Insecure, readable H for hand-computed test vectors."""
    return value % (parameters.subgroup_order - 1) + 1


@pytest.fixture
def parameters() -> DiffieHellmanParameters:
    """Return the toy group p = 23, g = 2, q = 11."""
    return DiffieHellmanParameters(prime=23, generator=2, subgroup_order=11)


@pytest.fixture
def attacker(parameters: DiffieHellmanParameters) -> YoungYungAttacker:
    """Return the attacker with X = 3 (Y = 8)."""
    return YoungYungAttacker(parameters, 3)


def build_configuration(
    parameters: DiffieHellmanParameters,
    attacker_public_key: int = 8,
) -> YoungYungConfiguration:
    """Return the test-vector configuration, embedding ``attacker_public_key``."""
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
    """Return the test-vector configuration of the toy group."""
    return build_configuration(parameters)


def test_attacker_public_key(attacker: YoungYungAttacker) -> None:
    """The attacker's public key is Y = g^X mod p."""
    assert attacker.private_key == 3
    assert attacker.public_key == 8


@pytest.mark.parametrize("private_key", [0, 11, -1])
def test_attacker_rejects_invalid_private_key(
    parameters: DiffieHellmanParameters,
    private_key: int,
) -> None:
    """A private key outside [1, q - 1] is rejected."""
    with pytest.raises(InvalidPrivateKey):
        YoungYungAttacker(parameters, private_key)


def test_attacker_repr_hides_private_key(attacker: YoungYungAttacker) -> None:
    """The private key X does not leak through repr."""
    assert "private_key" not in repr(attacker)


def test_attacker_is_frozen(attacker: YoungYungAttacker) -> None:
    """The attacker cannot be modified."""
    with pytest.raises(FrozenInstanceError):
        attacker.private_key = 4  # ty: ignore[invalid-assignment]


def test_generate_attacker() -> None:
    """A generated attacker has a valid, random key pair."""
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
    """Invalid public keys from the device are rejected."""
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
    """The recovered shared secret matches the test vector."""
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
    """An invalid public key from the peer is rejected."""
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
    """End to end with the default H: the attacker only reads the channel.

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
    """Without the SETUP, consecutive exponents are independent.

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


# --- Complementary tests -----------------------------------------------------


def reference_second_key(
    previous_private_key: int,
    correction_bit: int,
    configuration: YoungYungConfiguration,
) -> int:
    """c2 = H(g^(c1 - W*t) * Y^(-a*c1 - b) mod p), computed independently."""
    parameters = configuration.parameters
    prime = parameters.prime
    z = (
        pow(
            parameters.generator,
            previous_private_key - configuration.correction_w * correction_bit,
            prime,
        )
        * pow(
            configuration.attacker_public_key,
            -configuration.multiplier_a * previous_private_key - configuration.offset_b,
            prime,
        )
        % prime
    )
    return configuration.hash_function(z, parameters=parameters)


@pytest.mark.parametrize("private_key", range(1, 11))
def test_attacker_public_key_for_every_private_key(
    parameters: DiffieHellmanParameters,
    private_key: int,
) -> None:
    """Y = g^X mod p for every X of the toy group."""
    attacker = YoungYungAttacker(parameters, private_key)

    assert attacker.public_key == pow(2, private_key, 23)


@pytest.fixture
def larger_parameters() -> DiffieHellmanParameters:
    """Return the group p = 47, g = 2, q = 23."""
    return DiffieHellmanParameters(prime=47, generator=2, subgroup_order=23)


@pytest.mark.parametrize("private_key", [11, 15, 22])
def test_attacker_validates_private_key_in_its_own_group(
    larger_parameters: DiffieHellmanParameters,
    private_key: int,
) -> None:
    """The private key range is that of the attacker's group."""
    attacker = YoungYungAttacker(larger_parameters, private_key)

    assert attacker.public_key == pow(2, private_key, 47)


def test_attacker_rejects_private_key_equal_to_its_group_order(
    larger_parameters: DiffieHellmanParameters,
) -> None:
    """X = q is rejected in a larger group."""
    with pytest.raises(InvalidPrivateKey):
        YoungYungAttacker(larger_parameters, 23)


def test_generate_attacker_returns_valid_attacker(
    parameters: DiffieHellmanParameters,
) -> None:
    """Generated attackers have valid and varied private keys."""
    private_keys = set()
    for _ in range(64):
        attacker = YoungYungAttacker.generate(parameters)

        assert isinstance(attacker, YoungYungAttacker)
        assert 1 <= attacker.private_key < parameters.subgroup_order
        private_keys.add(attacker.private_key)

    assert len(private_keys) > 1


@pytest.mark.parametrize("attacker_private_key", range(1, 11))
@pytest.mark.parametrize("correction_bit", [0, 1])
def test_recovery_for_every_first_exponent(
    parameters: DiffieHellmanParameters,
    attacker_private_key: int,
    correction_bit: int,
) -> None:
    """Every X, c1 and t of the toy group, with the toy H."""
    attacker = YoungYungAttacker(parameters, attacker_private_key)
    configuration = build_configuration(
        parameters, attacker_public_key=pow(2, attacker_private_key, 23)
    )

    for previous_private_key in range(1, 11):
        first_public_key = pow(2, previous_private_key, 23)
        second_private_key = reference_second_key(
            previous_private_key, correction_bit, configuration
        )
        second_public_key = pow(2, second_private_key, 23)

        recovered_key = attacker.recover_private_key(
            first_public_key=first_public_key,
            second_public_key=second_public_key,
            configuration=configuration,
        )
        recovered_secret = attacker.recover_shared_secret(
            first_public_key=first_public_key,
            second_public_key=second_public_key,
            peer_public_key=13,
            configuration=configuration,
        )

        assert type(recovered_key) is int
        assert recovered_key == second_private_key
        assert recovered_secret == pow(13, second_private_key, 23)


@pytest.mark.parametrize("correction_bit", [0, 1])
def test_recovery_in_larger_group(
    larger_parameters: DiffieHellmanParameters,
    correction_bit: int,
) -> None:
    """Public values above 23 must be validated against p = 47."""
    attacker = YoungYungAttacker(larger_parameters, 15)
    configuration = YoungYungConfiguration(
        parameters=larger_parameters,
        attacker_public_key=pow(2, 15, 47),
        multiplier_a=3,
        offset_b=5,
        correction_w=7,
        hash_function=toy_hash,
    )
    peer_public_key = pow(2, 9, 47)

    for previous_private_key in range(1, 23):
        second_private_key = reference_second_key(
            previous_private_key, correction_bit, configuration
        )

        recovered_secret = attacker.recover_shared_secret(
            first_public_key=pow(2, previous_private_key, 47),
            second_public_key=pow(2, second_private_key, 47),
            peer_public_key=peer_public_key,
            configuration=configuration,
        )

        assert recovered_secret == pow(peer_public_key, second_private_key, 47)


@pytest.mark.parametrize(
    ("first_public_key", "second_public_key"),
    [(1, 16), (5, 16), (18, 0), (18, 22)],
)
def test_recover_shared_secret_rejects_invalid_device_keys(
    attacker: YoungYungAttacker,
    configuration: YoungYungConfiguration,
    first_public_key: int,
    second_public_key: int,
) -> None:
    """Invalid public keys from the device are rejected."""
    with pytest.raises(InvalidPublicKey):
        attacker.recover_shared_secret(
            first_public_key=first_public_key,
            second_public_key=second_public_key,
            peer_public_key=13,
            configuration=configuration,
        )


def test_recover_shared_secret_rejects_foreign_configuration(
    attacker: YoungYungAttacker,
    parameters: DiffieHellmanParameters,
) -> None:
    """A configuration with another attacker's Y is rejected."""
    foreign_configuration = build_configuration(parameters, attacker_public_key=4)

    with pytest.raises(InvalidSetupConfiguration):
        attacker.recover_shared_secret(
            first_public_key=18,
            second_public_key=16,
            peer_public_key=13,
            configuration=foreign_configuration,
        )


def test_recover_shared_secret_fails_for_unrelated_output(
    attacker: YoungYungAttacker,
    configuration: YoungYungConfiguration,
) -> None:
    """A second key not derived by the SETUP raises SetupRecoveryError."""
    with pytest.raises(SetupRecoveryError):
        attacker.recover_shared_secret(
            first_public_key=18,
            second_public_key=2,
            peer_public_key=13,
            configuration=configuration,
        )


def test_recover_private_key_fails_when_outputs_are_swapped(
    attacker: YoungYungAttacker,
    configuration: YoungYungConfiguration,
) -> None:
    """The recovery goes from m1 to m2, not backwards (m2 = 16 -> m1 = 18)."""
    with pytest.raises(SetupRecoveryError):
        attacker.recover_private_key(
            first_public_key=16,
            second_public_key=18,
            configuration=configuration,
        )


@pytest.mark.parametrize("correction_bit", [0, 1])
def test_attacker_recovers_second_exchange_in_rfc_group(
    monkeypatch: pytest.MonkeyPatch,
    correction_bit: int,
) -> None:
    """End to end with a 2048-bit standardized group and the default H."""
    monkeypatch.setattr(
        YoungYungDiffieHellmanParticipant,
        "_sample_correction_bit",
        lambda self: correction_bit,
    )
    parameters = ffdhe2048()
    attacker = YoungYungAttacker.generate(parameters)
    configuration = YoungYungConfiguration(
        parameters=parameters,
        attacker_public_key=attacker.public_key,
        multiplier_a=7,
        offset_b=11,
        correction_w=3,
    )
    device = YoungYungDiffieHellmanParticipant(parameters, configuration)

    perform_key_exchange(device, DiffieHellmanParticipant(parameters))
    first_public_key = device.public_key
    device.generate_keypair()
    peer = DiffieHellmanParticipant(parameters)
    second = perform_key_exchange(device, peer)

    assert first_public_key is not None
    assert device.public_key is not None
    assert peer.public_key is not None

    recovered_secret = attacker.recover_shared_secret(
        first_public_key=first_public_key,
        second_public_key=device.public_key,
        peer_public_key=peer.public_key,
        configuration=configuration,
    )

    assert recovered_secret == second.alice_shared_secret


@pytest.mark.parametrize(
    ("second_public_key", "expected_bit", "expected_key"),
    [(16, 0, 4), (12, 1, 10)],
)
def test_recover_records_intermediate_values(
    attacker: YoungYungAttacker,
    configuration: YoungYungConfiguration,
    second_public_key: int,
    expected_bit: int,
    expected_key: int,
) -> None:
    """The recovery exposes r, both candidates, t and c2."""
    recovery = attacker.recover(
        first_public_key=18,
        second_public_key=second_public_key,
        configuration=configuration,
    )

    assert recovery == SetupRecovery(
        first_public_key=18,
        second_public_key=second_public_key,
        r=8,
        z_candidates=(3, 9),
        private_key_candidates=(4, 10),
        correction_bit=expected_bit,
        private_key=expected_key,
    )


def test_recover_raises_like_recover_private_key(
    attacker: YoungYungAttacker,
    configuration: YoungYungConfiguration,
    parameters: DiffieHellmanParameters,
) -> None:
    """The method recover raises the same errors as recover_private_key."""
    with pytest.raises(SetupRecoveryError):
        attacker.recover(
            first_public_key=18, second_public_key=2, configuration=configuration
        )
    with pytest.raises(InvalidPublicKey):
        attacker.recover(
            first_public_key=5, second_public_key=16, configuration=configuration
        )
    with pytest.raises(InvalidSetupConfiguration):
        attacker.recover(
            first_public_key=18,
            second_public_key=16,
            configuration=build_configuration(parameters, attacker_public_key=4),
        )


def test_recover_rejects_configuration_of_another_group(
    attacker: YoungYungAttacker,
) -> None:
    """A configuration for another group is rejected."""
    other_parameters = DiffieHellmanParameters(prime=47, generator=2, subgroup_order=23)
    other_configuration = build_configuration(other_parameters, attacker_public_key=8)

    with pytest.raises(InvalidSetupConfiguration):
        attacker.recover(
            first_public_key=18,
            second_public_key=16,
            configuration=other_configuration,
        )


def test_recovered_bit_matches_device_bit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The attacker learns t too (unless H(z1) and H(z2) collide)."""
    parameters = DiffieHellmanParameters.generate_toy(bits=32)
    attacker = YoungYungAttacker.generate(parameters)
    configuration = attacker.generate_configuration()

    for correction_bit in (0, 1):
        monkeypatch.setattr(
            YoungYungDiffieHellmanParticipant,
            "_sample_correction_bit",
            lambda self, bit=correction_bit: bit,
        )
        device = YoungYungDiffieHellmanParticipant(parameters, configuration)
        device.generate_keypair()
        first_public_key = device.public_key
        device.generate_keypair()
        derivation = device.last_derivation

        assert first_public_key is not None
        assert device.public_key is not None
        assert derivation is not None

        recovery = attacker.recover(
            first_public_key=first_public_key,
            second_public_key=device.public_key,
            configuration=configuration,
        )

        assert recovery.correction_bit == derivation.correction_bit
        assert recovery.z_candidates[correction_bit] == derivation.z
        assert recovery.private_key == derivation.private_key


def test_generate_configuration_embeds_attacker_key(
    attacker: YoungYungAttacker,
    parameters: DiffieHellmanParameters,
) -> None:
    """Generated configurations embed Y and valid constants."""
    for _ in range(64):
        configuration = attacker.generate_configuration()

        assert configuration.parameters is parameters
        assert configuration.attacker_public_key == attacker.public_key
        assert configuration.hash_function is hash_to_exponent
        assert 1 <= configuration.multiplier_a < 11
        assert configuration.multiplier_a * 3 % 11 != 1
        assert 1 <= configuration.offset_b < 11
        assert 1 <= configuration.correction_w < 11
        assert configuration.correction_w % 2 == 1


def test_generate_configuration_skips_degenerate_multiplier(
    attacker: YoungYungAttacker,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """X = 3 and a = 4 give a*X = 12 = 1 (mod 11), so a is sampled again."""
    samples = iter([3, 0, 5, 1])
    monkeypatch.setattr(
        "kleptography.crypto.dh.setup.attacker.randbelow",
        lambda upper: next(samples),
    )

    configuration = attacker.generate_configuration()

    assert configuration.multiplier_a == 1
    assert configuration.offset_b == 6
    assert configuration.correction_w == 3


def test_generate_configuration_uses_given_hash(
    attacker: YoungYungAttacker,
) -> None:
    """A generated configuration uses the given hash function."""
    configuration = attacker.generate_configuration(hash_function=toy_hash)

    assert configuration.hash_function is toy_hash


def test_generate_configuration_rejects_tiny_group() -> None:
    """A group with q < 3 cannot hold a SETUP."""
    parameters = DiffieHellmanParameters(prime=5, generator=4, subgroup_order=2)
    attacker = YoungYungAttacker(parameters, 1)

    with pytest.raises(InvalidSetupConfiguration):
        attacker.generate_configuration()


@pytest.mark.parametrize("repetition", range(5))
def test_generated_configuration_works_end_to_end(repetition: int) -> None:
    """A generated backdoor recovers the second secret of a real run."""
    parameters = DiffieHellmanParameters.generate_toy(bits=32)
    attacker = YoungYungAttacker.generate(parameters)
    configuration = attacker.generate_configuration()
    device = YoungYungDiffieHellmanParticipant(parameters, configuration)

    perform_key_exchange(device, DiffieHellmanParticipant(parameters))
    first_public_key = device.public_key
    device.generate_keypair()
    peer = DiffieHellmanParticipant(parameters)
    second = perform_key_exchange(device, peer)

    assert first_public_key is not None
    assert device.public_key is not None
    assert peer.public_key is not None
    assert (
        attacker.recover_shared_secret(
            first_public_key=first_public_key,
            second_public_key=device.public_key,
            peer_public_key=peer.public_key,
            configuration=configuration,
        )
        == second.bob_shared_secret
    )


def test_compute_candidates_matches_test_vector(
    attacker: YoungYungAttacker,
    configuration: YoungYungConfiguration,
) -> None:
    """From m1 = 18 alone: r = 8, z = (3, 9), keys (4, 10)."""
    candidates = attacker.compute_candidates(
        first_public_key=18, configuration=configuration
    )

    assert candidates == SetupCandidates(
        first_public_key=18,
        r=8,
        z_candidates=(3, 9),
        private_key_candidates=(4, 10),
    )


def test_compute_candidates_rejects_invalid_inputs(
    attacker: YoungYungAttacker,
    configuration: YoungYungConfiguration,
    parameters: DiffieHellmanParameters,
) -> None:
    """Invalid m1 and foreign configurations are rejected."""
    with pytest.raises(InvalidPublicKey):
        attacker.compute_candidates(first_public_key=5, configuration=configuration)
    with pytest.raises(InvalidSetupConfiguration):
        attacker.compute_candidates(
            first_public_key=18,
            configuration=build_configuration(parameters, attacker_public_key=4),
        )


@pytest.mark.parametrize(
    ("second_public_key", "expected_bit", "expected_key"),
    [(16, 0, 4), (12, 1, 10)],
)
def test_match_candidates_keeps_the_matching_key(
    attacker: YoungYungAttacker,
    configuration: YoungYungConfiguration,
    second_public_key: int,
    expected_bit: int,
    expected_key: int,
) -> None:
    """Matching keeps the candidate that reproduces m2."""
    candidates = attacker.compute_candidates(
        first_public_key=18, configuration=configuration
    )

    recovery = attacker.match_candidates(
        candidates, second_public_key=second_public_key
    )

    assert recovery == attacker.recover(
        first_public_key=18,
        second_public_key=second_public_key,
        configuration=configuration,
    )
    assert (recovery.correction_bit, recovery.private_key) == (
        expected_bit,
        expected_key,
    )


def test_match_candidates_rejects_unrelated_or_invalid_keys(
    attacker: YoungYungAttacker,
    configuration: YoungYungConfiguration,
) -> None:
    """2 = g^1 is a valid key, but 1 is neither candidate; 5 is not valid."""
    candidates = attacker.compute_candidates(
        first_public_key=18, configuration=configuration
    )

    with pytest.raises(SetupRecoveryError):
        attacker.match_candidates(candidates, second_public_key=2)
    with pytest.raises(InvalidPublicKey):
        attacker.match_candidates(candidates, second_public_key=5)


def test_candidates_are_frozen(
    attacker: YoungYungAttacker,
    configuration: YoungYungConfiguration,
) -> None:
    """The candidates cannot be modified."""
    candidates = attacker.compute_candidates(
        first_public_key=18, configuration=configuration
    )

    with pytest.raises(FrozenInstanceError):
        candidates.r = 1  # ty: ignore[invalid-assignment]

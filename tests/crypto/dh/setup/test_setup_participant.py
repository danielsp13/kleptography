"""
Test vectors: see ``test_setup_construction.py``.

Toy group p = 23, g = 2, q = 11; Y = 8, a = 2, b = 2, W = 3,
H(v) = v mod 10 + 1. With c1 = 6: t = 0 gives c2 = 4 (m2 = 16) and
t = 1 gives c2 = 10 (m2 = 12).
"""

from __future__ import annotations

import pytest

from kleptography.crypto.dh.exceptions import (
    DiffieHellmanParametersMismatch,
    InvalidPrivateKey,
)
from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.participant import DiffieHellmanParticipant
from kleptography.crypto.dh.protocol import perform_key_exchange
from kleptography.crypto.dh.setup.configuration import YoungYungConfiguration
from kleptography.crypto.dh.setup.participant import (
    YoungYungDiffieHellmanParticipant,
)
from kleptography.crypto.dh.setup.records import SetupDerivation
from kleptography.crypto.dh.tracing.context import ProtocolExecutionContext
from kleptography.crypto.dh.tracing.events import Actor, ProtocolEventType
from kleptography.crypto.dh.validation import (
    validate_private_key,
    validate_public_key,
)


def toy_hash(value: int, *, parameters: DiffieHellmanParameters) -> int:
    """Insecure, readable H for hand-computed test vectors."""
    return value % (parameters.subgroup_order - 1) + 1


@pytest.fixture
def parameters() -> DiffieHellmanParameters:
    return DiffieHellmanParameters(prime=23, generator=2, subgroup_order=11)


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


@pytest.fixture
def device(
    parameters: DiffieHellmanParameters,
    configuration: YoungYungConfiguration,
) -> YoungYungDiffieHellmanParticipant:
    return YoungYungDiffieHellmanParticipant(parameters, configuration)


def force_correction_bit(monkeypatch: pytest.MonkeyPatch, correction_bit: int) -> None:
    monkeypatch.setattr(
        YoungYungDiffieHellmanParticipant,
        "_sample_correction_bit",
        lambda self: correction_bit,
    )


def test_device_is_a_diffie_hellman_participant(
    device: YoungYungDiffieHellmanParticipant,
) -> None:
    """The compromised device is a drop-in replacement for the honest one."""
    assert isinstance(device, DiffieHellmanParticipant)


def test_device_initial_state(
    device: YoungYungDiffieHellmanParticipant,
    configuration: YoungYungConfiguration,
) -> None:
    assert device.configuration is configuration
    assert device.private_key is None
    assert device.public_key is None
    assert device.has_keypair is False


def test_device_rejects_configuration_for_another_group(
    configuration: YoungYungConfiguration,
) -> None:
    other_parameters = DiffieHellmanParameters(prime=47, generator=2, subgroup_order=23)

    with pytest.raises(DiffieHellmanParametersMismatch):
        YoungYungDiffieHellmanParticipant(other_parameters, configuration)


def test_device_accepts_equal_but_distinct_parameters(
    configuration: YoungYungConfiguration,
) -> None:
    equal_parameters = DiffieHellmanParameters(prime=23, generator=2, subgroup_order=11)

    device = YoungYungDiffieHellmanParticipant(equal_parameters, configuration)

    assert device.parameters == configuration.parameters


def test_device_repr_hides_private_key(
    device: YoungYungDiffieHellmanParticipant,
) -> None:
    device.load_private_key(6)

    assert "_private_key" not in repr(device)


def test_first_key_comes_from_honest_generator(
    device: YoungYungDiffieHellmanParticipant,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The first exchange is honest: c1 is the honest random exponent."""
    monkeypatch.setattr(
        DiffieHellmanParticipant,
        "_generate_private_key",
        lambda self: 9,
    )

    device.generate_keypair()

    assert device.private_key == 9
    assert device.public_key == 6


@pytest.mark.parametrize(
    ("correction_bit", "expected_private_key", "expected_public_key"),
    [(0, 4, 16), (1, 10, 12)],
)
def test_second_key_is_derived_from_stored_exponent(
    device: YoungYungDiffieHellmanParticipant,
    monkeypatch: pytest.MonkeyPatch,
    correction_bit: int,
    expected_private_key: int,
    expected_public_key: int,
) -> None:
    force_correction_bit(monkeypatch, correction_bit)
    device.load_private_key(6)

    device.generate_keypair()

    assert device.private_key == expected_private_key
    assert device.public_key == expected_public_key


def test_two_generations_follow_the_setup(
    device: YoungYungDiffieHellmanParticipant,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        DiffieHellmanParticipant,
        "_generate_private_key",
        lambda self: 6,
    )
    force_correction_bit(monkeypatch, 1)

    device.generate_keypair()
    first = (device.private_key, device.public_key)
    device.generate_keypair()
    second = (device.private_key, device.public_key)

    assert first == (6, 18)
    assert second == (10, 12)


def test_load_private_key_is_still_validated(
    device: YoungYungDiffieHellmanParticipant,
) -> None:
    with pytest.raises(InvalidPrivateKey):
        device.load_private_key(0)


def test_sample_correction_bit_is_a_random_bit(
    device: YoungYungDiffieHellmanParticipant,
) -> None:
    """Both values appear in 128 samples (failure probability 2^-127)."""
    samples = {device._sample_correction_bit() for _ in range(128)}

    assert samples == {0, 1}


@pytest.fixture
def toy_device() -> YoungYungDiffieHellmanParticipant:
    """A device on a random 32-bit group using the default H."""
    parameters = DiffieHellmanParameters.generate_toy(bits=32)
    configuration = YoungYungConfiguration(
        parameters=parameters,
        attacker_public_key=pow(parameters.generator, 12345, parameters.prime),
        multiplier_a=7,
        offset_b=11,
        correction_w=3,
    )
    return YoungYungDiffieHellmanParticipant(parameters, configuration)


def test_device_keys_pass_honest_validation(
    toy_device: YoungYungDiffieHellmanParticipant,
) -> None:
    """SETUP outputs are valid DH key pairs, like honest ones."""
    parameters = toy_device.parameters

    for _ in range(10):
        toy_device.generate_keypair()
        private_key = toy_device.private_key
        public_key = toy_device.public_key

        assert private_key is not None
        assert public_key is not None
        validate_private_key(private_key, subgroup_order=parameters.subgroup_order)
        validate_public_key(
            public_key,
            prime=parameters.prime,
            subgroup_order=parameters.subgroup_order,
        )
        assert public_key == pow(parameters.generator, private_key, parameters.prime)


def test_honest_peer_agrees_with_device_in_both_exchanges(
    toy_device: YoungYungDiffieHellmanParticipant,
) -> None:
    """The SETUP does not break the protocol for the honest peer."""
    parameters = toy_device.parameters

    first = perform_key_exchange(toy_device, DiffieHellmanParticipant(parameters))
    toy_device.generate_keypair()
    second = perform_key_exchange(toy_device, DiffieHellmanParticipant(parameters))

    assert first.successful is True
    assert second.successful is True


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


def test_first_generation_does_not_sample_correction_bit(
    device: YoungYungDiffieHellmanParticipant,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """t only exists in the second exchange."""

    def unexpected(self: YoungYungDiffieHellmanParticipant) -> int:
        raise AssertionError("t sampled in the first exchange")

    monkeypatch.setattr(
        YoungYungDiffieHellmanParticipant, "_sample_correction_bit", unexpected
    )

    device.generate_keypair()

    assert device.has_keypair is True


def test_second_generation_does_not_use_honest_generator(
    device: YoungYungDiffieHellmanParticipant,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """c2 is derived from c1, not sampled at random."""
    device.load_private_key(6)
    force_correction_bit(monkeypatch, 0)

    def unexpected(self: DiffieHellmanParticipant) -> int:
        raise AssertionError("honest generator used in the second exchange")

    monkeypatch.setattr(DiffieHellmanParticipant, "_generate_private_key", unexpected)

    device.generate_keypair()

    assert device.private_key == 4


def test_second_generation_samples_correction_bit_once(
    device: YoungYungDiffieHellmanParticipant,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []

    def counting(self: YoungYungDiffieHellmanParticipant) -> int:
        calls.append(1)
        return 1

    monkeypatch.setattr(
        YoungYungDiffieHellmanParticipant, "_sample_correction_bit", counting
    )
    device.load_private_key(6)

    device.generate_keypair()

    assert calls == [1]
    assert device.private_key == 10


def test_device_uses_configured_hash(
    parameters: DiffieHellmanParameters,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    received: list[int] = []

    def recording_hash(value: int, *, parameters: DiffieHellmanParameters) -> int:
        received.append(value)
        return 7

    configuration = YoungYungConfiguration(
        parameters=parameters,
        attacker_public_key=8,
        multiplier_a=2,
        offset_b=2,
        correction_w=3,
        hash_function=recording_hash,
    )
    device = YoungYungDiffieHellmanParticipant(parameters, configuration)
    force_correction_bit(monkeypatch, 1)
    device.load_private_key(6)

    device.generate_keypair()

    assert received == [9]
    assert device.private_key == 7
    assert device.public_key == pow(2, 7, 23)


@pytest.mark.parametrize("correction_bit", [0, 1])
def test_second_key_matches_reference_for_every_stored_exponent(
    device: YoungYungDiffieHellmanParticipant,
    configuration: YoungYungConfiguration,
    monkeypatch: pytest.MonkeyPatch,
    correction_bit: int,
) -> None:
    force_correction_bit(monkeypatch, correction_bit)

    for previous_private_key in range(1, 11):
        device.load_private_key(previous_private_key)

        device.generate_keypair()

        expected = reference_second_key(
            previous_private_key, correction_bit, configuration
        )
        assert device.private_key == expected
        assert device.public_key == pow(2, expected, 23)


@pytest.mark.parametrize("correction_bit", [0, 1])
def test_second_key_matches_reference_with_default_hash(
    toy_device: YoungYungDiffieHellmanParticipant,
    monkeypatch: pytest.MonkeyPatch,
    correction_bit: int,
) -> None:
    force_correction_bit(monkeypatch, correction_bit)

    toy_device.generate_keypair()
    previous_private_key = toy_device.private_key
    assert previous_private_key is not None

    toy_device.generate_keypair()

    assert toy_device.private_key == reference_second_key(
        previous_private_key, correction_bit, toy_device.configuration
    )


def test_device_works_as_second_participant(
    toy_device: YoungYungDiffieHellmanParticipant,
) -> None:
    parameters = toy_device.parameters

    first = perform_key_exchange(DiffieHellmanParticipant(parameters), toy_device)
    toy_device.generate_keypair()
    second = perform_key_exchange(DiffieHellmanParticipant(parameters), toy_device)

    assert first.successful is True
    assert second.successful is True


def exchange_shape(
    alice: DiffieHellmanParticipant,
    bob: DiffieHellmanParticipant,
) -> list[tuple[ProtocolEventType, Actor, frozenset[str]]]:
    """Event types, actors and data keys: what the timeline looks like."""
    context = ProtocolExecutionContext()
    perform_key_exchange(alice, bob, observer=context)
    return [
        (event.event_type, event.actor, frozenset(event.data))
        for event in context.events
    ]


def test_device_timeline_looks_like_honest_timeline(
    toy_device: YoungYungDiffieHellmanParticipant,
) -> None:
    """The observer sees the same sequence of steps in both exchanges."""
    parameters = toy_device.parameters
    honest = DiffieHellmanParticipant(parameters)

    honest_first = exchange_shape(honest, DiffieHellmanParticipant(parameters))
    device_first = exchange_shape(toy_device, DiffieHellmanParticipant(parameters))
    honest.generate_keypair()
    toy_device.generate_keypair()
    honest_second = exchange_shape(honest, DiffieHellmanParticipant(parameters))
    device_second = exchange_shape(toy_device, DiffieHellmanParticipant(parameters))

    assert device_first == honest_first
    assert device_second == honest_second


def test_device_in_exchange_with_other_group_is_rejected(
    toy_device: YoungYungDiffieHellmanParticipant,
) -> None:
    other_parameters = DiffieHellmanParameters(prime=47, generator=2, subgroup_order=23)

    with pytest.raises(DiffieHellmanParametersMismatch):
        perform_key_exchange(toy_device, DiffieHellmanParticipant(other_parameters))

    assert toy_device.has_keypair is False


def test_device_mismatch_is_raised_before_any_key_exists(
    configuration: YoungYungConfiguration,
) -> None:
    other_parameters = DiffieHellmanParameters(prime=47, generator=2, subgroup_order=23)

    with pytest.raises(ValueError):
        YoungYungDiffieHellmanParticipant(other_parameters, configuration)


def test_device_is_slotted(device: YoungYungDiffieHellmanParticipant) -> None:
    assert not hasattr(device, "__dict__")


def test_device_public_key_is_consistent_after_each_generation(
    toy_device: YoungYungDiffieHellmanParticipant,
) -> None:
    """The honest invariant public_key == g^x mod p still holds."""
    parameters = toy_device.parameters

    for _ in range(5):
        toy_device.generate_keypair()
        private_key = toy_device.private_key
        assert private_key is not None
        assert toy_device.public_key == pow(
            parameters.generator, private_key, parameters.prime
        )


def test_last_derivation_is_empty_until_setup_runs(
    device: YoungYungDiffieHellmanParticipant,
) -> None:
    assert device.last_derivation is None

    device.generate_keypair()

    assert device.last_derivation is None


@pytest.mark.parametrize(
    ("correction_bit", "expected_z", "expected_key"),
    [(0, 3, 4), (1, 9, 10)],
)
def test_last_derivation_records_setup_internals(
    device: YoungYungDiffieHellmanParticipant,
    monkeypatch: pytest.MonkeyPatch,
    correction_bit: int,
    expected_z: int,
    expected_key: int,
) -> None:
    force_correction_bit(monkeypatch, correction_bit)
    device.load_private_key(6)

    device.generate_keypair()

    assert device.last_derivation == SetupDerivation(
        previous_private_key=6,
        correction_bit=correction_bit,
        z=expected_z,
        private_key=expected_key,
    )
    assert device.private_key == expected_key


def test_load_private_key_clears_last_derivation(
    device: YoungYungDiffieHellmanParticipant,
) -> None:
    device.load_private_key(6)
    device.generate_keypair()
    assert device.last_derivation is not None

    device.load_private_key(6)

    assert device.last_derivation is None


def test_repr_hides_last_derivation(
    device: YoungYungDiffieHellmanParticipant,
) -> None:
    device.load_private_key(6)
    device.generate_keypair()

    assert "derivation" not in repr(device)


def test_last_derivation_follows_the_chain(
    toy_device: YoungYungDiffieHellmanParticipant,
) -> None:
    """Each derivation starts from the exponent of the previous exchange."""
    toy_device.generate_keypair()

    for _ in range(3):
        previous_private_key = toy_device.private_key
        toy_device.generate_keypair()
        derivation = toy_device.last_derivation

        assert derivation is not None
        assert derivation.previous_private_key == previous_private_key
        assert derivation.private_key == toy_device.private_key

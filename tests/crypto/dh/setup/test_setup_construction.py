"""
Test vectors in the toy group p = 23, g = 2, q = 11.

Attacker X = 3, Y = 8. Constants a = 2, b = 2, W = 3. H(v) = v mod 10 + 1.
Device's first exponent c1 = 6, so m1 = 18.

    t = 0: z = g^(6 - 0) * 8^(-14) = 3  ->  c2 = H(3) = 4,  m2 = 16
    t = 1: z = g^(6 - 3) * 8^(-14) = 9  ->  c2 = H(9) = 10, m2 = 12

Attacker: r = 18^2 * 2^2 = 8, z1 = 18 / 8^3 = 3, z2 = 3 / 2^3 = 9.
"""

from __future__ import annotations

import secrets

import pytest

from kleptography.crypto.dh.exceptions import InvalidPrivateKey, InvalidPublicKey
from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.setup.configuration import YoungYungConfiguration
from kleptography.crypto.dh.setup.construction import (
    compute_z,
    derive_private_key,
    recover_z_candidates,
)
from kleptography.crypto.dh.setup.hashing import SetupHashFunction


def toy_hash(value: int, *, parameters: DiffieHellmanParameters) -> int:
    """Insecure, readable H for hand-computed test vectors."""
    return value % (parameters.subgroup_order - 1) + 1


@pytest.fixture
def parameters() -> DiffieHellmanParameters:
    return DiffieHellmanParameters(prime=23, generator=2, subgroup_order=11)


def build_configuration(
    parameters: DiffieHellmanParameters,
    hash_function: SetupHashFunction = toy_hash,
) -> YoungYungConfiguration:
    return YoungYungConfiguration(
        parameters=parameters,
        attacker_public_key=8,
        multiplier_a=2,
        offset_b=2,
        correction_w=3,
        hash_function=hash_function,
    )


@pytest.fixture
def configuration(parameters: DiffieHellmanParameters) -> YoungYungConfiguration:
    return build_configuration(parameters)


@pytest.mark.parametrize(("correction_bit", "expected_z"), [(0, 3), (1, 9)])
def test_compute_z_matches_test_vector(
    configuration: YoungYungConfiguration,
    correction_bit: int,
    expected_z: int,
) -> None:
    z = compute_z(6, correction_bit=correction_bit, configuration=configuration)

    assert z == expected_z


@pytest.mark.parametrize("correction_bit", [-1, 2])
def test_compute_z_rejects_invalid_correction_bit(
    configuration: YoungYungConfiguration,
    correction_bit: int,
) -> None:
    with pytest.raises(ValueError):
        compute_z(6, correction_bit=correction_bit, configuration=configuration)


@pytest.mark.parametrize("previous_private_key", [0, 11, -1])
def test_compute_z_rejects_invalid_previous_private_key(
    configuration: YoungYungConfiguration,
    previous_private_key: int,
) -> None:
    with pytest.raises(InvalidPrivateKey):
        compute_z(
            previous_private_key,
            correction_bit=0,
            configuration=configuration,
        )


@pytest.mark.parametrize(("correction_bit", "expected_key"), [(0, 4), (1, 10)])
def test_derive_private_key_matches_test_vector(
    configuration: YoungYungConfiguration,
    correction_bit: int,
    expected_key: int,
) -> None:
    private_key = derive_private_key(
        6,
        correction_bit=correction_bit,
        configuration=configuration,
    )

    assert private_key == expected_key


def test_derive_private_key_uses_configured_hash(
    parameters: DiffieHellmanParameters,
) -> None:
    received: list[int] = []

    def recording_hash(value: int, *, parameters: DiffieHellmanParameters) -> int:
        received.append(value)
        return 5

    configuration = build_configuration(parameters, recording_hash)

    private_key = derive_private_key(6, correction_bit=1, configuration=configuration)

    assert private_key == 5
    assert received == [9]


@pytest.mark.parametrize("hash_output", [0, 11])
def test_derive_private_key_rejects_invalid_hash_output(
    parameters: DiffieHellmanParameters,
    hash_output: int,
) -> None:
    def broken_hash(value: int, *, parameters: DiffieHellmanParameters) -> int:
        return hash_output

    configuration = build_configuration(parameters, broken_hash)

    with pytest.raises(InvalidPrivateKey):
        derive_private_key(6, correction_bit=0, configuration=configuration)


def test_recover_z_candidates_matches_test_vector(
    configuration: YoungYungConfiguration,
) -> None:
    candidates = recover_z_candidates(
        18,
        attacker_private_key=3,
        configuration=configuration,
    )

    assert candidates == (3, 9)


@pytest.mark.parametrize("first_public_key", [0, 1, 5, 23])
def test_recover_z_candidates_rejects_invalid_public_key(
    configuration: YoungYungConfiguration,
    first_public_key: int,
) -> None:
    with pytest.raises(InvalidPublicKey):
        recover_z_candidates(
            first_public_key,
            attacker_private_key=3,
            configuration=configuration,
        )


@pytest.mark.parametrize("attacker_private_key", [0, 11])
def test_recover_z_candidates_rejects_invalid_attacker_key(
    configuration: YoungYungConfiguration,
    attacker_private_key: int,
) -> None:
    with pytest.raises(InvalidPrivateKey):
        recover_z_candidates(
            18,
            attacker_private_key=attacker_private_key,
            configuration=configuration,
        )


@pytest.fixture
def toy_setup() -> tuple[YoungYungConfiguration, int]:
    """A random 32-bit group, attacker key and configuration."""
    parameters = DiffieHellmanParameters.generate_toy(bits=32)
    subgroup_order = parameters.subgroup_order
    attacker_private_key = secrets.randbelow(subgroup_order - 1) + 1

    configuration = YoungYungConfiguration(
        parameters=parameters,
        attacker_public_key=pow(
            parameters.generator, attacker_private_key, parameters.prime
        ),
        multiplier_a=secrets.randbelow(subgroup_order - 1) + 1,
        offset_b=secrets.randbelow(subgroup_order),
        correction_w=3,
    )

    return configuration, attacker_private_key


def test_attacker_candidates_undo_device_z(
    toy_setup: tuple[YoungYungConfiguration, int],
) -> None:
    """z1 is the device's z for t = 0 and z2 the one for t = 1."""
    configuration, attacker_private_key = toy_setup
    parameters = configuration.parameters

    for _ in range(20):
        previous_private_key = secrets.randbelow(parameters.subgroup_order - 1) + 1
        first_public_key = pow(
            parameters.generator, previous_private_key, parameters.prime
        )

        candidates = recover_z_candidates(
            first_public_key,
            attacker_private_key=attacker_private_key,
            configuration=configuration,
        )

        for correction_bit in (0, 1):
            z = compute_z(
                previous_private_key,
                correction_bit=correction_bit,
                configuration=configuration,
            )

            assert z == candidates[correction_bit]
            assert pow(z, parameters.subgroup_order, parameters.prime) == 1


def test_wrong_attacker_key_does_not_recover_z(
    toy_setup: tuple[YoungYungConfiguration, int],
) -> None:
    """Knowing the device constants without X is not enough."""
    configuration, attacker_private_key = toy_setup
    parameters = configuration.parameters
    wrong_private_key = attacker_private_key % (parameters.subgroup_order - 1) + 1

    previous_private_key = secrets.randbelow(parameters.subgroup_order - 1) + 1
    first_public_key = pow(parameters.generator, previous_private_key, parameters.prime)

    candidates = recover_z_candidates(
        first_public_key,
        attacker_private_key=wrong_private_key,
        configuration=configuration,
    )

    for correction_bit in (0, 1):
        z = compute_z(
            previous_private_key,
            correction_bit=correction_bit,
            configuration=configuration,
        )
        assert z not in candidates

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
from dataclasses import FrozenInstanceError

import pytest

from kleptography.crypto.dh.exceptions import InvalidPrivateKey, InvalidPublicKey
from kleptography.crypto.dh.groups.rfc7919 import ffdhe2048
from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.setup.configuration import YoungYungConfiguration
from kleptography.crypto.dh.setup.construction import (
    compute_r,
    compute_z,
    derive_private_key,
    derive_setup,
    recover_z_candidates,
)
from kleptography.crypto.dh.setup.hashing import SetupHashFunction, hash_to_exponent
from kleptography.crypto.dh.setup.records import SetupDerivation


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


# --- Complementary tests -----------------------------------------------------
#
# Reference values are computed here with Python's ``pow`` (a negative exponent
# with a modulus computes a modular inverse), independently of the module under
# test.


def reference_z(
    previous_private_key: int,
    correction_bit: int,
    configuration: YoungYungConfiguration,
) -> int:
    """z = g^(c1 - W*t) * Y^(-a*c1 - b) mod p."""
    prime = configuration.parameters.prime
    generator = configuration.parameters.generator
    left = pow(
        generator,
        previous_private_key - configuration.correction_w * correction_bit,
        prime,
    )
    right = pow(
        configuration.attacker_public_key,
        -configuration.multiplier_a * previous_private_key - configuration.offset_b,
        prime,
    )
    return left * right % prime


def reference_candidates(
    first_public_key: int,
    attacker_private_key: int,
    configuration: YoungYungConfiguration,
) -> tuple[int, int]:
    """r = m1^a * g^b, z1 = m1 / r^X, z2 = z1 / g^W, all modulo p."""
    prime = configuration.parameters.prime
    generator = configuration.parameters.generator
    r = (
        pow(first_public_key, configuration.multiplier_a, prime)
        * pow(generator, configuration.offset_b, prime)
        % prime
    )
    z1 = first_public_key * pow(r, -attacker_private_key, prime) % prime
    z2 = z1 * pow(generator, -configuration.correction_w, prime) % prime
    return z1, z2


# (prime, generator, subgroup_order, X, a, b, W): the first row is the test
# vector; the others use constants outside [0, q) and a second group.
CONSTANT_SETS = [
    (23, 2, 11, 3, 2, 2, 3),
    (23, 2, 11, 7, 13, -9, 25),
    (23, 2, 11, 10, -1, 0, -1),
    (23, 2, 11, 1, 5, 11, 1),
    (47, 2, 23, 5, 3, 5, 7),
    (47, 2, 23, 22, 30, -40, -21),
]


def build_general_configuration(
    constants: tuple[int, int, int, int, int, int, int],
    hash_function: SetupHashFunction = toy_hash,
) -> tuple[YoungYungConfiguration, int]:
    prime, generator, subgroup_order, attacker_private_key, a, b, w = constants
    parameters = DiffieHellmanParameters(
        prime=prime, generator=generator, subgroup_order=subgroup_order
    )
    configuration = YoungYungConfiguration(
        parameters=parameters,
        attacker_public_key=pow(generator, attacker_private_key, prime),
        multiplier_a=a,
        offset_b=b,
        correction_w=w,
        hash_function=hash_function,
    )
    return configuration, attacker_private_key


@pytest.mark.parametrize("constants", CONSTANT_SETS)
def test_compute_z_matches_reference_for_every_input(
    constants: tuple[int, int, int, int, int, int, int],
) -> None:
    configuration, _ = build_general_configuration(constants)
    parameters = configuration.parameters

    for previous_private_key in range(1, parameters.subgroup_order):
        for correction_bit in (0, 1):
            z = compute_z(
                previous_private_key,
                correction_bit=correction_bit,
                configuration=configuration,
            )

            assert type(z) is int
            assert z == reference_z(previous_private_key, correction_bit, configuration)
            assert 1 <= z < parameters.prime
            assert pow(z, parameters.subgroup_order, parameters.prime) == 1


@pytest.mark.parametrize("constants", CONSTANT_SETS)
def test_recover_z_candidates_matches_reference_for_every_input(
    constants: tuple[int, int, int, int, int, int, int],
) -> None:
    configuration, attacker_private_key = build_general_configuration(constants)
    parameters = configuration.parameters

    for previous_private_key in range(1, parameters.subgroup_order):
        first_public_key = pow(
            parameters.generator, previous_private_key, parameters.prime
        )

        candidates = recover_z_candidates(
            first_public_key,
            attacker_private_key=attacker_private_key,
            configuration=configuration,
        )

        assert isinstance(candidates, tuple)
        assert all(type(candidate) is int for candidate in candidates)
        assert candidates == reference_candidates(
            first_public_key, attacker_private_key, configuration
        )
        assert candidates == (
            reference_z(previous_private_key, 0, configuration),
            reference_z(previous_private_key, 1, configuration),
        )


@pytest.mark.parametrize("constants", CONSTANT_SETS)
def test_z_candidates_are_distinct(
    constants: tuple[int, int, int, int, int, int, int],
) -> None:
    """W is not 0 mod q, so g^W != 1 and z1 != z2."""
    configuration, attacker_private_key = build_general_configuration(constants)
    parameters = configuration.parameters

    for previous_private_key in range(1, parameters.subgroup_order):
        first_public_key = pow(
            parameters.generator, previous_private_key, parameters.prime
        )
        first, second = recover_z_candidates(
            first_public_key,
            attacker_private_key=attacker_private_key,
            configuration=configuration,
        )

        assert first != second


@pytest.mark.parametrize("constants", CONSTANT_SETS)
def test_derive_private_key_is_hash_of_z_for_every_input(
    constants: tuple[int, int, int, int, int, int, int],
) -> None:
    """c2 = H(z) with the default H."""
    configuration, _ = build_general_configuration(constants, hash_to_exponent)
    parameters = configuration.parameters

    for previous_private_key in range(1, parameters.subgroup_order):
        for correction_bit in (0, 1):
            private_key = derive_private_key(
                previous_private_key,
                correction_bit=correction_bit,
                configuration=configuration,
            )

            assert private_key == hash_to_exponent(
                reference_z(previous_private_key, correction_bit, configuration),
                parameters=parameters,
            )


def test_derive_private_key_passes_configuration_parameters_to_hash(
    parameters: DiffieHellmanParameters,
) -> None:
    received: list[DiffieHellmanParameters] = []

    def recording_hash(value: int, *, parameters: DiffieHellmanParameters) -> int:
        received.append(parameters)
        return 5

    configuration = build_configuration(parameters, recording_hash)

    derive_private_key(6, correction_bit=0, configuration=configuration)

    assert received == [parameters]


@pytest.mark.parametrize("previous_private_key", [0, 11, -1])
def test_derive_private_key_rejects_invalid_previous_private_key(
    configuration: YoungYungConfiguration,
    previous_private_key: int,
) -> None:
    with pytest.raises(InvalidPrivateKey):
        derive_private_key(
            previous_private_key,
            correction_bit=0,
            configuration=configuration,
        )


@pytest.mark.parametrize("correction_bit", [-1, 2])
def test_derive_private_key_rejects_invalid_correction_bit(
    configuration: YoungYungConfiguration,
    correction_bit: int,
) -> None:
    with pytest.raises(ValueError):
        derive_private_key(
            6,
            correction_bit=correction_bit,
            configuration=configuration,
        )


@pytest.fixture
def larger_configuration() -> YoungYungConfiguration:
    """Group p = 47, g = 2, q = 23 with X = 5 (Y = 32)."""
    configuration, _ = build_general_configuration(CONSTANT_SETS[4])
    return configuration


@pytest.mark.parametrize("previous_private_key", [11, 15, 22])
def test_compute_z_validates_against_configuration_group(
    larger_configuration: YoungYungConfiguration,
    previous_private_key: int,
) -> None:
    """Exponents >= 11 are valid when q = 23."""
    z = compute_z(
        previous_private_key,
        correction_bit=0,
        configuration=larger_configuration,
    )

    assert z == reference_z(previous_private_key, 0, larger_configuration)


def test_compute_z_rejects_exponent_equal_to_configuration_order(
    larger_configuration: YoungYungConfiguration,
) -> None:
    with pytest.raises(InvalidPrivateKey):
        compute_z(23, correction_bit=0, configuration=larger_configuration)


def test_recover_z_candidates_validates_against_configuration_group(
    larger_configuration: YoungYungConfiguration,
) -> None:
    """25 is in the subgroup of Z_47^*; 13 is only in the one of Z_23^*."""
    candidates = recover_z_candidates(
        25,
        attacker_private_key=15,
        configuration=larger_configuration,
    )

    assert candidates == reference_candidates(25, 15, larger_configuration)

    with pytest.raises(InvalidPublicKey):
        recover_z_candidates(
            13,
            attacker_private_key=15,
            configuration=larger_configuration,
        )


def test_attacker_candidates_undo_device_z_in_rfc_group() -> None:
    """Round trip with 2048-bit values (no precision loss)."""
    parameters = ffdhe2048()
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
    previous_private_key = secrets.randbelow(subgroup_order - 1) + 1
    first_public_key = pow(parameters.generator, previous_private_key, parameters.prime)

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

        assert z == reference_z(previous_private_key, correction_bit, configuration)
        assert z == candidates[correction_bit]


@pytest.mark.parametrize(
    ("correction_bit", "expected_z", "expected_key"),
    [(0, 3, 4), (1, 9, 10)],
)
def test_derive_setup_records_intermediate_values(
    configuration: YoungYungConfiguration,
    correction_bit: int,
    expected_z: int,
    expected_key: int,
) -> None:
    derivation = derive_setup(
        6,
        correction_bit=correction_bit,
        configuration=configuration,
    )

    assert derivation == SetupDerivation(
        previous_private_key=6,
        correction_bit=correction_bit,
        z=expected_z,
        private_key=expected_key,
    )


def test_setup_derivation_is_frozen(configuration: YoungYungConfiguration) -> None:
    derivation = derive_setup(6, correction_bit=0, configuration=configuration)

    with pytest.raises(FrozenInstanceError):
        derivation.z = 1  # ty: ignore[invalid-assignment]


@pytest.mark.parametrize("hash_output", [0, 11])
def test_derive_setup_rejects_invalid_hash_output(
    parameters: DiffieHellmanParameters,
    hash_output: int,
) -> None:
    def broken_hash(value: int, *, parameters: DiffieHellmanParameters) -> int:
        return hash_output

    configuration = build_configuration(parameters, broken_hash)

    with pytest.raises(InvalidPrivateKey):
        derive_setup(6, correction_bit=0, configuration=configuration)


def test_compute_r_matches_test_vector(
    configuration: YoungYungConfiguration,
) -> None:
    """r = 18^2 * 2^2 mod 23 = 8 = g^(a*c1 + b)."""
    assert compute_r(18, configuration=configuration) == 8


@pytest.mark.parametrize("constants", CONSTANT_SETS)
def test_r_to_the_x_is_the_device_mask(
    constants: tuple[int, int, int, int, int, int, int],
) -> None:
    """r^X = Y^(a*c1 + b): the value the device divides by, shared with X."""
    configuration, attacker_private_key = build_general_configuration(constants)
    parameters = configuration.parameters
    prime = parameters.prime

    for previous_private_key in range(1, parameters.subgroup_order):
        first_public_key = pow(parameters.generator, previous_private_key, prime)
        r = compute_r(first_public_key, configuration=configuration)

        assert pow(r, attacker_private_key, prime) == pow(
            configuration.attacker_public_key,
            configuration.multiplier_a * previous_private_key + configuration.offset_b,
            prime,
        )


@pytest.mark.parametrize("first_public_key", [0, 1, 5, 23])
def test_compute_r_rejects_invalid_public_key(
    configuration: YoungYungConfiguration,
    first_public_key: int,
) -> None:
    with pytest.raises(InvalidPublicKey):
        compute_r(first_public_key, configuration=configuration)

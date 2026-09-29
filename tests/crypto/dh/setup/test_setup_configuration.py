from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from kleptography.crypto.dh.exceptions import InvalidPublicKey
from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.setup.configuration import YoungYungConfiguration
from kleptography.crypto.dh.setup.exceptions import InvalidSetupConfiguration
from kleptography.crypto.dh.setup.hashing import hash_to_exponent


def toy_hash(value: int, *, parameters: DiffieHellmanParameters) -> int:
    """Insecure, readable H for hand-computed test vectors."""
    return value % (parameters.subgroup_order - 1) + 1


@pytest.fixture
def parameters() -> DiffieHellmanParameters:
    return DiffieHellmanParameters(prime=23, generator=2, subgroup_order=11)


def build_configuration(
    parameters: DiffieHellmanParameters,
    *,
    attacker_public_key: int = 8,
    multiplier_a: int = 2,
    offset_b: int = 2,
    correction_w: int = 3,
) -> YoungYungConfiguration:
    return YoungYungConfiguration(
        parameters=parameters,
        attacker_public_key=attacker_public_key,
        multiplier_a=multiplier_a,
        offset_b=offset_b,
        correction_w=correction_w,
        hash_function=toy_hash,
    )


def test_configuration_stores_constants(
    parameters: DiffieHellmanParameters,
) -> None:
    configuration = build_configuration(parameters)

    assert configuration.parameters is parameters
    assert configuration.attacker_public_key == 8
    assert configuration.multiplier_a == 2
    assert configuration.offset_b == 2
    assert configuration.correction_w == 3
    assert configuration.hash_function is toy_hash


def test_configuration_uses_hash_to_exponent_by_default(
    parameters: DiffieHellmanParameters,
) -> None:
    configuration = YoungYungConfiguration(
        parameters=parameters,
        attacker_public_key=8,
        multiplier_a=2,
        offset_b=2,
        correction_w=3,
    )

    assert configuration.hash_function is hash_to_exponent


def test_configuration_is_frozen_and_hashable(
    parameters: DiffieHellmanParameters,
) -> None:
    configuration = build_configuration(parameters)

    with pytest.raises(FrozenInstanceError):
        configuration.multiplier_a = 3  # ty: ignore[invalid-assignment]

    assert configuration == build_configuration(parameters)
    assert hash(configuration) == hash(build_configuration(parameters))


def test_configuration_is_keyword_only(
    parameters: DiffieHellmanParameters,
) -> None:
    with pytest.raises(TypeError):
        YoungYungConfiguration(parameters, 8, 2, 2, 3)  # ty: ignore[missing-argument, too-many-positional-arguments]


@pytest.mark.parametrize("attacker_public_key", [0, 1, 5, 22, 23])
def test_configuration_rejects_invalid_attacker_public_key(
    parameters: DiffieHellmanParameters,
    attacker_public_key: int,
) -> None:
    """Y must be a non-identity element of the subgroup (5, 22 are not)."""
    with pytest.raises(InvalidPublicKey):
        build_configuration(parameters, attacker_public_key=attacker_public_key)


@pytest.mark.parametrize("multiplier_a", [0, 11, 22, -11])
def test_configuration_rejects_multiplier_zero_modulo_q(
    parameters: DiffieHellmanParameters,
    multiplier_a: int,
) -> None:
    """With a = 0 mod q, r = g^b and anybody can compute r^X = Y^b."""
    with pytest.raises(InvalidSetupConfiguration):
        build_configuration(parameters, multiplier_a=multiplier_a)


@pytest.mark.parametrize("correction_w", [0, 2, 4, -2])
def test_configuration_rejects_even_correction(
    parameters: DiffieHellmanParameters,
    correction_w: int,
) -> None:
    """The paper requires W to be odd."""
    with pytest.raises(InvalidSetupConfiguration):
        build_configuration(parameters, correction_w=correction_w)


@pytest.mark.parametrize("correction_w", [11, 33])
def test_configuration_rejects_correction_zero_modulo_q(
    parameters: DiffieHellmanParameters,
    correction_w: int,
) -> None:
    """With W = 0 mod q, g^W = 1 and both candidates coincide."""
    with pytest.raises(InvalidSetupConfiguration):
        build_configuration(parameters, correction_w=correction_w)


@pytest.mark.parametrize("correction_w", [1, 3, 13])
def test_configuration_accepts_odd_correction(
    parameters: DiffieHellmanParameters,
    correction_w: int,
) -> None:
    configuration = build_configuration(parameters, correction_w=correction_w)

    assert configuration.correction_w == correction_w

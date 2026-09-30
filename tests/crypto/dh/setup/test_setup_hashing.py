from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import hashes

from kleptography.crypto.dh.groups.rfc7919 import ffdhe2048
from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.setup.hashing import hash_to_exponent
from kleptography.crypto.dh.validation import validate_private_key


@pytest.fixture
def toy_parameters() -> DiffieHellmanParameters:
    return DiffieHellmanParameters(prime=23, generator=2, subgroup_order=11)


def test_hash_output_is_a_valid_private_key_in_toy_group(
    toy_parameters: DiffieHellmanParameters,
) -> None:
    """Every element of Z_23^* maps into [1, q - 1]."""
    for value in range(1, toy_parameters.prime):
        exponent = hash_to_exponent(value, parameters=toy_parameters)

        validate_private_key(
            exponent,
            subgroup_order=toy_parameters.subgroup_order,
        )


def test_hash_is_deterministic(toy_parameters: DiffieHellmanParameters) -> None:
    """The device and the attacker must obtain the same exponent."""
    assert hash_to_exponent(12, parameters=toy_parameters) == hash_to_exponent(
        12, parameters=toy_parameters
    )


@pytest.mark.parametrize("value", [0, -1, 23, 24])
def test_hash_rejects_values_outside_group(
    toy_parameters: DiffieHellmanParameters,
    value: int,
) -> None:
    with pytest.raises(ValueError):
        hash_to_exponent(value, parameters=toy_parameters)


def test_hash_spreads_distinct_inputs() -> None:
    """Distinct group elements give (almost always) distinct exponents."""
    parameters = DiffieHellmanParameters.generate_toy(bits=32)
    generator, prime = parameters.generator, parameters.prime

    values = [pow(generator, exponent, prime) for exponent in range(1, 101)]
    exponents = {hash_to_exponent(value, parameters=parameters) for value in values}

    assert len(exponents) >= 95


def test_hash_covers_full_exponent_range_of_rfc_group() -> None:
    """
    H must cover [1, q - 1], as c2 does in the paper.

    A truncated 256-bit digest would give exponents of at most 256 bits. With
    16 uniform samples, the chance that none exceeds bit_length(q) - 16 is
    2^-256.
    """
    parameters = ffdhe2048()
    subgroup_order = parameters.subgroup_order

    exponents = [
        hash_to_exponent(pow(2, exponent, parameters.prime), parameters=parameters)
        for exponent in range(1, 17)
    ]

    assert all(1 <= exponent < subgroup_order for exponent in exponents)
    assert max(e.bit_length() for e in exponents) > subgroup_order.bit_length() - 16


# --- Complementary tests -----------------------------------------------------


@pytest.mark.parametrize(
    ("prime", "generator", "subgroup_order"),
    [(5, 4, 2), (7, 2, 3), (47, 2, 23)],
)
def test_hash_output_is_a_valid_private_key_in_small_groups(
    prime: int,
    generator: int,
    subgroup_order: int,
) -> None:
    """Boundary groups, including q = 2 where the only valid exponent is 1."""
    parameters = DiffieHellmanParameters(
        prime=prime, generator=generator, subgroup_order=subgroup_order
    )

    for value in range(1, prime):
        exponent = hash_to_exponent(value, parameters=parameters)

        assert isinstance(exponent, int)
        assert 1 <= exponent < subgroup_order


def test_hash_accepts_boundary_values_of_rfc_group() -> None:
    parameters = ffdhe2048()

    for value in (1, 2, parameters.prime - 1):
        exponent = hash_to_exponent(value, parameters=parameters)

        assert 1 <= exponent < parameters.subgroup_order


def test_hash_rejects_values_outside_rfc_group() -> None:
    parameters = ffdhe2048()

    with pytest.raises(ValueError):
        hash_to_exponent(parameters.prime, parameters=parameters)


def test_hash_parameters_are_keyword_only(
    toy_parameters: DiffieHellmanParameters,
) -> None:
    with pytest.raises(TypeError):
        hash_to_exponent(12, toy_parameters)  # ty: ignore[too-many-positional-arguments, missing-argument]


def test_hash_is_deterministic_for_equal_parameters() -> None:
    """Device and attacker may hold distinct but equal parameter objects."""
    first = DiffieHellmanParameters(prime=23, generator=2, subgroup_order=11)
    second = DiffieHellmanParameters(prime=23, generator=2, subgroup_order=11)

    for value in range(1, 23):
        assert hash_to_exponent(value, parameters=first) == hash_to_exponent(
            value, parameters=second
        )


def test_hash_spreads_distinct_inputs_of_rfc_group() -> None:
    parameters = ffdhe2048()

    values = [pow(2, exponent, parameters.prime) for exponent in range(1, 51)]
    exponents = {hash_to_exponent(value, parameters=parameters) for value in values}

    assert len(exponents) == len(values)


def test_hash_is_shake256_over_fixed_width_encoding() -> None:
    """H(z) = SHAKE-256(tag || I2OSP(z, len(p))) mod (q - 1) + 1."""
    parameters = ffdhe2048()
    value = 2
    output_length = (parameters.subgroup_order.bit_length() + 7) // 8 + 8

    digest = hashes.Hash(hashes.SHAKE256(output_length))
    digest.update(b"young-yung-setup-H")
    digest.update(value.to_bytes(256, "big"))
    expected = (
        int.from_bytes(digest.finalize(), "big") % (parameters.subgroup_order - 1) + 1
    )

    assert hash_to_exponent(value, parameters=parameters) == expected

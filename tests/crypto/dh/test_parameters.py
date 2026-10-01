"""Tests for ``DiffieHellmanParameters``, the public parameters of a group.

They check toy generation (bit length, safe prime, generator of order q),
construction from a standard, the bit and byte lengths, and that the
parameters are immutable and hashable.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from kleptography.crypto.dh.parameters import DiffieHellmanParameters


def test_generate_toy_returns_parameters() -> None:
    """Toy generation should return a DiffieHellmanParameters instance."""
    parameters = DiffieHellmanParameters.generate_toy(bits=32)

    assert isinstance(parameters, DiffieHellmanParameters)


def test_generate_toy_has_requested_bit_length() -> None:
    """Toy parameters should use a prime with the requested bit length."""
    bits = 32

    parameters = DiffieHellmanParameters.generate_toy(bits=bits)

    assert parameters.bit_length == bits
    assert parameters.prime.bit_length() == bits


def test_generate_toy_has_safe_prime_structure() -> None:
    """Toy parameters should use p = 2q + 1."""
    parameters = DiffieHellmanParameters.generate_toy(bits=32)

    assert parameters.prime == 2 * parameters.subgroup_order + 1


def test_generate_toy_generator_has_subgroup_order() -> None:
    """The generated generator should have exactly the declared subgroup order.

    For the generated safe prime p = 2q + 1:

        g^q ≡ 1 (mod p)

    Since q is prime and g != 1, the order of g is exactly q.
    """
    parameters = DiffieHellmanParameters.generate_toy(bits=32)

    assert parameters.generator != 1
    assert (
        pow(
            parameters.generator,
            parameters.subgroup_order,
            parameters.prime,
        )
        == 1
    )


def test_generate_toy_generator_is_valid_modulo_prime() -> None:
    """The generator should be a non-trivial element modulo p."""
    parameters = DiffieHellmanParameters.generate_toy(bits=32)

    assert 1 < parameters.generator < parameters.prime


def test_bit_length_returns_prime_bit_length() -> None:
    """bit_length should return the bit length of the modulus."""
    parameters = DiffieHellmanParameters(
        prime=23,
        generator=2,
        subgroup_order=11,
    )

    assert parameters.bit_length == 5


@pytest.mark.parametrize(
    ("prime", "generator", "subgroup_order", "expected"),
    [(23, 2, 11, 1), (263, 4, 131, 2), (167, 4, 83, 1)],
)
def test_byte_length_rounds_bit_length_up(
    prime: int, generator: int, subgroup_order: int, expected: int
) -> None:
    """byte_length is ceil(bit_length / 8): 5 and 8 bits fit in 1 byte, 9 need 2."""
    parameters = DiffieHellmanParameters(
        prime=prime, generator=generator, subgroup_order=subgroup_order
    )

    assert parameters.byte_length == expected


def test_from_standard_preserves_parameters() -> None:
    """from_standard should construct the supplied parameters unchanged."""
    prime = 23
    generator = 2
    subgroup_order = 11

    parameters = DiffieHellmanParameters.from_standard(
        prime=prime,
        generator=generator,
        subgroup_order=subgroup_order,
    )

    assert parameters.prime == prime
    assert parameters.generator == generator
    assert parameters.subgroup_order == subgroup_order


def test_from_standard_returns_parameters_instance() -> None:
    """from_standard should return a DiffieHellmanParameters instance."""
    parameters = DiffieHellmanParameters.from_standard(
        prime=23,
        generator=2,
        subgroup_order=11,
    )

    assert isinstance(parameters, DiffieHellmanParameters)


def test_parameters_are_immutable() -> None:
    """Parameters should be immutable because the dataclass is frozen."""
    parameters = DiffieHellmanParameters(
        prime=23,
        generator=2,
        subgroup_order=11,
    )

    with pytest.raises(FrozenInstanceError):
        setattr(parameters, "prime", 29)


def test_parameters_are_hashable() -> None:
    """Frozen parameters should be usable as dictionary keys."""
    parameters = DiffieHellmanParameters(
        prime=23,
        generator=2,
        subgroup_order=11,
    )

    values = {parameters: "dh"}

    assert values[parameters] == "dh"

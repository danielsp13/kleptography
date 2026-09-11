"""
Tests for prime number utilities.
"""

from __future__ import annotations

from unittest.mock import Mock

import pytest
from sympy import isprime

import kleptography.math.primes as primes
from kleptography.math.primes import (
    generate_safe_prime,
    generate_subgroup_generator,
)


def test_generate_safe_prime_returns_safe_prime() -> None:
    """Generated safe primes must have a prime Sophie Germain subgroup order."""
    prime = generate_safe_prime(128)

    subgroup_order = (prime - 1) // 2

    assert isprime(prime)
    assert isprime(subgroup_order)


def test_generate_safe_prime_has_requested_bit_length() -> None:
    """Generated safe prime should have the requested bit length."""
    bits = 128

    prime = generate_safe_prime(bits)

    assert prime.bit_length() == bits


def test_generate_safe_prime_has_expected_structure() -> None:
    """A safe prime must satisfy p = 2q + 1."""
    prime = generate_safe_prime(128)

    subgroup_order = (prime - 1) // 2

    assert prime == 2 * subgroup_order + 1


@pytest.mark.parametrize("bits", [0, 1, 2, -1, -128])
def test_generate_safe_prime_rejects_too_few_bits(bits: int) -> None:
    """generate_safe_prime should reject bit lengths below three."""
    with pytest.raises(ValueError, match="bits must be at least 3"):
        generate_safe_prime(bits)


def test_generate_safe_prime_retries_when_candidate_is_not_safe_prime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    generate_safe_prime should retry when the generated q does not produce
    a prime p = 2q + 1.
    """
    # The first q produces p = 11, which we mark as non-prime.
    # The second q produces p = 23, which we mark as prime.
    randprime = Mock(side_effect=[5, 11])

    def fake_isprime(value: int) -> bool:
        return value == 23

    monkeypatch.setattr(primes, "randprime", randprime)
    monkeypatch.setattr(primes, "isprime", fake_isprime)

    result = generate_safe_prime(4)

    assert result == 23
    assert randprime.call_count == 2


def test_generate_subgroup_generator_rejects_non_prime() -> None:
    """generate_subgroup_generator should reject a non-prime input."""
    with pytest.raises(ValueError, match="prime must be prime"):
        generate_subgroup_generator(15)


def test_generate_subgroup_generator_rejects_non_safe_prime() -> None:
    """generate_subgroup_generator should reject a prime that is not safe."""
    # 13 is prime, but (13 - 1) / 2 = 6 is not prime.
    with pytest.raises(ValueError, match="prime must be a safe prime"):
        generate_subgroup_generator(13)


def test_generate_subgroup_generator_returns_generator() -> None:
    """A generated subgroup generator must have the expected order."""
    prime = generate_safe_prime(128)
    subgroup_order = (prime - 1) // 2

    generator = generate_subgroup_generator(prime)

    assert generator != 1
    assert pow(generator, subgroup_order, prime) == 1


def test_generate_subgroup_generator_belongs_to_subgroup() -> None:
    """The generated value must be a non-zero element modulo p."""
    prime = generate_safe_prime(128)

    generator = generate_subgroup_generator(prime)

    assert 1 < generator < prime


def test_generate_subgroup_generator_is_not_a_primitive_root() -> None:
    """
    A subgroup generator has order q, not p - 1.

    Therefore g^q = 1 while a primitive root would have g^q != 1.
    """
    prime = generate_safe_prime(128)
    subgroup_order = (prime - 1) // 2

    generator = generate_subgroup_generator(prime)

    assert pow(generator, subgroup_order, prime) == 1
    assert pow(generator, 2, prime) != 1


def test_generate_subgroup_generator_raises_when_no_primitive_root_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing primitive root should raise RuntimeError."""
    monkeypatch.setattr(primes, "primitive_root", lambda _: None)

    with pytest.raises(RuntimeError, match="No primitive root found"):
        generate_subgroup_generator(23)


def test_generate_subgroup_generator_converts_primitive_root_to_int(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    The primitive root returned by SymPy should be converted to int before
    exponentiation.
    """
    primitive_root = Mock()
    primitive_root.__int__ = Mock(return_value=5)

    monkeypatch.setattr(primes, "primitive_root", lambda _: primitive_root)

    result = generate_subgroup_generator(23)

    assert result == pow(5, 2, 23)
    primitive_root.__int__.assert_called_once()

"""
Tests for prime number utilities.
"""

from __future__ import annotations

from sympy import isprime

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


def test_generate_subgroup_generator_has_correct_order() -> None:
    """
    A generator of the DH subgroup must have order q.

    For a safe prime p = 2q + 1:

        g^q ≡ 1 (mod p)

    and, because q is prime and g != 1, the order of g is exactly q.
    """
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

"""
Prime number utilities.
"""

from __future__ import annotations

from sympy import isprime
from sympy import primitive_root
from sympy import randprime


def generate_prime(bits: int) -> int:
    """
    Generate a random prime with approximately the requested bit length.

    Args:
        bits: The requested bit length of the prime.

    Returns:
        A randomly generated prime with ``bits`` bits.

    Raises:
        ValueError: If ``bits`` is less than two.
    """
    if bits < 2:
        raise ValueError("bits must be at least 2.")

    lower = 1 << (bits - 1)
    upper = 1 << bits

    return int(randprime(lower, upper))


def generate_safe_prime(bits: int) -> int:
    """
    Generate a random safe prime with approximately the requested bit length.

    A safe prime is a prime ``p`` such that ``p = 2q + 1``, where ``q`` is
    also prime.

    Args:
        bits: The requested bit length of the safe prime.

    Returns:
        A randomly generated safe prime with ``bits`` bits.

    Raises:
        ValueError: If ``bits`` is less than three.
    """
    if bits < 3:
        raise ValueError("bits must be at least 3.")

    lower = 1 << (bits - 2)
    upper = 1 << (bits - 1)

    while True:
        q = int(randprime(lower, upper))
        p = 2 * q + 1

        if isprime(p):
            return p


def is_prime(value: int) -> bool:
    """
    Determine whether an integer is prime.

    Args:
        value: The integer to test.

    Returns:
        ``True`` if ``value`` is prime, otherwise ``False``.
    """
    return bool(isprime(value))


def generate_generator(prime: int) -> int:
    """
    Generate a primitive root modulo a prime.

    The returned value generates the multiplicative group of integers
    modulo ``prime``.

    Args:
        prime: The prime modulus for which to find a primitive root.

    Returns:
        A primitive root modulo ``prime``.

    Raises:
        ValueError: If ``prime`` is not prime.
        RuntimeError: If no primitive root can be found.
    """
    if not isprime(prime):
        raise ValueError("prime must be prime.")

    generator = primitive_root(prime)

    if generator is None:
        raise RuntimeError("No primitive root found.")

    return int(generator)

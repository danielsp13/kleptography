"""Utility functions for modular arithmetic."""

from __future__ import annotations

from math import gcd


def mod_pow(base: int, exponent: int, modulus: int) -> int:
    """Compute the modular exponentiation of an integer.

    Returns the remainder of ``base`` raised to ``exponent`` modulo
    ``modulus``. This function is a thin wrapper around Python's built-in
    modular exponentiation and is equivalent to
    ``pow(base, exponent, modulus)``.

    Args:
        base: The integer base.
        exponent: The integer exponent.
        modulus: The positive modulus.

    Returns:
        The value of ``(base ** exponent) mod modulus``.

    Raises:
        ValueError: If ``modulus`` is not positive.
    """
    if modulus <= 0:
        raise ValueError("The modulus must be positive.")

    return pow(base, exponent, modulus)


def mod_inverse(value: int, modulus: int) -> int:
    """Compute the multiplicative inverse of an integer modulo a modulus.

    An inverse exists if and only if ``value`` and ``modulus`` are coprime.
    The returned integer ``inverse`` satisfies
    ``(value * inverse) % modulus == 1``.

    Args:
        value: The integer whose multiplicative inverse is required.
        modulus: The modulus, which must be greater than one.

    Returns:
        The multiplicative inverse of ``value`` modulo ``modulus``.

    Raises:
        ValueError: If ``modulus`` is not greater than one or if ``value``
            has no multiplicative inverse modulo ``modulus``.
    """
    if modulus <= 1:
        raise ValueError("The modulus must be greater than one.")

    if gcd(value, modulus) != 1:
        raise ValueError(f"{value} has no multiplicative inverse modulo {modulus}.")

    return pow(value, -1, modulus)


def is_coprime(a: int, b: int) -> bool:
    """Determine whether two integers are coprime.

    Two integers are coprime if their greatest common divisor is equal to
    one.

    Args:
        a: The first integer.
        b: The second integer.

    Returns:
        ``True`` if ``a`` and ``b`` are coprime, otherwise ``False``.
    """
    return gcd(a, b) == 1

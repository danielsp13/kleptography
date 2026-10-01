"""Prime number utilities."""

from __future__ import annotations

from sympy import isprime, primitive_root, randprime


def generate_safe_prime(bits: int) -> int:
    """Generate a random safe prime with the requested bit length.

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


def generate_subgroup_generator(prime: int) -> int:
    """Generate a generator of the order-(p - 1) / 2 subgroup modulo a safe prime.

    Args:
        prime: A safe prime.

    Returns:
        An element of order ``(prime - 1) // 2``.

    Raises:
        ValueError: If ``prime`` is not a safe prime.
        RuntimeError: If no primitive root can be found.
    """
    if not isprime(prime):
        raise ValueError("prime must be prime.")

    subgroup_order = (prime - 1) // 2

    if not isprime(subgroup_order):
        raise ValueError("prime must be a safe prime.")

    primitive_root_value = primitive_root(prime)

    if primitive_root_value is None:
        raise RuntimeError("No primitive root found.")

    return pow(int(primitive_root_value), 2, prime)

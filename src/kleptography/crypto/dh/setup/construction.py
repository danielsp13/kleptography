"""
Equations of the Young-Yung SETUP, as pure functions.

Device side and attacker side are kept next to each other so that it is
easy to check that one undoes the other:

    device:   z  = g^(c1 - W*t) * Y^(-a*c1 - b)            mod p
    attacker: r  = m1^a * g^b,  z1 = m1 / r^X,  z2 = z1 / g^W   mod p

Since Y = g^X and m1 = g^c1, z1 is the device's z for t = 0 and z2 is the
device's z for t = 1.

Implementation hints: g and Y have order q, so exponents can be reduced
modulo q (a negative exponent e becomes e mod q). Use ``mod_pow`` and
``mod_inverse`` from ``kleptography.math.modular``, and the validators from
``kleptography.crypto.dh.validation``.
"""

from __future__ import annotations

from kleptography.crypto.dh.setup.configuration import YoungYungConfiguration


def compute_z(
    previous_private_key: int,
    *,
    correction_bit: int,
    configuration: YoungYungConfiguration,
) -> int:
    """
    Compute the device's intermediate value z (device side).

    Args:
        previous_private_key: The stored exponent c1 of the first exchange.
        correction_bit: The random bit t of the paper, 0 or 1.
        configuration: The constants embedded in the device.

    Returns:
        z = g^(c1 - W*t) * Y^(-a*c1 - b) mod p.

    Raises:
        InvalidPrivateKey: If c1 is outside [1, q - 1].
        ValueError: If ``correction_bit`` is not 0 or 1.
    """
    raise NotImplementedError("TODO: implement the device's z.")


def derive_private_key(
    previous_private_key: int,
    *,
    correction_bit: int,
    configuration: YoungYungConfiguration,
) -> int:
    """
    Derive the second private exponent c2 = H(z) (device side).

    Args:
        previous_private_key: The stored exponent c1 of the first exchange.
        correction_bit: The random bit t of the paper, 0 or 1.
        configuration: The constants embedded in the device.

    Returns:
        The exponent c2, validated as a private key.

    Raises:
        InvalidPrivateKey: If c1, or the output of H, is outside [1, q - 1].
        ValueError: If ``correction_bit`` is not 0 or 1.
    """
    raise NotImplementedError("TODO: implement c2 = H(z).")


def recover_z_candidates(
    first_public_key: int,
    *,
    attacker_private_key: int,
    configuration: YoungYungConfiguration,
) -> tuple[int, int]:
    """
    Recompute both possible values of z from m1 (attacker side).

    Args:
        first_public_key: The public value m1 = g^c1 seen on the channel.
        attacker_private_key: The attacker's private key X.
        configuration: The constants embedded in the device.

    Returns:
        The pair (z1, z2): z1 = m1 / r^X with r = m1^a * g^b, and
        z2 = z1 / g^W, all modulo p.

    Raises:
        InvalidPublicKey: If m1 is not a valid public value.
        InvalidPrivateKey: If X is outside [1, q - 1].
    """
    raise NotImplementedError("TODO: implement the attacker's z candidates.")

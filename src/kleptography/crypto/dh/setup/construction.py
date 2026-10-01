"""The SETUP equations of Young and Yung (EUROCRYPT '97) for Diffie-Hellman.

All exponents are reduced modulo q, and division modulo p is done with the
modular inverse. These are pure functions: the device and the attacker
classes call them.
"""

from __future__ import annotations

from kleptography.crypto.dh.exceptions import InvalidPrivateKey
from kleptography.crypto.dh.setup.configuration import YoungYungConfiguration
from kleptography.crypto.dh.setup.records import SetupDerivation
from kleptography.crypto.dh.validation import validate_private_key, validate_public_key
from kleptography.math.modular import mod_inverse, mod_pow


def compute_z(
    previous_private_key: int,
    *,
    correction_bit: int,
    configuration: YoungYungConfiguration,
) -> int:
    """Compute the device's value z = g^(c1 - W*t) * Y^(-a*c1 - b) mod p.

    Args:
        previous_private_key: The previous exponent c1.
        correction_bit: The bit t, 0 or 1.
        configuration: The SETUP configuration of the device.

    Returns:
        The group element z.

    Raises:
        InvalidPrivateKey: If c1 is outside [1, q - 1].
        ValueError: If t is not 0 or 1.
    """
    validate_private_key(
        previous_private_key, subgroup_order=configuration.parameters.subgroup_order
    )
    if correction_bit not in [0, 1]:
        raise ValueError("correction bit is not 0 or 1")

    prime = configuration.parameters.prime
    subgroup_order = configuration.parameters.subgroup_order

    # g and Y have order q, so negative exponents are reduced modulo q.
    left_expr = mod_pow(
        configuration.parameters.generator,
        (previous_private_key - configuration.correction_w * correction_bit)
        % subgroup_order,
        prime,
    )
    right_expr = mod_pow(
        configuration.attacker_public_key,
        (-configuration.multiplier_a * previous_private_key - configuration.offset_b)
        % subgroup_order,
        prime,
    )

    return (left_expr * right_expr) % prime


def derive_setup(
    previous_private_key: int,
    *,
    correction_bit: int,
    configuration: YoungYungConfiguration,
) -> SetupDerivation:
    """Derive the next exponent c2 = H(z) and keep every intermediate value.

    Args:
        previous_private_key: The previous exponent c1.
        correction_bit: The bit t, 0 or 1.
        configuration: The SETUP configuration of the device.

    Returns:
        The derivation (c1, t, z, c2).

    Raises:
        InvalidPrivateKey: If c1 is outside [1, q - 1], or H returns an
            exponent outside that range.
        ValueError: If t is not 0 or 1.
    """
    z = compute_z(
        previous_private_key,
        correction_bit=correction_bit,
        configuration=configuration,
    )
    c2 = configuration.hash_function(z, parameters=configuration.parameters)
    if not 1 <= c2 < configuration.parameters.subgroup_order:
        raise InvalidPrivateKey("'c2 = H(z)' is out of range [1, q - 1]")

    return SetupDerivation(
        previous_private_key=previous_private_key,
        correction_bit=correction_bit,
        z=z,
        private_key=c2,
    )


def derive_private_key(
    previous_private_key: int,
    *,
    correction_bit: int,
    configuration: YoungYungConfiguration,
) -> int:
    """Derive the next exponent c2 = H(z).

    Args:
        previous_private_key: The previous exponent c1.
        correction_bit: The bit t, 0 or 1.
        configuration: The SETUP configuration of the device.

    Returns:
        The exponent c2.

    Raises:
        InvalidPrivateKey: If c1 or c2 is outside [1, q - 1].
        ValueError: If t is not 0 or 1.
    """
    return derive_setup(
        previous_private_key,
        correction_bit=correction_bit,
        configuration=configuration,
    ).private_key


def compute_r(
    first_public_key: int,
    *,
    configuration: YoungYungConfiguration,
) -> int:
    """Compute the attacker's value r = m1^a * g^b mod p.

    Since r^X = Y^(a*c1 + b), r is the attacker's side of the mask that the
    device applied to z.

    Args:
        first_public_key: The first public key m1.
        configuration: The SETUP configuration of the device.

    Returns:
        The group element r.

    Raises:
        InvalidPublicKey: If m1 is not a public value of the group.
    """
    prime = configuration.parameters.prime
    subgroup_order = configuration.parameters.subgroup_order

    validate_public_key(
        first_public_key,
        prime=prime,
        subgroup_order=subgroup_order,
    )

    # Exponents are reduced modulo q (a or b may be negative or >= q).
    r_left_expr = mod_pow(
        first_public_key, configuration.multiplier_a % subgroup_order, prime
    )
    r_right_expr = mod_pow(
        configuration.parameters.generator,
        configuration.offset_b % subgroup_order,
        prime,
    )

    return (r_left_expr * r_right_expr) % prime


def recover_z_candidates(
    first_public_key: int,
    *,
    attacker_private_key: int,
    configuration: YoungYungConfiguration,
) -> tuple[int, int]:
    """Recover the candidates z1 = m1 / r^X and z2 = z1 / g^W modulo p.

    Args:
        first_public_key: The first public key m1.
        attacker_private_key: The attacker's private key X.
        configuration: The SETUP configuration of the device.

    Returns:
        The candidates (z1, z2), for t = 0 and t = 1.

    Raises:
        InvalidPublicKey: If m1 is not a public value of the group.
        InvalidPrivateKey: If X is outside [1, q - 1].
    """
    prime = configuration.parameters.prime
    subgroup_order = configuration.parameters.subgroup_order

    r = compute_r(first_public_key, configuration=configuration)
    validate_private_key(attacker_private_key, subgroup_order=subgroup_order)

    # Division modulo p is multiplication by the modular inverse.
    z1 = (
        first_public_key * mod_inverse(mod_pow(r, attacker_private_key, prime), prime)
    ) % prime
    g_to_w = mod_pow(
        configuration.parameters.generator,
        configuration.correction_w % subgroup_order,
        prime,
    )
    z2 = (z1 * mod_inverse(g_to_w, prime)) % prime

    return (z1, z2)

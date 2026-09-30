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

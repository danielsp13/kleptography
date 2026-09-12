"""
Validation helpers for finite-field Diffie-Hellman.

This module contains the mathematical validation rules for Diffie-Hellman
parameters, private exponents, and public values.

It deliberately does not depend on the DiffieHellmanParameters domain model
to avoid circular dependencies between the validation and parameter modules.
"""

from __future__ import annotations

from kleptography.crypto.dh.exceptions import (
    InvalidDiffieHellmanParameters,
    InvalidPrivateKey,
    InvalidPublicKey,
)
from kleptography.math.modular import mod_pow


def validate_parameters(
    *,
    prime: int,
    generator: int,
    subgroup_order: int,
) -> None:
    """
    Validate a finite-field Diffie-Hellman parameter set.

    The educational DH implementation uses a safe-prime subgroup of prime
    order q, where:

        p = 2q + 1

    and `generator` has order q modulo p.

    Raises
    ------
    InvalidDiffieHellmanParameters
        If the parameters do not satisfy the required invariants.
    """
    if prime <= 2:
        raise InvalidDiffieHellmanParameters("DH prime must be greater than 2.")

    if subgroup_order <= 1:
        raise InvalidDiffieHellmanParameters(
            "DH subgroup order must be greater than 1."
        )

    if not 1 < generator < prime:
        raise InvalidDiffieHellmanParameters(
            "DH generator must satisfy 1 < generator < prime."
        )

    if prime != 2 * subgroup_order + 1:
        raise InvalidDiffieHellmanParameters(
            "DH parameters must satisfy prime = 2 * subgroup_order + 1."
        )

    if mod_pow(generator, subgroup_order, prime) != 1:
        raise InvalidDiffieHellmanParameters(
            "DH generator must belong to the subgroup of order q."
        )


def validate_private_key(
    private_key: int,
    *,
    subgroup_order: int,
) -> None:
    """
    Validate a Diffie-Hellman private exponent.

    The private exponent must satisfy:

        1 <= private_key < q

    where q is the order of the subgroup.

    Raises
    ------
    InvalidPrivateKey
        If the private exponent is outside the valid range.
    """
    if not 1 <= private_key < subgroup_order:
        raise InvalidPrivateKey(
            "DH private key must satisfy 1 <= private_key < subgroup_order."
        )


def validate_public_key(
    public_key: int,
    *,
    prime: int,
    subgroup_order: int,
) -> None:
    """
    Validate a peer's Diffie-Hellman public value.

    A valid public value must be a non-identity element of the subgroup
    of order q modulo p. Therefore:

        1 < public_key < p

    and:

        public_key^q mod p = 1

    Raises
    ------
    InvalidPublicKey
        If the public value is outside the valid range or does not belong
        to the expected subgroup.
    """
    if not 1 < public_key < prime:
        raise InvalidPublicKey("DH public key must satisfy 1 < public_key < prime.")

    if mod_pow(public_key, subgroup_order, prime) != 1:
        raise InvalidPublicKey(
            "DH public key does not belong to the expected subgroup."
        )

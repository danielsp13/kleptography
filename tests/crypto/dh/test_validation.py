"""Tests for the validation of Diffie-Hellman values.

The validated values are the group parameters, private exponents and public
values.

They cover valid inputs, the boundary values, and every rejected case with
its exception type.
"""

from __future__ import annotations

import pytest

from kleptography.crypto.dh.exceptions import (
    InvalidDiffieHellmanParameters,
    InvalidPrivateKey,
    InvalidPublicKey,
)
from kleptography.crypto.dh.validation import (
    validate_parameters,
    validate_private_key,
    validate_public_key,
)


def test_validate_parameters() -> None:
    """Valid DH parameters pass validation."""
    validate_parameters(
        prime=23,
        generator=2,
        subgroup_order=11,
    )


def test_validate_parameters_rejects_small_prime() -> None:
    """A prime modulus must be greater than 2."""
    with pytest.raises(
        InvalidDiffieHellmanParameters,
        match="DH prime must be greater than 2.",
    ):
        validate_parameters(
            prime=2,
            generator=2,
            subgroup_order=1,
        )


def test_validate_parameters_rejects_small_subgroup_order() -> None:
    """The subgroup order must be greater than 1."""
    with pytest.raises(
        InvalidDiffieHellmanParameters,
        match="DH subgroup order must be greater than 1.",
    ):
        validate_parameters(
            prime=23,
            generator=2,
            subgroup_order=1,
        )


def test_validate_parameters_rejects_generator_outside_range() -> None:
    """The generator must be between 1 and the prime modulus."""
    with pytest.raises(
        InvalidDiffieHellmanParameters,
        match=r"DH generator must satisfy 1 < generator < prime\.",
    ):
        validate_parameters(
            prime=23,
            generator=23,
            subgroup_order=11,
        )


def test_validate_parameters_rejects_invalid_safe_prime_relation() -> None:
    """The modulus and subgroup order must satisfy p = 2q + 1."""
    with pytest.raises(
        InvalidDiffieHellmanParameters,
        match=r"DH parameters must satisfy prime = 2 \* subgroup_order \+ 1\.",
    ):
        validate_parameters(
            prime=23,
            generator=2,
            subgroup_order=5,
        )


def test_validate_parameters_rejects_generator_outside_subgroup() -> None:
    """The generator must belong to the subgroup of order q."""
    with pytest.raises(
        InvalidDiffieHellmanParameters,
        match="DH generator must belong to the subgroup of order q.",
    ):
        validate_parameters(
            prime=23,
            generator=5,
            subgroup_order=11,
        )


def test_validate_private_key() -> None:
    """A private exponent in [1, q - 1] passes validation."""
    validate_private_key(
        7,
        subgroup_order=11,
    )


def test_validate_private_key_accepts_lower_bound() -> None:
    """The smallest valid private exponent is 1."""
    validate_private_key(
        1,
        subgroup_order=11,
    )


def test_validate_private_key_accepts_upper_bound() -> None:
    """The largest valid private exponent is q - 1."""
    validate_private_key(
        10,
        subgroup_order=11,
    )


def test_validate_private_key_rejects_zero() -> None:
    """Zero is not a valid private exponent."""
    with pytest.raises(
        InvalidPrivateKey,
        match=r"DH private key must satisfy 1 <= private_key < subgroup_order\.",
    ):
        validate_private_key(
            0,
            subgroup_order=11,
        )


def test_validate_private_key_rejects_subgroup_order() -> None:
    """The subgroup order itself is outside the valid range."""
    with pytest.raises(
        InvalidPrivateKey,
        match=r"DH private key must satisfy 1 <= private_key < subgroup_order\.",
    ):
        validate_private_key(
            11,
            subgroup_order=11,
        )


def test_validate_public_key() -> None:
    """A non-identity element of the subgroup passes validation."""
    validate_public_key(
        4,
        prime=23,
        subgroup_order=11,
    )


def test_validate_public_key_rejects_identity() -> None:
    """The identity element is not accepted as a public key."""
    with pytest.raises(
        InvalidPublicKey,
        match=r"DH public key must satisfy 1 < public_key < prime\.",
    ):
        validate_public_key(
            1,
            prime=23,
            subgroup_order=11,
        )


def test_validate_public_key_rejects_zero() -> None:
    """Zero is not a valid public key."""
    with pytest.raises(
        InvalidPublicKey,
        match=r"DH public key must satisfy 1 < public_key < prime\.",
    ):
        validate_public_key(
            0,
            prime=23,
            subgroup_order=11,
        )


def test_validate_public_key_rejects_prime() -> None:
    """The modulus itself is not a valid public key."""
    with pytest.raises(
        InvalidPublicKey,
        match=r"DH public key must satisfy 1 < public_key < prime\.",
    ):
        validate_public_key(
            23,
            prime=23,
            subgroup_order=11,
        )


def test_validate_public_key_rejects_value_outside_subgroup() -> None:
    """A field element outside the expected subgroup is rejected."""
    with pytest.raises(
        InvalidPublicKey,
        match="DH public key does not belong to the expected subgroup.",
    ):
        validate_public_key(
            5,
            prime=23,
            subgroup_order=11,
        )

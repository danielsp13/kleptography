"""
Tests for modular arithmetic utilities.
"""

from __future__ import annotations

import pytest

from kleptography.math.modular import (
    is_coprime,
    mod_inverse,
    mod_pow,
)


def test_mod_pow_returns_modular_power() -> None:
    """mod_pow should return the modular exponentiation result."""
    assert mod_pow(2, 10, 1000) == 24


def test_mod_pow_handles_negative_base() -> None:
    """mod_pow should correctly handle negative bases."""
    assert mod_pow(-2, 3, 5) == 2


def test_mod_pow_rejects_non_positive_modulus() -> None:
    """mod_pow should reject zero and negative moduli."""
    with pytest.raises(ValueError, match="modulus must be positive"):
        mod_pow(2, 3, 0)

    with pytest.raises(ValueError, match="modulus must be positive"):
        mod_pow(2, 3, -5)


def test_mod_inverse_returns_multiplicative_inverse() -> None:
    """mod_inverse should return an inverse when values are coprime."""
    inverse = mod_inverse(3, 11)

    assert inverse == 4
    assert (3 * inverse) % 11 == 1


def test_mod_inverse_handles_negative_value() -> None:
    """mod_inverse should correctly handle negative values."""
    inverse = mod_inverse(-3, 11)

    assert inverse == 7
    assert (-3 * inverse) % 11 == 1


def test_mod_inverse_rejects_modulus_equal_to_one() -> None:
    """mod_inverse should reject modulus values less than or equal to one."""
    with pytest.raises(
        ValueError,
        match="modulus must be greater than one",
    ):
        mod_inverse(3, 1)


def test_mod_inverse_rejects_zero_modulus() -> None:
    """mod_inverse should reject a zero modulus."""
    with pytest.raises(
        ValueError,
        match="modulus must be greater than one",
    ):
        mod_inverse(3, 0)


def test_mod_inverse_rejects_negative_modulus() -> None:
    """mod_inverse should reject a negative modulus."""
    with pytest.raises(
        ValueError,
        match="modulus must be greater than one",
    ):
        mod_inverse(3, -11)


def test_mod_inverse_rejects_non_coprime_values() -> None:
    """mod_inverse should reject values without a multiplicative inverse."""
    with pytest.raises(
        ValueError,
        match="has no multiplicative inverse",
    ):
        mod_inverse(6, 9)


def test_is_coprime_returns_true_for_coprime_values() -> None:
    """is_coprime should return True when gcd is one."""
    assert is_coprime(8, 15) is True


def test_is_coprime_returns_false_for_non_coprime_values() -> None:
    """is_coprime should return False when gcd is greater than one."""
    assert is_coprime(8, 12) is False


def test_is_coprime_handles_zero() -> None:
    """is_coprime should correctly handle zero."""
    assert is_coprime(1, 0) is True
    assert is_coprime(2, 0) is False

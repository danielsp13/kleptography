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


@pytest.mark.parametrize(
    ("base", "exponent", "modulus"),
    [
        (2, 10, 17),
        (5, 117, 19),
        (123, 456, 97),
        (999, 12345, 65537),
    ],
)
def test_mod_pow_matches_builtin(
    base: int,
    exponent: int,
    modulus: int,
) -> None:
    """mod_pow should behave exactly like Python's built-in pow."""
    assert mod_pow(base, exponent, modulus) == pow(base, exponent, modulus)


@pytest.mark.parametrize(
    ("value", "modulus", "expected"),
    [
        (3, 11, 4),
        (7, 13, 2),
        (10, 17, 12),
    ],
)
def test_mod_inverse_returns_expected_inverse(
    value: int,
    modulus: int,
    expected: int,
) -> None:
    """Known modular inverses should be computed correctly."""
    assert mod_inverse(value, modulus) == expected


def test_mod_inverse_satisfies_definition() -> None:
    """a * a⁻¹ ≡ 1 (mod m)."""
    inverse = mod_inverse(12345, 65537)

    assert (12345 * inverse) % 65537 == 1


def test_mod_inverse_raises_if_inverse_does_not_exist() -> None:
    """Numbers that are not coprime have no inverse."""
    with pytest.raises(ValueError):
        mod_inverse(6, 12)


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        (7, 13, True),
        (12, 18, False),
        (35, 64, True),
    ],
)
def test_is_coprime(
    a: int,
    b: int,
    expected: bool,
) -> None:
    """Verify coprimality detection."""
    assert is_coprime(a, b) is expected

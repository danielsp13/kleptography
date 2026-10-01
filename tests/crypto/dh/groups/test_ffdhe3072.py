"""Tests for the RFC 7919 FFDHE3072 group.

They check the subgroup order given by the RFC, the bit length of p, the
primality of p and q, q = (p - 1) / 2, and that the generator has order q.
"""

from __future__ import annotations

from sympy import isprime

from kleptography.crypto.dh.groups.rfc7919.ffdhe3072 import ffdhe3072

EXPECTED_PRIME = int(
    """
    FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1
    D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9
    7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561
    2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935
    984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735
    30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB
    B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19
    0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61
    9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73
    3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA
    886B4238 611FCFDC DE355B3B 6519035B BC34F4DE F99C0238
    61B46FC9 D6E6C907 7AD91D26 91F7F7EE 598CB0FA C186D91C
    AEFE1309 85139270 B4130C93 BC437944 F4FD4452 E2D74DD3
    64F2E21E 71F54BFF 5CAE82AB 9C9DF69E E86D2BC5 22363A0D
    ABC52197 9B0DEADA 1DBF9A42 D5C4484E 0ABCD06B FA53DDEF
    3C1B20EE 3FD59D7C 25E41D2B 66C62E37 FFFFFFFF FFFFFFFF
    """.replace(" ", "").replace("\n", ""),
    16,
)

EXPECTED_SUBGROUP_ORDER = (EXPECTED_PRIME - 1) // 2


def test_ffdhe3072_returns_parameters() -> None:
    """FFDHE3072 should return DiffieHellmanParameters."""
    parameters = ffdhe3072()

    assert parameters.prime == EXPECTED_PRIME
    assert parameters.generator == 2


def test_ffdhe3072_has_expected_subgroup_order() -> None:
    """FFDHE3072 should use q = (p - 1) / 2."""
    parameters = ffdhe3072()

    assert parameters.subgroup_order == (parameters.prime - 1) // 2


def test_ffdhe3072_has_expected_bit_length() -> None:
    """FFDHE3072 should use a 3072-bit modulus."""
    parameters = ffdhe3072()

    assert parameters.bit_length == 3072


def test_ffdhe3072_prime_is_prime() -> None:
    """The FFDHE3072 modulus should be prime."""
    parameters = ffdhe3072()

    assert isprime(parameters.prime)


def test_ffdhe3072_subgroup_order_is_prime() -> None:
    """The FFDHE3072 subgroup order should be prime."""
    parameters = ffdhe3072()

    assert isprime(parameters.subgroup_order)


def test_ffdhe3072_generator_has_subgroup_order() -> None:
    """The generator should have order q."""
    parameters = ffdhe3072()

    assert (
        pow(
            parameters.generator,
            parameters.subgroup_order,
            parameters.prime,
        )
        == 1
    )


def test_ffdhe3072_has_rfc7919_subgroup_order() -> None:
    """FFDHE3072 should use the subgroup order specified by RFC 7919."""
    parameters = ffdhe3072()

    assert parameters.subgroup_order == EXPECTED_SUBGROUP_ORDER


def test_ffdhe3072_generator_is_non_trivial() -> None:
    """The generator should be a non-trivial element modulo p."""
    parameters = ffdhe3072()

    assert 1 < parameters.generator < parameters.prime

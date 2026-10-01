"""Value objects exposing every intermediate value of the SETUP."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SetupDerivation:
    """One SETUP derivation made by the device: c_i from c_{i-1}.

    Attributes:
        previous_private_key: The previous exponent c_{i-1}.
        correction_bit: The random bit t.
        z: The value z = g^(c_{i-1} - W*t) * Y^(-a*c_{i-1} - b) mod p.
        private_key: The new exponent c_i = H(z).
    """

    previous_private_key: int
    correction_bit: int
    z: int
    private_key: int


@dataclass(frozen=True, slots=True)
class SetupCandidates:
    """What the attacker computes from m1 alone, before checking against m2.

    Attributes:
        first_public_key: The first public key m1.
        r: The value r = m1^a * g^b mod p.
        z_candidates: The candidates (z1, z2) for t = 0 and t = 1.
        private_key_candidates: The candidate exponents (H(z1), H(z2)).
    """

    first_public_key: int
    r: int
    z_candidates: tuple[int, int]
    private_key_candidates: tuple[int, int]


@dataclass(frozen=True, slots=True)
class SetupRecovery:
    """A successful recovery of c2 from the public keys (m1, m2).

    Attributes:
        first_public_key: The first public key m1.
        second_public_key: The second public key m2.
        r: The value r = m1^a * g^b mod p.
        z_candidates: The candidates (z1, z2) for t = 0 and t = 1.
        private_key_candidates: The candidate exponents (H(z1), H(z2)).
        correction_bit: The bit t of the first candidate that matches m2.
        private_key: The recovered exponent c2, with g^c2 = m2.
    """

    first_public_key: int
    second_public_key: int
    r: int
    z_candidates: tuple[int, int]
    private_key_candidates: tuple[int, int]
    correction_bit: int
    private_key: int

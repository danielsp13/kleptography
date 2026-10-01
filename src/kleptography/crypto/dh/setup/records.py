from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SetupDerivation:
    previous_private_key: int
    correction_bit: int
    z: int
    private_key: int


# What the attacker computes from m1 alone, before checking against m2.
@dataclass(frozen=True, slots=True)
class SetupCandidates:
    first_public_key: int
    r: int
    z_candidates: tuple[int, int]
    private_key_candidates: tuple[int, int]


@dataclass(frozen=True, slots=True)
class SetupRecovery:
    first_public_key: int
    second_public_key: int
    r: int
    z_candidates: tuple[int, int]
    private_key_candidates: tuple[int, int]
    correction_bit: int
    private_key: int

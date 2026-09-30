from __future__ import annotations

from dataclasses import dataclass

from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.setup.exceptions import InvalidSetupConfiguration
from kleptography.crypto.dh.setup.hashing import SetupHashFunction, hash_to_exponent
from kleptography.crypto.dh.validation import validate_public_key


@dataclass(frozen=True, slots=True, kw_only=True)
class YoungYungConfiguration:
    parameters: DiffieHellmanParameters
    attacker_public_key: int
    multiplier_a: int
    offset_b: int
    correction_w: int
    hash_function: SetupHashFunction = hash_to_exponent

    def __post_init__(self) -> None:
        validate_public_key(
            self.attacker_public_key,
            prime=self.parameters.prime,
            subgroup_order=self.parameters.subgroup_order,
        )

        if self.multiplier_a % self.parameters.subgroup_order == 0:
            raise InvalidSetupConfiguration("Weak 'a' multiplier (a % q == 0)")
        if self.correction_w % 2 == 0:
            raise InvalidSetupConfiguration("'w' parameter is even")
        if self.correction_w % self.parameters.subgroup_order == 0:
            raise InvalidSetupConfiguration("Weak 'w' parameter (w % q == 0)")

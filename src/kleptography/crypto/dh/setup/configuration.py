"""The public configuration that the attacker embeds in the device."""

from __future__ import annotations

from dataclasses import dataclass

from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.setup.exceptions import InvalidSetupConfiguration
from kleptography.crypto.dh.setup.hashing import SetupHashFunction, hash_to_exponent
from kleptography.crypto.dh.validation import validate_public_key


@dataclass(frozen=True, slots=True, kw_only=True)
class YoungYungConfiguration:
    """The SETUP constants embedded in a compromised device.

    Everything here is public: a reverse engineer who opens the device learns
    it, but still cannot recover any exponent without the attacker's private
    key X. Names follow the paper.

    Attributes:
        parameters: The Diffie-Hellman group of the device.
        attacker_public_key: The attacker's public key Y = g^X mod p.
        multiplier_a: The paper's constant a, nonzero modulo q.
        offset_b: The paper's constant b.
        correction_w: The paper's odd constant W, nonzero modulo q.
        hash_function: The paper's function H.

    Raises:
        InvalidPublicKey: If Y is not a public value of the group.
        InvalidSetupConfiguration: If a or W is zero modulo q, or W is even.
    """

    parameters: DiffieHellmanParameters
    attacker_public_key: int
    multiplier_a: int
    offset_b: int
    correction_w: int
    hash_function: SetupHashFunction = hash_to_exponent

    def __post_init__(self) -> None:
        """Validate Y and the constants a and W."""
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

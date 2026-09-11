"""
Implementation of an honest Diffie-Hellman participant.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from secrets import randbelow

from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.math.modular import mod_pow


@dataclass(slots=True)
class DiffieHellmanParticipant:
    """
    Honest participant in a finite-field Diffie-Hellman key exchange.
    """

    parameters: DiffieHellmanParameters

    private_key: int | None = field(init=False, default=None, repr=False)
    public_key: int | None = field(init=False, default=None)

    def generate_keypair(self) -> None:
        """Generate a fresh Diffie-Hellman key pair."""
        self.private_key = self._generate_private_key()
        self.public_key = self._compute_public_key(self.private_key)

    def _generate_private_key(self) -> int:
        """
        Generate a uniformly random private exponent.

        The exponent belongs to [1, q - 1], where q is the order
        of the subgroup used by the DH parameters.
        """
        return randbelow(self.parameters.subgroup_order - 1) + 1

    def _compute_public_key(self, private_key: int) -> int:
        """Compute the public value g^x mod p."""
        return mod_pow(
            self.parameters.generator,
            private_key,
            self.parameters.prime,
        )

    def compute_shared_secret(self, peer_public_key: int) -> int:
        """
        Compute the shared DH secret from a peer's public value.

        Raises
        ------
        RuntimeError
            If no key pair has been generated.
        """
        if self.private_key is None:
            raise RuntimeError(
                "Key pair has not been generated. Call generate_keypair() first."
            )

        return mod_pow(
            peer_public_key,
            self.private_key,
            self.parameters.prime,
        )

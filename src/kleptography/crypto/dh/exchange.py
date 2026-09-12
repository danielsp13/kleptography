"""
Result types for the Diffie-Hellman protocol.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DiffieHellmanExchangeResult:
    """
    Result of a Diffie-Hellman key exchange.
    """

    alice_shared_secret: int
    bob_shared_secret: int

    @property
    def successful(self) -> bool:
        """
        Return whether both participants computed the same secret.
        """
        return self.alice_shared_secret == self.bob_shared_secret

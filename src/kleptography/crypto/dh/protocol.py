"""
Utility functions for executing the Diffie-Hellman protocol.
"""

from __future__ import annotations

from kleptography.crypto.dh.exchange import DiffieHellmanExchangeResult
from kleptography.crypto.dh.participant import DiffieHellmanParticipant


def perform_key_exchange(
    alice: DiffieHellmanParticipant,
    bob: DiffieHellmanParticipant,
) -> DiffieHellmanExchangeResult:
    """
    Execute an honest Diffie-Hellman key exchange.

    Both participants must have generated a key pair before calling
    this function.

    Raises
    ------
    RuntimeError
        If either participant has not generated a key pair.
    """
    if alice.public_key is None:
        raise RuntimeError("Alice has not generated a key pair.")

    if bob.public_key is None:
        raise RuntimeError("Bob has not generated a key pair.")

    alice_secret = alice.compute_shared_secret(
        bob.public_key,
    )

    bob_secret = bob.compute_shared_secret(
        alice.public_key,
    )

    return DiffieHellmanExchangeResult(
        alice_shared_secret=alice_secret,
        bob_shared_secret=bob_secret,
    )

from __future__ import annotations

import pytest

from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.participant import DiffieHellmanParticipant
from kleptography.crypto.dh.protocol import perform_key_exchange


@pytest.fixture
def parameters() -> DiffieHellmanParameters:
    """Return toy DH parameters suitable for testing."""
    return DiffieHellmanParameters.generate_toy(bits=32)


def test_perform_key_exchange(
    parameters: DiffieHellmanParameters,
) -> None:
    """Two participants derive the same shared secret."""
    alice = DiffieHellmanParticipant(parameters)
    bob = DiffieHellmanParticipant(parameters)

    alice.generate_keypair()
    bob.generate_keypair()

    result = perform_key_exchange(alice, bob)

    assert result.alice_shared_secret == result.bob_shared_secret
    assert result.successful is True


def test_perform_key_exchange_requires_alice_keypair(
    parameters: DiffieHellmanParameters,
) -> None:
    """Alice must generate a key pair before the exchange."""
    alice = DiffieHellmanParticipant(parameters)
    bob = DiffieHellmanParticipant(parameters)

    bob.generate_keypair()

    with pytest.raises(
        RuntimeError,
        match="Alice has not generated a key pair.",
    ):
        perform_key_exchange(alice, bob)


def test_perform_key_exchange_requires_bob_keypair(
    parameters: DiffieHellmanParameters,
) -> None:
    """Bob must generate a key pair before the exchange."""
    alice = DiffieHellmanParticipant(parameters)
    bob = DiffieHellmanParticipant(parameters)

    alice.generate_keypair()

    with pytest.raises(
        RuntimeError,
        match="Bob has not generated a key pair.",
    ):
        perform_key_exchange(alice, bob)

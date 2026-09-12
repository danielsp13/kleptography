from __future__ import annotations

import pytest

from kleptography.crypto.dh.exceptions import DiffieHellmanStateError
from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.participant import DiffieHellmanParticipant


@pytest.fixture
def parameters() -> DiffieHellmanParameters:
    """Return toy DH parameters suitable for testing."""
    return DiffieHellmanParameters.generate_toy(bits=32)


def test_participant_initial_state(
    parameters: DiffieHellmanParameters,
) -> None:
    """A participant starts without a generated key pair."""
    participant = DiffieHellmanParticipant(parameters)

    assert participant.parameters is parameters
    assert participant.private_key is None
    assert participant.public_key is None


def test_generate_keypair(
    parameters: DiffieHellmanParameters,
) -> None:
    """Generating a key pair sets valid private and public values."""
    participant = DiffieHellmanParticipant(parameters)

    participant.generate_keypair()

    assert participant.private_key is not None
    assert participant.public_key is not None

    assert 1 <= participant.private_key < parameters.subgroup_order
    assert 1 < participant.public_key < parameters.prime


def test_generate_keypair_produces_fresh_keypair(
    parameters: DiffieHellmanParameters,
) -> None:
    """Generating a key pair again replaces the previous key pair."""
    participant = DiffieHellmanParticipant(parameters)

    participant.generate_keypair()
    first_private_key = participant.private_key
    first_public_key = participant.public_key

    participant.generate_keypair()

    assert participant.private_key is not None
    assert participant.public_key is not None

    assert (
        participant.private_key != first_private_key
        or participant.public_key != first_public_key
    )


def test_compute_shared_secret(
    parameters: DiffieHellmanParameters,
) -> None:
    """Two participants derive the same shared secret."""
    alice = DiffieHellmanParticipant(parameters)
    bob = DiffieHellmanParticipant(parameters)

    alice.generate_keypair()
    bob.generate_keypair()

    assert alice.public_key is not None
    assert bob.public_key is not None

    alice_secret = alice.compute_shared_secret(bob.public_key)
    bob_secret = bob.compute_shared_secret(alice.public_key)

    assert alice_secret == bob_secret


def test_compute_shared_secret_requires_keypair(
    parameters: DiffieHellmanParameters,
) -> None:
    """Computing a secret before key generation raises DiffieHellmanStateError."""
    participant = DiffieHellmanParticipant(parameters)

    with pytest.raises(
        DiffieHellmanStateError,
        match="Key pair has not been generated. Call generate_keypair\\(\\) first.",
    ):
        participant.compute_shared_secret(2)


def test_private_key_generation_range(
    parameters: DiffieHellmanParameters,
) -> None:
    """Private exponents are sampled from [1, q - 1]."""
    participant = DiffieHellmanParticipant(parameters)

    private_key = participant._generate_private_key()

    assert 1 <= private_key < parameters.subgroup_order


def test_compute_public_key(
    parameters: DiffieHellmanParameters,
) -> None:
    """The public key is computed as g^x mod p."""
    participant = DiffieHellmanParticipant(parameters)
    private_key = 7

    public_key = participant._compute_public_key(private_key)

    assert public_key == pow(
        parameters.generator,
        private_key,
        parameters.prime,
    )


def test_compute_public_key_with_generated_private_key(
    parameters: DiffieHellmanParameters,
) -> None:
    """A generated private exponent produces a valid public value."""
    participant = DiffieHellmanParticipant(parameters)

    private_key = participant._generate_private_key()
    public_key = participant._compute_public_key(private_key)

    assert 1 < public_key < parameters.prime
    assert public_key == pow(
        parameters.generator,
        private_key,
        parameters.prime,
    )

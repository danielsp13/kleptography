"""Tests for ``DiffieHellmanParticipant``, the honest participant.

They check key generation and loading, the invariant public = g^x mod p,
the read-only key material, the shared secret, and the errors raised when a
key pair or the peer's public value is missing.
"""

from __future__ import annotations

import pytest

from kleptography.crypto.dh.exceptions import (
    DiffieHellmanStateError,
    InvalidPrivateKey,
)
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
    assert participant.has_keypair is False


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


@pytest.fixture
def toy_parameters() -> DiffieHellmanParameters:
    """Return the fixed toy group p = 23, g = 2, q = 11."""
    return DiffieHellmanParameters(prime=23, generator=2, subgroup_order=11)


def test_generate_keypair_sets_has_keypair(
    parameters: DiffieHellmanParameters,
) -> None:
    """A participant holds a key pair after generating one."""
    participant = DiffieHellmanParticipant(parameters)

    participant.generate_keypair()

    assert participant.has_keypair is True


def test_load_private_key_derives_public_key(
    toy_parameters: DiffieHellmanParameters,
) -> None:
    """Loading a known exponent derives g^x mod p."""
    participant = DiffieHellmanParticipant(toy_parameters)

    participant.load_private_key(6)

    assert participant.private_key == 6
    assert participant.public_key == 18
    assert participant.has_keypair is True


def test_load_private_key_replaces_previous_keypair(
    toy_parameters: DiffieHellmanParameters,
) -> None:
    """Loading an exponent replaces a previously generated key pair."""
    participant = DiffieHellmanParticipant(toy_parameters)
    participant.generate_keypair()

    participant.load_private_key(7)

    assert participant.private_key == 7
    assert participant.public_key == 13


@pytest.mark.parametrize("private_key", [0, -1, 11, 12])
def test_load_private_key_rejects_out_of_range_exponent(
    toy_parameters: DiffieHellmanParameters,
    private_key: int,
) -> None:
    """Exponents outside [1, q - 1] are rejected and leave no key pair."""
    participant = DiffieHellmanParticipant(toy_parameters)

    with pytest.raises(InvalidPrivateKey):
        participant.load_private_key(private_key)

    assert participant.has_keypair is False


@pytest.mark.parametrize("private_key", [1, 10])
def test_load_private_key_accepts_boundary_exponents(
    toy_parameters: DiffieHellmanParameters,
    private_key: int,
) -> None:
    """The boundary exponents 1 and q - 1 are valid."""
    participant = DiffieHellmanParticipant(toy_parameters)

    participant.load_private_key(private_key)

    assert participant.public_key == pow(2, private_key, 23)


@pytest.mark.parametrize("attribute", ["private_key", "public_key", "has_keypair"])
def test_keypair_attributes_are_read_only(
    toy_parameters: DiffieHellmanParameters,
    attribute: str,
) -> None:
    """Key material cannot be assigned directly, keeping (x, g^x) consistent."""
    participant = DiffieHellmanParticipant(toy_parameters)

    with pytest.raises(AttributeError):
        setattr(participant, attribute, 5)


def test_private_key_is_hidden_from_repr(
    toy_parameters: DiffieHellmanParameters,
) -> None:
    """The private exponent does not leak through repr."""
    participant = DiffieHellmanParticipant(toy_parameters)
    participant.load_private_key(6)

    assert "_private_key" not in repr(participant)
    assert "_public_key=18" in repr(participant)


def test_compute_shared_secret_requires_peer_public_key(
    toy_parameters: DiffieHellmanParameters,
) -> None:
    """A missing peer public value raises DiffieHellmanStateError."""
    participant = DiffieHellmanParticipant(toy_parameters)
    participant.load_private_key(6)

    with pytest.raises(DiffieHellmanStateError):
        participant.compute_shared_secret(None)

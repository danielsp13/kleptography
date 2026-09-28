"""
Implementation of an honest Diffie-Hellman participant.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from secrets import randbelow

from kleptography.crypto.dh.exceptions import DiffieHellmanStateError
from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.validation import (
    validate_private_key,
    validate_public_key,
)
from kleptography.math.modular import mod_pow


@dataclass(slots=True)
class DiffieHellmanParticipant:
    """
    Honest participant in a finite-field Diffie-Hellman key exchange.

    The key pair is read-only from the outside. It can only be set through
    ``generate_keypair()`` (fresh random exponent) or ``load_private_key()``
    (known exponent, e.g. for reproducible demonstrations). Both derive the
    public value from the private exponent, so ``public_key == g^x mod p``
    always holds.
    """

    parameters: DiffieHellmanParameters

    _private_key: int | None = field(init=False, default=None, repr=False)
    _public_key: int | None = field(init=False, default=None)

    @property
    def private_key(self) -> int | None:
        """Return the private exponent x, or ``None`` if not set."""
        return self._private_key

    @property
    def public_key(self) -> int | None:
        """Return the public value g^x mod p, or ``None`` if not set."""
        return self._public_key

    @property
    def has_keypair(self) -> bool:
        """Return whether the participant holds a key pair."""
        return self._private_key is not None

    def generate_keypair(self) -> None:
        """Generate a fresh Diffie-Hellman key pair, replacing any previous one."""
        self._set_keypair(self._generate_private_key())

    def load_private_key(self, private_key: int) -> None:
        """
        Use a known private exponent, replacing any previous key pair.

        The public value is derived from the exponent.

        Raises
        ------
        InvalidPrivateKey
            If the private exponent is outside [1, q - 1].
        """
        validate_private_key(
            private_key,
            subgroup_order=self.parameters.subgroup_order,
        )

        self._set_keypair(private_key)

    def _set_keypair(self, private_key: int) -> None:
        """Store a private exponent together with its public value."""
        self._private_key = private_key
        self._public_key = self._compute_public_key(private_key)

    def _generate_private_key(self) -> int:
        """
        Generate a uniformly random private exponent.

        The exponent belongs to [1, q - 1], where q is the order
        of the subgroup used by the DH parameters.
        """
        private_key = randbelow(self.parameters.subgroup_order - 1) + 1

        validate_private_key(
            private_key,
            subgroup_order=self.parameters.subgroup_order,
        )

        return private_key

    def _compute_public_key(self, private_key: int) -> int:
        """Compute the public value g^x mod p."""
        return mod_pow(
            self.parameters.generator,
            private_key,
            self.parameters.prime,
        )

    def compute_shared_secret(self, peer_public_key: int | None) -> int:
        """
        Compute the shared DH secret from a peer's public value.

        Raises
        ------
        DiffieHellmanStateError
            If no key pair has been generated or the peer public key
            is missing.
        InvalidPublicKey
            If the peer public key does not belong to the expected subgroup.
        """
        if peer_public_key is None:
            raise DiffieHellmanStateError("Public Key from other participant is None.")

        private_key = self._private_key
        if private_key is None:
            raise DiffieHellmanStateError(
                "Key pair has not been generated. Call generate_keypair() first."
            )

        validate_public_key(
            peer_public_key,
            prime=self.parameters.prime,
            subgroup_order=self.parameters.subgroup_order,
        )

        return mod_pow(
            peer_public_key,
            private_key,
            self.parameters.prime,
        )

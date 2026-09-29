"""
The attacker of the Young-Yung SETUP: the only party holding X.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.setup.configuration import YoungYungConfiguration


@dataclass(frozen=True, slots=True)
class YoungYungAttacker:
    """
    Attacker who designed the device and holds the private key X.

    The attacker only observes the public channel: the device's public
    values m1 and m2, and the honest peer's public value.

    Attributes:
        parameters: The DH group shared with the device.
        private_key: The attacker's private key X, in [1, q - 1].
    """

    parameters: DiffieHellmanParameters
    private_key: int = field(repr=False)

    def __post_init__(self) -> None:
        """
        Validate the attacker's private key.

        Raises:
            InvalidPrivateKey: If X is outside [1, q - 1].
        """
        raise NotImplementedError("TODO: validate X.")

    @property
    def public_key(self) -> int:
        """Return the public key Y = g^X mod p embedded in the device."""
        raise NotImplementedError("TODO: compute Y.")

    @classmethod
    def generate(cls, parameters: DiffieHellmanParameters) -> YoungYungAttacker:
        """Create an attacker with a fresh random private key X."""
        raise NotImplementedError("TODO: generate X.")

    def recover_private_key(
        self,
        *,
        first_public_key: int,
        second_public_key: int,
        configuration: YoungYungConfiguration,
    ) -> int:
        """
        Recover the device's second exponent c2 from m1 and m2.

        Args:
            first_public_key: m1, the device's first public value.
            second_public_key: m2, the device's second public value.
            configuration: The constants embedded in the device.

        Returns:
            c2 = H(z1) if g^H(z1) == m2, otherwise H(z2).

        Raises:
            InvalidSetupConfiguration: If the configuration does not embed
                this attacker's public key.
            InvalidPublicKey: If m1 or m2 is not a valid public value.
            SetupRecoveryError: If neither candidate matches m2 (m2 was not
                produced by this SETUP from m1).
        """
        raise NotImplementedError("TODO: recover c2.")

    def recover_shared_secret(
        self,
        *,
        first_public_key: int,
        second_public_key: int,
        peer_public_key: int,
        configuration: YoungYungConfiguration,
    ) -> int:
        """
        Recover the shared secret of the device's second exchange.

        Args:
            first_public_key: m1, the device's first public value.
            second_public_key: m2, the device's second public value.
            peer_public_key: The honest peer's public value in the second
                exchange.
            configuration: The constants embedded in the device.

        Returns:
            peer_public_key^c2 mod p.

        Raises:
            InvalidSetupConfiguration: See ``recover_private_key``.
            InvalidPublicKey: If any public value is invalid.
            SetupRecoveryError: See ``recover_private_key``.
        """
        raise NotImplementedError("TODO: recover the shared secret.")

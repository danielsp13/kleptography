"""The attacker of the Young-Yung SETUP, who alone holds the private key X."""

from __future__ import annotations

from dataclasses import dataclass, field
from secrets import randbelow

from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.setup.configuration import YoungYungConfiguration
from kleptography.crypto.dh.setup.construction import compute_r, recover_z_candidates
from kleptography.crypto.dh.setup.exceptions import (
    InvalidSetupConfiguration,
    SetupRecoveryError,
)
from kleptography.crypto.dh.setup.hashing import SetupHashFunction, hash_to_exponent
from kleptography.crypto.dh.setup.records import SetupCandidates, SetupRecovery
from kleptography.crypto.dh.validation import validate_private_key, validate_public_key
from kleptography.math.modular import mod_pow


@dataclass(frozen=True, slots=True)
class YoungYungAttacker:
    """The party that built the SETUP and can exploit it.

    From two consecutive public keys of the device, m1 and m2, the attacker
    recovers the second exponent c2 and therefore the second shared secret.

    Attributes:
        parameters: The Diffie-Hellman group of the device.
        private_key: The attacker's private key X.

    Raises:
        InvalidPrivateKey: If X is outside [1, q - 1].
    """

    parameters: DiffieHellmanParameters
    private_key: int = field(repr=False)

    def __post_init__(self) -> None:
        """Validate the attacker's private key X."""
        validate_private_key(
            self.private_key, subgroup_order=self.parameters.subgroup_order
        )

    @property
    def public_key(self) -> int:
        """Return the attacker's public key Y = g^X mod p."""
        return mod_pow(
            self.parameters.generator, self.private_key, self.parameters.prime
        )

    @classmethod
    def generate(cls, parameters: DiffieHellmanParameters) -> YoungYungAttacker:
        """Create an attacker with a fresh random private key.

        Args:
            parameters: The Diffie-Hellman group of the device.

        Returns:
            A new attacker.
        """
        return cls(parameters, randbelow(parameters.subgroup_order - 1) + 1)

    def generate_configuration(
        self,
        *,
        hash_function: SetupHashFunction = hash_to_exponent,
    ) -> YoungYungConfiguration:
        """Generate the configuration to embed in a device.

        The constants a and b are random in [1, q - 1] and W is random and odd
        in [1, q - 2]. The degenerate a*X = 1 (mod q) is skipped.

        Args:
            hash_function: The function H to embed.

        Returns:
            A configuration that embeds this attacker's public key.

        Raises:
            InvalidSetupConfiguration: If q < 3.
        """
        subgroup_order = self.parameters.subgroup_order
        if subgroup_order < 3:
            raise InvalidSetupConfiguration("The group is too small for a SETUP.")

        # With a*X = 1 (mod q), z no longer depends on c1 and c2 takes only
        # two values. Only the attacker knows X, so only it can avoid it.
        multiplier_a = randbelow(subgroup_order - 1) + 1
        while multiplier_a * self.private_key % subgroup_order == 1:
            multiplier_a = randbelow(subgroup_order - 1) + 1

        return YoungYungConfiguration(
            parameters=self.parameters,
            attacker_public_key=self.public_key,
            multiplier_a=multiplier_a,
            offset_b=randbelow(subgroup_order - 1) + 1,
            correction_w=2 * randbelow((subgroup_order - 1) // 2) + 1,
            hash_function=hash_function,
        )

    def compute_candidates(
        self,
        *,
        first_public_key: int,
        configuration: YoungYungConfiguration,
    ) -> SetupCandidates:
        """Compute the candidate exponents from the first public key alone.

        Args:
            first_public_key: The first public key m1.
            configuration: The configuration embedded in the device.

        Returns:
            The value r and both candidates (z, H(z)).

        Raises:
            InvalidSetupConfiguration: If the configuration is for another
                group or does not embed this attacker's public key.
            InvalidPublicKey: If m1 is not a public value of the group.
        """
        self._validate_configuration(configuration)
        validate_public_key(
            first_public_key,
            prime=self.parameters.prime,
            subgroup_order=self.parameters.subgroup_order,
        )

        z_candidates = recover_z_candidates(
            first_public_key,
            attacker_private_key=self.private_key,
            configuration=configuration,
        )
        return SetupCandidates(
            first_public_key=first_public_key,
            r=compute_r(first_public_key, configuration=configuration),
            z_candidates=z_candidates,
            private_key_candidates=(
                configuration.hash_function(
                    z_candidates[0], parameters=self.parameters
                ),
                configuration.hash_function(
                    z_candidates[1], parameters=self.parameters
                ),
            ),
        )

    def match_candidates(
        self,
        candidates: SetupCandidates,
        *,
        second_public_key: int,
    ) -> SetupRecovery:
        """Keep the candidate whose exponent reproduces the second public key.

        Args:
            candidates: The candidates computed from m1.
            second_public_key: The second public key m2.

        Returns:
            The recovery, with the inferred t and the exponent c2.

        Raises:
            InvalidPublicKey: If m2 is not a public value of the group.
            SetupRecoveryError: If neither candidate reproduces m2.
        """
        prime = self.parameters.prime
        validate_public_key(
            second_public_key,
            prime=prime,
            subgroup_order=self.parameters.subgroup_order,
        )

        # t is unknown: try z1 (t = 0), then z2 (t = 1), and keep the one
        # whose exponent reproduces the observed m2.
        for correction_bit, c2 in enumerate(candidates.private_key_candidates):
            if mod_pow(self.parameters.generator, c2, prime) == second_public_key:
                return SetupRecovery(
                    first_public_key=candidates.first_public_key,
                    second_public_key=second_public_key,
                    r=candidates.r,
                    z_candidates=candidates.z_candidates,
                    private_key_candidates=candidates.private_key_candidates,
                    correction_bit=correction_bit,
                    private_key=c2,
                )

        raise SetupRecoveryError(
            "Neither candidate reproduces m2: it was not derived from m1 by this SETUP."
        )

    def recover(
        self,
        *,
        first_public_key: int,
        second_public_key: int,
        configuration: YoungYungConfiguration,
    ) -> SetupRecovery:
        """Recover the second exponent with every intermediate value.

        Args:
            first_public_key: The first public key m1.
            second_public_key: The second public key m2.
            configuration: The configuration embedded in the device.

        Returns:
            The recovery, with the candidates, the inferred t and c2.

        Raises:
            InvalidSetupConfiguration: If the configuration is for another
                group or does not embed this attacker's public key.
            InvalidPublicKey: If m1 or m2 is not a public value of the group.
            SetupRecoveryError: If neither candidate reproduces m2.
        """
        candidates = self.compute_candidates(
            first_public_key=first_public_key, configuration=configuration
        )
        return self.match_candidates(candidates, second_public_key=second_public_key)

    def _validate_configuration(self, configuration: YoungYungConfiguration) -> None:
        """Check that the configuration embeds this attacker and its group."""
        if (
            configuration.parameters != self.parameters
            or configuration.attacker_public_key != self.public_key
        ):
            raise InvalidSetupConfiguration(
                "The configuration does not embed this attacker's public key."
            )

    def recover_private_key(
        self,
        *,
        first_public_key: int,
        second_public_key: int,
        configuration: YoungYungConfiguration,
    ) -> int:
        """Recover the second exponent c2.

        Args:
            first_public_key: The first public key m1.
            second_public_key: The second public key m2.
            configuration: The configuration embedded in the device.

        Returns:
            The exponent c2.

        Raises:
            InvalidSetupConfiguration: If the configuration is for another
                group or does not embed this attacker's public key.
            InvalidPublicKey: If m1 or m2 is not a public value of the group.
            SetupRecoveryError: If neither candidate reproduces m2.
        """
        return self.recover(
            first_public_key=first_public_key,
            second_public_key=second_public_key,
            configuration=configuration,
        ).private_key

    def recover_shared_secret(
        self,
        *,
        first_public_key: int,
        second_public_key: int,
        peer_public_key: int,
        configuration: YoungYungConfiguration,
    ) -> int:
        """Recover the second shared secret, peer^c2 mod p.

        Args:
            first_public_key: The first public key m1.
            second_public_key: The second public key m2.
            peer_public_key: The peer's public key in the second exchange.
            configuration: The configuration embedded in the device.

        Returns:
            The shared secret of the second exchange.

        Raises:
            InvalidSetupConfiguration: If the configuration is for another
                group or does not embed this attacker's public key.
            InvalidPublicKey: If m1, m2 or the peer key is not a public value
                of the group.
            SetupRecoveryError: If neither candidate reproduces m2.
        """
        validate_public_key(
            peer_public_key,
            prime=self.parameters.prime,
            subgroup_order=self.parameters.subgroup_order,
        )

        second_private_key = self.recover_private_key(
            first_public_key=first_public_key,
            second_public_key=second_public_key,
            configuration=configuration,
        )

        return mod_pow(peer_public_key, second_private_key, self.parameters.prime)

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
    parameters: DiffieHellmanParameters
    private_key: int = field(repr=False)

    def __post_init__(self) -> None:
        validate_private_key(
            self.private_key, subgroup_order=self.parameters.subgroup_order
        )

    @property
    def public_key(self) -> int:
        return mod_pow(
            self.parameters.generator, self.private_key, self.parameters.prime
        )

    @classmethod
    def generate(cls, parameters: DiffieHellmanParameters) -> YoungYungAttacker:
        return cls(parameters, randbelow(parameters.subgroup_order - 1) + 1)

    def generate_configuration(
        self,
        *,
        hash_function: SetupHashFunction = hash_to_exponent,
    ) -> YoungYungConfiguration:
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
        candidates = self.compute_candidates(
            first_public_key=first_public_key, configuration=configuration
        )
        return self.match_candidates(candidates, second_public_key=second_public_key)

    def _validate_configuration(self, configuration: YoungYungConfiguration) -> None:
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

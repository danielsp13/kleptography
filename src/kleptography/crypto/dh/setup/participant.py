from __future__ import annotations

from dataclasses import dataclass, field
from secrets import randbelow

from kleptography.crypto.dh.exceptions import DiffieHellmanParametersMismatch
from kleptography.crypto.dh.participant import DiffieHellmanParticipant
from kleptography.crypto.dh.setup.configuration import YoungYungConfiguration
from kleptography.crypto.dh.setup.construction import derive_setup
from kleptography.crypto.dh.setup.records import SetupDerivation


@dataclass(slots=True)
class YoungYungDiffieHellmanParticipant(DiffieHellmanParticipant):
    configuration: YoungYungConfiguration

    # SETUP derivations of the current chain, in order: c2 from c1, c3 from c2, …
    # A new chain (honest c1 or a loaded key) starts empty.
    _derivations: list[SetupDerivation] = field(
        init=False, default_factory=list, repr=False
    )

    def __post_init__(self) -> None:
        if self.parameters != self.configuration.parameters:
            raise DiffieHellmanParametersMismatch(
                "The device and its SETUP configuration use different DH groups."
            )

    @property
    def derivations(self) -> tuple[SetupDerivation, ...]:
        return tuple(self._derivations)

    @property
    def last_derivation(self) -> SetupDerivation | None:
        return self._derivations[-1] if self._derivations else None

    def load_private_key(self, private_key: int) -> None:
        DiffieHellmanParticipant.load_private_key(self, private_key)
        self._derivations.clear()

    def _generate_private_key(self) -> int:
        previous_private_key = self._private_key
        if previous_private_key is None:
            self._derivations.clear()
            return DiffieHellmanParticipant._generate_private_key(self)

        derivation = derive_setup(
            previous_private_key,
            correction_bit=self._sample_correction_bit(),
            configuration=self.configuration,
        )
        self._derivations.append(derivation)
        return derivation.private_key

    def _sample_correction_bit(self) -> int:
        return randbelow(2)

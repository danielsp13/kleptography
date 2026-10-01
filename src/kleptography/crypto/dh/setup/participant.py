"""The compromised device: a Diffie-Hellman participant with a SETUP.

It is a separate class, never a flag of the honest participant, and a
drop-in replacement for it in the key exchange and the channel.
"""

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
    """A Diffie-Hellman participant whose exponents leak to the attacker.

    Its first exponent c1 is honest. Every later ``generate_keypair()`` derives
    the next exponent from the previous one with the SETUP (c2 from c1, c3 from
    c2, ...), so its public values look random to everyone but the attacker.

    Attributes:
        configuration: The SETUP configuration embedded by the attacker.

    Raises:
        DiffieHellmanParametersMismatch: If the device and its configuration
            use different groups.
    """

    configuration: YoungYungConfiguration

    # SETUP derivations of the current chain, in order: c2 from c1, c3 from c2, …
    # A new chain (honest c1 or a loaded key) starts empty.
    _derivations: list[SetupDerivation] = field(
        init=False, default_factory=list, repr=False
    )

    def __post_init__(self) -> None:
        """Check that the device and its configuration share the group."""
        if self.parameters != self.configuration.parameters:
            raise DiffieHellmanParametersMismatch(
                "The device and its SETUP configuration use different DH groups."
            )

    @property
    def derivations(self) -> tuple[SetupDerivation, ...]:
        """Return the SETUP derivations of the current chain, in order."""
        return tuple(self._derivations)

    @property
    def last_derivation(self) -> SetupDerivation | None:
        """Return the latest SETUP derivation, or ``None`` if there is none."""
        return self._derivations[-1] if self._derivations else None

    def load_private_key(self, private_key: int) -> None:
        """Use a known private exponent and start a new chain.

        Args:
            private_key: The private exponent to use.

        Raises:
            InvalidPrivateKey: If the private exponent is outside [1, q - 1].
        """
        DiffieHellmanParticipant.load_private_key(self, private_key)
        self._derivations.clear()

    def _generate_private_key(self) -> int:
        """Return an honest c1 first, then the SETUP derivation of the next."""
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
        """Sample the random correction bit t."""
        return randbelow(2)

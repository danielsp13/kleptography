"""
A Diffie-Hellman participant running inside a Young-Yung SETUP device.
"""

from __future__ import annotations

from dataclasses import dataclass

from kleptography.crypto.dh.participant import DiffieHellmanParticipant
from kleptography.crypto.dh.setup.configuration import YoungYungConfiguration


@dataclass(slots=True)
class YoungYungDiffieHellmanParticipant(DiffieHellmanParticipant):
    """
    Compromised DH participant: same public API as the honest one.

    It subclasses ``DiffieHellmanParticipant`` so that it can be passed to
    ``perform_key_exchange`` unchanged: from the outside it is the same black
    box. Only ``_generate_private_key`` differs:

    - Without a stored exponent (first exchange), it generates an honest,
      uniformly random exponent c1.
    - With a stored exponent c1 (the current ``_private_key``), it samples t
      and returns ``derive_private_key(c1, ...)``.

    Open question (research issue): what the device does from the third
    exchange onward. The tests only fix the first two exchanges.

    Pitfall: ``super()`` without arguments does not work inside methods of a
    ``slots=True`` dataclass on Python < 3.14 (the class is recreated). Call
    ``DiffieHellmanParticipant._generate_private_key(self)`` explicitly.
    """

    configuration: YoungYungConfiguration

    def __post_init__(self) -> None:
        """
        Check that the device and its configuration use the same group.

        Raises:
            DiffieHellmanParametersMismatch: If ``parameters`` differs from
                ``configuration.parameters``.
        """
        raise NotImplementedError("TODO: check the parameters.")

    def _generate_private_key(self) -> int:
        """Return an honest c1 first, and the SETUP exponent c2 afterwards."""
        raise NotImplementedError("TODO: implement the SETUP key generation.")

    def _sample_correction_bit(self) -> int:
        """Sample the paper's bit t uniformly from {0, 1} with ``secrets``."""
        raise NotImplementedError("TODO: sample t.")

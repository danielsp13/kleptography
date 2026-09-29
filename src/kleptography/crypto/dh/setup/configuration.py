"""
Constants that the attacker embeds in a Young-Yung SETUP device.
"""

from __future__ import annotations

from dataclasses import dataclass

from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.setup.hashing import SetupHashFunction, hash_to_exponent


@dataclass(frozen=True, slots=True, kw_only=True)
class YoungYungConfiguration:
    """
    Everything the attacker hard-codes into the compromised device.

    A reverse engineer who opens the device learns all of these values, but
    not the attacker's private key X. The SETUP must stay secure against
    that reverse engineer.

    Attributes:
        parameters: The DH group (p, g, q) used by the device.
        attacker_public_key: The attacker's public key Y = g^X mod p.
        multiplier_a: The constant a of the paper.
        offset_b: The constant b of the paper.
        correction_w: The constant W of the paper (an odd integer).
        hash_function: The hash function H of the paper.
    """

    parameters: DiffieHellmanParameters
    attacker_public_key: int
    multiplier_a: int
    offset_b: int
    correction_w: int
    hash_function: SetupHashFunction = hash_to_exponent

    def __post_init__(self) -> None:
        """
        Validate the embedded constants.

        Rules checked by the tests:

        - ``attacker_public_key`` is a valid public value of the group
          (reuse ``validate_public_key``; it raises ``InvalidPublicKey``).
        - ``multiplier_a`` is not 0 modulo q. Otherwise r = g^b is known to
          everyone and anybody could compute r^X = Y^b and recover c2.
        - ``correction_w`` is odd, as stated in the paper.
        - ``correction_w`` is not 0 modulo q. Otherwise g^W = 1, both
          candidates z1 and z2 coincide and t has no effect.

        Raises:
            InvalidPublicKey: If the attacker public key is invalid.
            InvalidSetupConfiguration: If a or W violates a rule above.
        """
        raise NotImplementedError("TODO: validate the SETUP configuration.")

"""
The hash function H of the Young-Yung SETUP.

H maps the group element z computed by the device to the next private
exponent c2. Both the device and the attacker must use the same H.
"""

from __future__ import annotations

from typing import Protocol

from kleptography.crypto.dh.parameters import DiffieHellmanParameters


class SetupHashFunction(Protocol):
    """Signature of any H usable by the SETUP device and the attacker."""

    def __call__(
        self,
        value: int,
        *,
        parameters: DiffieHellmanParameters,
    ) -> int:
        """Map a group element to a private exponent in [1, q - 1]."""
        ...


def hash_to_exponent(
    value: int,
    *,
    parameters: DiffieHellmanParameters,
) -> int:
    """
    Hash a group element to a valid private exponent (the paper's H).

    Requirements checked by the tests:

    - Deterministic: the attacker must obtain the same c2 as the device.
    - Output in [1, q - 1], so it passes ``validate_private_key``.
    - Full range: the output covers the whole exponent range even for
      2048-bit groups. A plain SHA-256 digest (256 bits) is therefore not
      enough; its output has to be expanded (e.g. SHAKE-256, or SHA-256 in
      counter mode) to more bits than q before reducing it.

    Args:
        value: The group element z, with 1 <= value < p.
        parameters: The DH group, which fixes p (input encoding) and q
            (output range).

    Returns:
        A private exponent in [1, q - 1].

    Raises:
        ValueError: If ``value`` is outside [1, p - 1].
    """
    raise NotImplementedError("TODO: implement H (see the docstring).")

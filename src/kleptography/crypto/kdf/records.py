"""Value objects for key derivation."""

from __future__ import annotations

from dataclasses import dataclass, field

from kleptography.crypto.kdf.exceptions import InvalidKeyDerivation

KEY_SIZE = 32
"""Derived key size in bytes (256 bits, one SHA-256 output block)."""


@dataclass(frozen=True, slots=True)
class KeyDerivation:
    """Every value involved in deriving a session key from a shared secret.

    The derivation is deterministic: the same shared secret always gives the
    same key. Nothing here adds secrecy beyond the shared secret itself, so
    whoever learns the shared secret can recompute the key.

    Attributes:
        shared_secret: The shared secret as an integer.
        encoded_secret: ``Z``, the shared secret as fixed-width big-endian bytes.
        other_info: The fixed context label bound into the key.
        key: The derived 32-byte key. Hidden from ``repr``.

    Raises:
        InvalidKeyDerivation: If ``encoded_secret`` does not encode
            ``shared_secret``, or ``key`` is not 32 bytes.
    """

    shared_secret: int = field(repr=False)
    encoded_secret: bytes = field(repr=False)
    other_info: bytes
    key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if int.from_bytes(self.encoded_secret, "big") != self.shared_secret:
            raise InvalidKeyDerivation(
                "The encoded secret does not encode the shared secret."
            )
        if not isinstance(self.key, bytes) or len(self.key) != KEY_SIZE:
            raise InvalidKeyDerivation(f"The key must be {KEY_SIZE} bytes.")

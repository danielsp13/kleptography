"""Value objects for authenticated encryption."""

from __future__ import annotations

from dataclasses import dataclass

from kleptography.crypto.aead.exceptions import InvalidAeadNonce, InvalidAeadTag

NONCE_SIZE = 12
"""GCM nonce size in bytes (96 bits, the size recommended by NIST SP 800-38D)."""

TAG_SIZE = 16
"""GCM authentication tag size in bytes (128 bits, the full tag)."""


@dataclass(frozen=True, slots=True)
class EncryptedMessage:
    """A message protected with AES-256-GCM, as it travels over the channel.

    Every field is public: an eavesdropper sees the nonce, the ciphertext and
    the tag. Confidentiality and integrity rely only on the secrecy of the key.
    The ciphertext has the same length as the plaintext (GCM is a stream mode,
    without padding), and the tag authenticates the nonce and the ciphertext.

    Attributes:
        nonce: The 12-byte nonce. It must never repeat under the same key.
        ciphertext: The encrypted bytes, as long as the plaintext.
        tag: The 16-byte authentication tag.

    Raises:
        InvalidAeadNonce: If ``nonce`` is not 12 bytes.
        InvalidAeadTag: If ``tag`` is not 16 bytes.
    """

    nonce: bytes
    ciphertext: bytes
    tag: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.nonce, bytes) or len(self.nonce) != NONCE_SIZE:
            raise InvalidAeadNonce(f"The nonce must be {NONCE_SIZE} bytes.")
        if not isinstance(self.tag, bytes) or len(self.tag) != TAG_SIZE:
            raise InvalidAeadTag(f"The authentication tag must be {TAG_SIZE} bytes.")

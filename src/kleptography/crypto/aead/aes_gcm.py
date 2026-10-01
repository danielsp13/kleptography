"""AES-256-GCM authenticated encryption (NIST SP 800-38D).

GCM combines AES in counter mode, which gives confidentiality, with the GHASH
authenticator, which gives integrity: a ciphertext decrypts only under the
key that produced it, and any change to the nonce, the ciphertext or the tag
is detected. The block cipher itself comes from the ``cryptography`` library
and is never reimplemented here.

This module adds no associated data, which keeps the demonstration focused
on the key: whoever holds it reads every message, whoever does not reads
none. It is educational code, not a hardened channel.
"""

from __future__ import annotations

from secrets import token_bytes

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from kleptography.crypto.aead.exceptions import (
    AeadAuthenticationError,
    InvalidAeadKey,
    InvalidAeadNonce,
)
from kleptography.crypto.aead.records import NONCE_SIZE, TAG_SIZE, EncryptedMessage

KEY_SIZE = 32
"""AES-256 key size in bytes."""


def generate_nonce() -> bytes:
    """Generate a fresh random nonce.

    The nonce is not secret: it travels next to the ciphertext. It only needs
    to be unique under a given key, and 96 random bits make a repetition
    negligible for the few messages of a demonstration.

    Returns:
        A random 12-byte nonce from ``secrets``.
    """
    return token_bytes(NONCE_SIZE)


def encrypt(
    key: bytes,
    plaintext: bytes,
    *,
    nonce: bytes | None = None,
) -> EncryptedMessage:
    """Encrypt and authenticate a message with AES-256-GCM.

    Args:
        key: The 32-byte symmetric key.
        plaintext: The bytes to protect. It may be empty.
        nonce: A 12-byte nonce. A fresh random one is generated when omitted.
            Pass it only for reproducible tests or test vectors: reusing a
            nonce under the same key breaks both confidentiality and
            integrity.

    Returns:
        The nonce, ciphertext and tag as an ``EncryptedMessage``.

    Raises:
        InvalidAeadKey: If ``key`` is not 32 bytes.
        InvalidAeadNonce: If ``nonce`` is given and is not 12 bytes.
    """
    _validate_key(key)
    if nonce is None:
        nonce = generate_nonce()
    elif not isinstance(nonce, bytes) or len(nonce) != NONCE_SIZE:
        raise InvalidAeadNonce(f"The nonce must be {NONCE_SIZE} bytes.")

    # The library returns the ciphertext followed by the tag.
    sealed = AESGCM(key).encrypt(nonce, plaintext, None)
    return EncryptedMessage(
        nonce=nonce,
        ciphertext=sealed[:-TAG_SIZE],
        tag=sealed[-TAG_SIZE:],
    )


def decrypt(key: bytes, message: EncryptedMessage) -> bytes:
    """Verify and decrypt a message protected with AES-256-GCM.

    The tag is checked before any plaintext is returned, so a wrong key and a
    tampered message fail in the same way.

    Args:
        key: The 32-byte symmetric key.
        message: The message produced by ``encrypt``.

    Returns:
        The original plaintext.

    Raises:
        InvalidAeadKey: If ``key`` is not 32 bytes.
        AeadAuthenticationError: If the tag does not verify under ``key``.
    """
    _validate_key(key)
    try:
        return AESGCM(key).decrypt(
            message.nonce,
            message.ciphertext + message.tag,
            None,
        )
    except InvalidTag as error:
        raise AeadAuthenticationError(
            "Authentication failed: wrong key or tampered message."
        ) from error


def _validate_key(key: bytes) -> None:
    """Check that the key is a 32-byte AES-256 key."""
    if not isinstance(key, bytes) or len(key) != KEY_SIZE:
        raise InvalidAeadKey(f"The key must be {KEY_SIZE} bytes (AES-256).")

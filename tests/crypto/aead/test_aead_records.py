from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from kleptography.crypto.aead.exceptions import InvalidAeadNonce, InvalidAeadTag
from kleptography.crypto.aead.records import NONCE_SIZE, TAG_SIZE, EncryptedMessage


def test_sizes_follow_sp_800_38d() -> None:
    """The nonce is 96 bits and the tag is the full 128 bits."""
    assert NONCE_SIZE == 12
    assert TAG_SIZE == 16


def test_encrypted_message_stores_its_fields() -> None:
    """An encrypted message keeps nonce, ciphertext and tag unchanged."""
    message = EncryptedMessage(nonce=bytes(12), ciphertext=b"abc", tag=bytes(16))

    assert message.nonce == bytes(12)
    assert message.ciphertext == b"abc"
    assert message.tag == bytes(16)


def test_encrypted_message_accepts_empty_ciphertext() -> None:
    """An empty plaintext gives an empty ciphertext, which is valid."""
    message = EncryptedMessage(nonce=bytes(12), ciphertext=b"", tag=bytes(16))

    assert message.ciphertext == b""


def test_encrypted_message_is_frozen() -> None:
    """An encrypted message cannot be modified after creation."""
    message = EncryptedMessage(nonce=bytes(12), ciphertext=b"abc", tag=bytes(16))

    with pytest.raises(FrozenInstanceError):
        message.ciphertext = b"xyz"  # ty: ignore[invalid-assignment]


@pytest.mark.parametrize("nonce", [b"", bytes(11), bytes(13), bytearray(12)])
def test_encrypted_message_rejects_invalid_nonce(nonce: bytes) -> None:
    """The nonce must be exactly 12 immutable bytes."""
    with pytest.raises(InvalidAeadNonce):
        EncryptedMessage(nonce=nonce, ciphertext=b"abc", tag=bytes(16))


@pytest.mark.parametrize("tag", [b"", bytes(15), bytes(17), bytearray(16)])
def test_encrypted_message_rejects_invalid_tag(tag: bytes) -> None:
    """The tag must be exactly 16 immutable bytes (no truncated tags)."""
    with pytest.raises(InvalidAeadTag):
        EncryptedMessage(nonce=bytes(12), ciphertext=b"abc", tag=tag)

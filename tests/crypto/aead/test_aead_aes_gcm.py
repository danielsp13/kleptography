from __future__ import annotations

from unittest.mock import patch

import pytest

from kleptography.crypto.aead.aes_gcm import KEY_SIZE, decrypt, encrypt, generate_nonce
from kleptography.crypto.aead.exceptions import (
    AeadAuthenticationError,
    InvalidAeadKey,
    InvalidAeadNonce,
)
from kleptography.crypto.aead.records import NONCE_SIZE, TAG_SIZE, EncryptedMessage

# Test cases 13-15 (AES-256, 96-bit IV, no associated data) from
# D. A. McGrew and J. Viega, "The Galois/Counter Mode of Operation (GCM)".
SPEC_KEY = bytes.fromhex("feffe9928665731c6d6a8f9467308308" * 2)
SPEC_NONCE = bytes.fromhex("cafebabefacedbaddecaf888")
SPEC_PLAINTEXT = bytes.fromhex(
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
)
SPEC_CIPHERTEXT = bytes.fromhex(
    "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
    "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad"
)
SPEC_TAG = bytes.fromhex("b094dac5d93471bdec1a502270e3cc6c")

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))
NONCE = bytes(range(12))
PLAINTEXT = b"Hola mundo"


@pytest.mark.parametrize(
    ("key", "nonce", "plaintext", "ciphertext", "tag"),
    [
        (
            bytes(32),
            bytes(12),
            b"",
            b"",
            bytes.fromhex("530f8afbc74536b9a963b4f1c4cb738b"),
        ),
        (
            bytes(32),
            bytes(12),
            bytes(16),
            bytes.fromhex("cea7403d4d606b6e074ec5d3baf39d18"),
            bytes.fromhex("d0d1c8a799996bf0265b98b5d48ab919"),
        ),
        (SPEC_KEY, SPEC_NONCE, SPEC_PLAINTEXT, SPEC_CIPHERTEXT, SPEC_TAG),
    ],
    ids=["test-case-13", "test-case-14", "test-case-15"],
)
def test_encrypt_matches_gcm_test_vectors(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    ciphertext: bytes,
    tag: bytes,
) -> None:
    """Encryption reproduces the published AES-256-GCM test vectors."""
    message = encrypt(key, plaintext, nonce=nonce)

    assert message == EncryptedMessage(nonce=nonce, ciphertext=ciphertext, tag=tag)
    assert decrypt(key, message) == plaintext


def test_round_trip_with_random_nonce() -> None:
    """A message encrypted with a fresh nonce decrypts to the plaintext."""
    message = encrypt(KEY, PLAINTEXT)

    assert len(message.nonce) == NONCE_SIZE
    assert len(message.tag) == TAG_SIZE
    assert decrypt(KEY, message) == PLAINTEXT


def test_ciphertext_has_the_length_of_the_plaintext() -> None:
    """GCM adds no padding: only the tag is added, outside the ciphertext."""
    message = encrypt(KEY, PLAINTEXT, nonce=NONCE)

    assert len(message.ciphertext) == len(PLAINTEXT)
    assert message.ciphertext != PLAINTEXT


def test_encryption_is_deterministic_for_a_fixed_nonce() -> None:
    """Same key, nonce and plaintext give the same message."""
    assert encrypt(KEY, PLAINTEXT, nonce=NONCE) == encrypt(KEY, PLAINTEXT, nonce=NONCE)


def test_random_nonces_give_different_ciphertexts() -> None:
    """Encrypting the same plaintext twice does not reveal it is repeated."""
    first = encrypt(KEY, PLAINTEXT)
    second = encrypt(KEY, PLAINTEXT)

    assert first.nonce != second.nonce
    assert first.ciphertext != second.ciphertext


def test_encrypt_draws_the_nonce_from_generate_nonce() -> None:
    """Without an explicit nonce, encryption uses generate_nonce()."""
    with patch(
        "kleptography.crypto.aead.aes_gcm.generate_nonce",
        return_value=NONCE,
    ) as generator:
        message = encrypt(KEY, PLAINTEXT)

    generator.assert_called_once_with()
    assert message == encrypt(KEY, PLAINTEXT, nonce=NONCE)


def test_generate_nonce_uses_secrets() -> None:
    """Nonces come from the secrets module and have 96 bits."""
    with patch(
        "kleptography.crypto.aead.aes_gcm.token_bytes",
        return_value=NONCE,
    ) as token_bytes:
        nonce = generate_nonce()

    token_bytes.assert_called_once_with(NONCE_SIZE)
    assert nonce == NONCE


def test_decrypt_with_wrong_key_fails() -> None:
    """A different key cannot read the message: the tag does not verify."""
    message = encrypt(KEY, PLAINTEXT, nonce=NONCE)

    with pytest.raises(AeadAuthenticationError):
        decrypt(OTHER_KEY, message)


def _flip_first_bit(data: bytes) -> bytes:
    return bytes([data[0] ^ 1]) + data[1:]


@pytest.mark.parametrize("field", ["nonce", "ciphertext", "tag"])
def test_decrypt_detects_tampering(field: str) -> None:
    """Changing a single bit of any field makes decryption fail."""
    message = encrypt(KEY, PLAINTEXT, nonce=NONCE)
    fields = {
        "nonce": message.nonce,
        "ciphertext": message.ciphertext,
        "tag": message.tag,
    }
    fields[field] = _flip_first_bit(fields[field])

    with pytest.raises(AeadAuthenticationError):
        decrypt(KEY, EncryptedMessage(**fields))


def test_authentication_error_chains_the_library_error() -> None:
    """The original InvalidTag is kept as the cause."""
    message = encrypt(KEY, PLAINTEXT, nonce=NONCE)

    with pytest.raises(AeadAuthenticationError) as error:
        decrypt(OTHER_KEY, message)

    assert type(error.value.__cause__).__name__ == "InvalidTag"


@pytest.mark.parametrize(
    "key",
    [b"", bytes(16), bytes(24), bytes(31), bytes(33), bytearray(32)],
    ids=["empty", "aes-128", "aes-192", "short", "long", "bytearray"],
)
def test_encrypt_rejects_keys_that_are_not_aes_256(key: bytes) -> None:
    """Only 32-byte keys are accepted, even if AES-128/192 would work."""
    with pytest.raises(InvalidAeadKey):
        encrypt(key, PLAINTEXT, nonce=NONCE)


@pytest.mark.parametrize("key", [bytes(16), bytes(33), bytearray(32)])
def test_decrypt_rejects_keys_that_are_not_aes_256(key: bytes) -> None:
    """Decryption validates the key before using it."""
    message = encrypt(KEY, PLAINTEXT, nonce=NONCE)

    with pytest.raises(InvalidAeadKey):
        decrypt(key, message)


@pytest.mark.parametrize("nonce", [b"", bytes(11), bytes(13), bytearray(12)])
def test_encrypt_rejects_invalid_nonce(nonce: bytes) -> None:
    """An explicit nonce must be exactly 12 bytes."""
    with pytest.raises(InvalidAeadNonce):
        encrypt(KEY, PLAINTEXT, nonce=nonce)


def test_key_size_is_aes_256() -> None:
    """The key size is 256 bits."""
    assert KEY_SIZE == 32

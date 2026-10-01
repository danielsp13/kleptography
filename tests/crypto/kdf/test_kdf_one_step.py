from __future__ import annotations

import hashlib

import pytest

from kleptography.crypto.kdf.exceptions import InvalidKdfInput
from kleptography.crypto.kdf.one_step import OTHER_INFO, derive_key
from kleptography.crypto.kdf.records import KEY_SIZE, KeyDerivation

# Shared secret of the reference toy exchange (p = 23, x_A = 6, x_B = 7).
TOY_SECRET = 6
TOY_LENGTH = 1


def _expected_key(encoded_secret: bytes) -> bytes:
    # SP 800-56C one-step KDF, recomputed with hashlib: one block, counter 1.
    return hashlib.sha256(b"\x00\x00\x00\x01" + encoded_secret + OTHER_INFO).digest()


def test_other_info_is_the_channel_label() -> None:
    """The context label is fixed and identifies the encrypted channel."""
    assert OTHER_INFO == b"kleptography-encrypted-channel"


def test_derive_key_matches_pinned_vector() -> None:
    """The toy shared secret gives a fixed, known key."""
    derivation = derive_key(TOY_SECRET, secret_length=TOY_LENGTH)

    assert derivation.key == bytes.fromhex(
        "5665325ff5c99d8a1be513143ded7be3c3b6e10ad00351959f58008b664ec731"
    )


@pytest.mark.parametrize(
    ("shared_secret", "secret_length"),
    [
        (1, 1),
        (TOY_SECRET, TOY_LENGTH),
        (255, 1),
        (256, 2),
        (TOY_SECRET, 256),
        ((1 << 2048) - 1, 256),
    ],
)
def test_derive_key_matches_hashlib(shared_secret: int, secret_length: int) -> None:
    """The key equals SHA-256(counter || Z || OtherInfo), computed independently."""
    derivation = derive_key(shared_secret, secret_length=secret_length)
    encoded_secret = shared_secret.to_bytes(secret_length, "big")

    assert derivation == KeyDerivation(
        shared_secret=shared_secret,
        encoded_secret=encoded_secret,
        other_info=OTHER_INFO,
        key=_expected_key(encoded_secret),
    )


def test_encoding_has_fixed_width() -> None:
    """Z is zero-padded to the requested length, as I2OSP does."""
    derivation = derive_key(TOY_SECRET, secret_length=256)

    assert len(derivation.encoded_secret) == 256
    assert derivation.encoded_secret == bytes(255) + b"\x06"


def test_encoding_width_changes_the_key() -> None:
    """The same integer encoded with another width gives another key."""
    narrow = derive_key(TOY_SECRET, secret_length=1)
    wide = derive_key(TOY_SECRET, secret_length=256)

    assert narrow.key != wide.key


def test_derive_key_is_deterministic() -> None:
    """Without salt or randomness, equal secrets always give equal keys."""
    assert derive_key(TOY_SECRET, secret_length=TOY_LENGTH) == derive_key(
        TOY_SECRET, secret_length=TOY_LENGTH
    )


def test_different_secrets_give_different_keys() -> None:
    """Distinct shared secrets give distinct keys."""
    first = derive_key(TOY_SECRET, secret_length=TOY_LENGTH)
    second = derive_key(TOY_SECRET + 1, secret_length=TOY_LENGTH)

    assert first.key != second.key


def test_key_has_aes_256_size() -> None:
    """The derived key is 32 bytes, the size of an AES-256 key."""
    assert len(derive_key(TOY_SECRET, secret_length=TOY_LENGTH).key) == KEY_SIZE


@pytest.mark.parametrize(
    ("shared_secret", "secret_length"),
    [
        (0, 1),
        (-1, 1),
        (256, 1),
        (1 << 16, 2),
    ],
    ids=["zero", "negative", "too-long-1", "too-long-2"],
)
def test_derive_key_rejects_out_of_range_secret(
    shared_secret: int,
    secret_length: int,
) -> None:
    """The secret must be positive and fit in the requested width."""
    with pytest.raises(InvalidKdfInput):
        derive_key(shared_secret, secret_length=secret_length)


@pytest.mark.parametrize("shared_secret", [True, 6.0, "6", b"\x06"])
def test_derive_key_rejects_non_integer_secret(shared_secret: object) -> None:
    """Only integers are accepted as shared secrets."""
    with pytest.raises(InvalidKdfInput):
        derive_key(shared_secret, secret_length=1)  # ty: ignore[invalid-argument-type]


@pytest.mark.parametrize("secret_length", [0, -1, True, 1.0])
def test_derive_key_rejects_invalid_length(secret_length: object) -> None:
    """The encoding length must be a positive integer."""
    with pytest.raises(InvalidKdfInput):
        derive_key(TOY_SECRET, secret_length=secret_length)  # ty: ignore[invalid-argument-type]

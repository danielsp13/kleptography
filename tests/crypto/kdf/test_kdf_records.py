from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from kleptography.crypto.kdf.exceptions import InvalidKeyDerivation
from kleptography.crypto.kdf.records import KEY_SIZE, KeyDerivation

KEY = bytes(range(32))


def test_key_size_is_256_bits() -> None:
    """Derived keys have the size of an AES-256 key."""
    assert KEY_SIZE == 32


def test_key_derivation_stores_its_fields() -> None:
    """A derivation keeps every intermediate value unchanged."""
    derivation = KeyDerivation(
        shared_secret=6,
        encoded_secret=b"\x00\x06",
        other_info=b"label",
        key=KEY,
    )

    assert derivation.shared_secret == 6
    assert derivation.encoded_secret == b"\x00\x06"
    assert derivation.other_info == b"label"
    assert derivation.key == KEY


def test_key_derivation_is_frozen() -> None:
    """A derivation cannot be modified after creation."""
    derivation = KeyDerivation(
        shared_secret=6, encoded_secret=b"\x06", other_info=b"", key=KEY
    )

    with pytest.raises(FrozenInstanceError):
        derivation.key = bytes(32)  # ty: ignore[invalid-assignment]


def test_key_derivation_hides_secret_values_from_repr() -> None:
    """The secret, its encoding and the key never appear in the repr."""
    derivation = KeyDerivation(
        shared_secret=123456789,
        encoded_secret=(123456789).to_bytes(4, "big"),
        other_info=b"label",
        key=KEY,
    )

    text = repr(derivation)
    assert "123456789" not in text
    assert "shared_secret" not in text
    assert "encoded_secret" not in text
    assert "key=" not in text
    assert "label" in text


def test_key_derivation_rejects_inconsistent_encoding() -> None:
    """The encoded secret must encode the integer secret."""
    with pytest.raises(InvalidKeyDerivation):
        KeyDerivation(shared_secret=6, encoded_secret=b"\x07", other_info=b"", key=KEY)


@pytest.mark.parametrize("key", [bytes(31), bytes(33), b"", bytearray(32)])
def test_key_derivation_rejects_invalid_key(key: bytes) -> None:
    """The key must be exactly 32 bytes of type bytes."""
    with pytest.raises(InvalidKeyDerivation):
        KeyDerivation(shared_secret=6, encoded_secret=b"\x06", other_info=b"", key=key)

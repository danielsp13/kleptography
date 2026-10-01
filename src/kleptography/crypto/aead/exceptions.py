"""
Exceptions raised by the authenticated encryption (AEAD) implementation.
"""

from __future__ import annotations


class AeadError(Exception):
    """Base exception for authenticated encryption errors."""


class InvalidAeadKey(AeadError, ValueError):
    """Raised when a symmetric key does not have the expected type or size."""


class InvalidAeadNonce(AeadError, ValueError):
    """Raised when a nonce does not have the expected type or size."""


class InvalidAeadTag(AeadError, ValueError):
    """Raised when an authentication tag does not have the expected type or size."""


class AeadAuthenticationError(AeadError, ValueError):
    """Raised when decryption fails: wrong key, or tampered nonce, data or tag."""

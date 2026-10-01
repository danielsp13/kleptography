"""
Exceptions raised by the key derivation function (KDF) implementation.
"""

from __future__ import annotations


class KdfError(Exception):
    """Base exception for key derivation errors."""


class InvalidKdfInput(KdfError, ValueError):
    """Raised when a shared secret or its encoding length is not valid."""


class InvalidKeyDerivation(KdfError, ValueError):
    """Raised when a key derivation record is internally inconsistent."""

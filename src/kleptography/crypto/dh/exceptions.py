"""
Exceptions raised by the Diffie-Hellman implementation.
"""

from __future__ import annotations


class DiffieHellmanError(Exception):
    """Base exception for Diffie-Hellman errors."""


class InvalidDiffieHellmanParameters(DiffieHellmanError, ValueError):
    """Raised when Diffie-Hellman parameters are invalid."""


class InvalidPrivateKey(DiffieHellmanError, ValueError):
    """Raised when a Diffie-Hellman private key is invalid."""


class InvalidPublicKey(DiffieHellmanError, ValueError):
    """Raised when a Diffie-Hellman public key is invalid."""


class DiffieHellmanStateError(DiffieHellmanError, RuntimeError):
    """Raised when a Diffie-Hellman operation is invalid for the current state."""

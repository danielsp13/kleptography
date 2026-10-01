"""Errors raised by the Young-Yung SETUP on Diffie-Hellman."""

from __future__ import annotations

from kleptography.crypto.dh.exceptions import DiffieHellmanError


class SetupError(DiffieHellmanError):
    """Base class for errors raised by the SETUP."""


class InvalidSetupConfiguration(SetupError, ValueError):
    """Raised when a SETUP configuration is invalid or does not match."""


class SetupRecoveryError(SetupError, ValueError):
    """Raised when no candidate exponent reproduces the second public key."""

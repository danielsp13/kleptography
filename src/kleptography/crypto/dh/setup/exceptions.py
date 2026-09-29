"""
Exceptions raised by the Young-Yung SETUP on Diffie-Hellman.
"""

from __future__ import annotations

from kleptography.crypto.dh.exceptions import DiffieHellmanError


class SetupError(DiffieHellmanError):
    """Base exception for errors of the kleptographic (SETUP) DH code."""


class InvalidSetupConfiguration(SetupError, ValueError):
    """Raised when the constants embedded in a SETUP device are invalid."""


class SetupRecoveryError(SetupError, ValueError):
    """Raised when the attacker cannot recover an exponent from two outputs."""

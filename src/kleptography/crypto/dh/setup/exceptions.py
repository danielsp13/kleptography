from __future__ import annotations

from kleptography.crypto.dh.exceptions import DiffieHellmanError


class SetupError(DiffieHellmanError):
    pass


class InvalidSetupConfiguration(SetupError, ValueError):
    pass


class SetupRecoveryError(SetupError, ValueError):
    pass

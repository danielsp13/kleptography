"""Tests for the SETUP exception hierarchy.

They check that every SETUP error is a ``DiffieHellmanError`` and also the
matching builtin, so callers can catch either.
"""

from __future__ import annotations

import pytest

from kleptography.crypto.dh.exceptions import DiffieHellmanError
from kleptography.crypto.dh.setup.exceptions import (
    InvalidSetupConfiguration,
    SetupError,
    SetupRecoveryError,
)


def test_setup_error_is_a_diffie_hellman_error() -> None:
    """SetupError is a DiffieHellmanError."""
    assert issubclass(SetupError, DiffieHellmanError)


@pytest.mark.parametrize(
    ("exception_type", "builtin_type"),
    [
        (InvalidSetupConfiguration, ValueError),
        (SetupRecoveryError, ValueError),
    ],
)
def test_setup_exceptions_hierarchy(
    exception_type: type[SetupError],
    builtin_type: type[Exception],
) -> None:
    """Each SETUP error is a SetupError and its builtin."""
    assert issubclass(exception_type, SetupError)
    assert issubclass(exception_type, builtin_type)

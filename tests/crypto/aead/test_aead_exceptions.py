"""Tests for the AEAD exception hierarchy.

They check that AEAD errors are independent of the DH hierarchy and that
each one is also the matching builtin.
"""

from __future__ import annotations

import pytest

from kleptography.crypto.aead.exceptions import (
    AeadAuthenticationError,
    AeadError,
    InvalidAeadKey,
    InvalidAeadNonce,
    InvalidAeadTag,
)
from kleptography.crypto.dh.exceptions import DiffieHellmanError


def test_aead_error_is_independent_of_diffie_hellman() -> None:
    """AEAD errors form their own hierarchy, outside the DH one."""
    assert not issubclass(AeadError, DiffieHellmanError)


@pytest.mark.parametrize(
    ("exception_type", "builtin_type"),
    [
        (InvalidAeadKey, ValueError),
        (InvalidAeadNonce, ValueError),
        (InvalidAeadTag, ValueError),
        (AeadAuthenticationError, ValueError),
    ],
)
def test_aead_exceptions_hierarchy(
    exception_type: type[AeadError],
    builtin_type: type[Exception],
) -> None:
    """Every AEAD error subclasses the base error and the matching builtin."""
    assert issubclass(exception_type, AeadError)
    assert issubclass(exception_type, builtin_type)

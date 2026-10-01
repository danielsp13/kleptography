"""Tests for the channel exception hierarchy.

They check that channel errors are independent of the DH, KDF and AEAD
hierarchies and that each one is also the matching builtin.
"""

from __future__ import annotations

import pytest

from kleptography.crypto.aead.exceptions import AeadError
from kleptography.crypto.channel.exceptions import (
    ChannelError,
    InvalidChannelMessage,
    InvalidChannelSessions,
)
from kleptography.crypto.dh.exceptions import DiffieHellmanError
from kleptography.crypto.kdf.exceptions import KdfError


@pytest.mark.parametrize("other_base", [DiffieHellmanError, KdfError, AeadError])
def test_channel_error_is_independent_of_other_schemes(
    other_base: type[Exception],
) -> None:
    """Channel errors form their own hierarchy."""
    assert not issubclass(ChannelError, other_base)


@pytest.mark.parametrize(
    ("exception_type", "builtin_type"),
    [
        (InvalidChannelMessage, ValueError),
        (InvalidChannelSessions, ValueError),
    ],
)
def test_channel_exceptions_hierarchy(
    exception_type: type[ChannelError],
    builtin_type: type[Exception],
) -> None:
    """Every channel error subclasses the base error and the matching builtin."""
    assert issubclass(exception_type, ChannelError)
    assert issubclass(exception_type, builtin_type)

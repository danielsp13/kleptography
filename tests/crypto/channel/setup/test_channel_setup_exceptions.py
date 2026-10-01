"""Tests for the exception of the channel attacker.

They check that ``InvalidChannelInterception`` belongs to the channel
hierarchy and is a ``ValueError``, but not a ``DiffieHellmanError``.
"""

from __future__ import annotations

from kleptography.crypto.channel.exceptions import ChannelError
from kleptography.crypto.channel.setup.exceptions import InvalidChannelInterception
from kleptography.crypto.dh.exceptions import DiffieHellmanError


def test_invalid_interception_is_a_channel_value_error() -> None:
    """The error is a ChannelError and a ValueError, not a DH error."""
    assert issubclass(InvalidChannelInterception, ChannelError)
    assert issubclass(InvalidChannelInterception, ValueError)
    assert not issubclass(InvalidChannelInterception, DiffieHellmanError)

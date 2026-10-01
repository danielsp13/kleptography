from __future__ import annotations

from kleptography.crypto.channel.exceptions import ChannelError
from kleptography.crypto.channel.setup.exceptions import InvalidChannelInterception
from kleptography.crypto.dh.exceptions import DiffieHellmanError


def test_invalid_interception_is_a_channel_value_error() -> None:
    assert issubclass(InvalidChannelInterception, ChannelError)
    assert issubclass(InvalidChannelInterception, ValueError)
    assert not issubclass(InvalidChannelInterception, DiffieHellmanError)

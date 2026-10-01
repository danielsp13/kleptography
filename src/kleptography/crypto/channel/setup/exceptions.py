from __future__ import annotations

from kleptography.crypto.channel.exceptions import ChannelError


class InvalidChannelInterception(ChannelError, ValueError):
    pass

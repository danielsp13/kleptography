"""Errors raised by the attacker of the encrypted channel."""

from __future__ import annotations

from kleptography.crypto.channel.exceptions import ChannelError


class InvalidChannelInterception(ChannelError, ValueError):
    """Raised when an interception record breaks its invariants."""

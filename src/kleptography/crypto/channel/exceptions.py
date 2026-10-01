"""Exceptions raised by the encrypted channel implementation."""

from __future__ import annotations


class ChannelError(Exception):
    """Base exception for encrypted channel errors."""


class InvalidChannelMessage(ChannelError, ValueError):
    """Raised when a message has an invalid sender or text."""


class InvalidChannelSessions(ChannelError, ValueError):
    """Raised when a channel run or transcript has invalid sessions."""

from __future__ import annotations

import pytest

from kleptography.crypto.dh.exchange import DiffieHellmanExchangeResult


def test_exchange_result() -> None:
    """An exchange result stores both shared secrets."""
    result = DiffieHellmanExchangeResult(
        alice_shared_secret=42,
        bob_shared_secret=42,
    )

    assert result.alice_shared_secret == 42
    assert result.bob_shared_secret == 42


def test_exchange_result_is_successful_when_secrets_match() -> None:
    """An exchange is successful when both secrets are equal."""
    result = DiffieHellmanExchangeResult(
        alice_shared_secret=42,
        bob_shared_secret=42,
    )

    assert result.successful is True


def test_exchange_result_is_unsuccessful_when_secrets_differ() -> None:
    """An exchange is unsuccessful when the secrets differ."""
    result = DiffieHellmanExchangeResult(
        alice_shared_secret=42,
        bob_shared_secret=43,
    )

    assert result.successful is False


def test_exchange_result_is_immutable() -> None:
    """An exchange result cannot be modified after creation."""
    result = DiffieHellmanExchangeResult(
        alice_shared_secret=42,
        bob_shared_secret=42,
    )

    with pytest.raises(AttributeError):
        setattr(result, "alice_shared_secret", 43)

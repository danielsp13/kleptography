"""The experiment of the Diffie-Hellman section, without Streamlit.

It only orchestrates the ``crypto`` API: two honest participants run a
traced exchange, and the timeline becomes the steps shown by the section.
"""

from __future__ import annotations

from dataclasses import dataclass

from kleptography.app.content.diffie_hellman import (
    ProtocolStep,
    build_protocol_steps,
)
from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.participant import DiffieHellmanParticipant
from kleptography.crypto.dh.protocol import perform_key_exchange
from kleptography.crypto.dh.tracing.context import ProtocolExecutionContext


@dataclass(frozen=True, slots=True)
class ExchangeRun:
    """An executed exchange and the parameters it was run with."""

    parameters: DiffieHellmanParameters
    steps: tuple[ProtocolStep, ...]


def run_exchange(
    parameters: DiffieHellmanParameters,
    private_keys: tuple[int, int] | None,
) -> ExchangeRun:
    """Run a traced exchange between Alice and Bob.

    Args:
        parameters: The group of the exchange.
        private_keys: Alice's and Bob's private keys, or ``None`` to generate
            them during the exchange.

    Returns:
        The parameters and the steps built from the recorded timeline.

    Raises:
        InvalidPrivateKey: If a chosen key is not in ``[1, q - 1]``.
    """
    alice = DiffieHellmanParticipant(parameters)
    bob = DiffieHellmanParticipant(parameters)

    if private_keys is not None:
        alice.load_private_key(private_keys[0])
        bob.load_private_key(private_keys[1])

    context = ProtocolExecutionContext()
    perform_key_exchange(alice, bob, observer=context)

    return ExchangeRun(
        parameters=parameters,
        steps=build_protocol_steps(context.events),
    )

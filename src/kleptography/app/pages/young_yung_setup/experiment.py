"""The experiment of the Young–Yung SETUP section, without Streamlit.

It only orchestrates the ``crypto`` API: the device plays Alice in two
exchanges with honest Bobs, and the attacker recovers the second key from
the public values of both timelines.
"""

from __future__ import annotations

from dataclasses import dataclass

from kleptography.app.components.young_yung_setup import SetupRun
from kleptography.app.content.young_yung_setup import summarize_exchange
from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.participant import DiffieHellmanParticipant
from kleptography.crypto.dh.protocol import perform_key_exchange
from kleptography.crypto.dh.setup.attacker import YoungYungAttacker
from kleptography.crypto.dh.setup.configuration import YoungYungConfiguration
from kleptography.crypto.dh.setup.participant import (
    YoungYungDiffieHellmanParticipant,
)
from kleptography.crypto.dh.tracing.context import ProtocolExecutionContext


@dataclass(frozen=True, slots=True)
class Backdoor:
    """The attacker and the SETUP configuration it embedded in the device."""

    attacker: YoungYungAttacker
    configuration: YoungYungConfiguration


@dataclass(frozen=True, slots=True)
class ChosenKeys:
    """Private keys typed by the user: the device's a1 and Bob's b1, b2."""

    device_first: int
    peer_first: int
    peer_second: int


def run_experiment(
    parameters: DiffieHellmanParameters,
    backdoor: Backdoor,
    chosen_keys: ChosenKeys | None,
) -> SetupRun:
    """Run both exchanges with the device and the attacker's recovery."""
    device = YoungYungDiffieHellmanParticipant(parameters, backdoor.configuration)
    first_peer = DiffieHellmanParticipant(parameters)
    second_peer = DiffieHellmanParticipant(parameters)

    if chosen_keys is not None:
        device.load_private_key(chosen_keys.device_first)
        first_peer.load_private_key(chosen_keys.peer_first)
        second_peer.load_private_key(chosen_keys.peer_second)

    # Exchange 1: the device has no previous key, so a1 is honest.
    first_context = ProtocolExecutionContext()
    perform_key_exchange(device, first_peer, observer=first_context)

    # Between exchanges: the SETUP derives a2 from a1.
    device.generate_keypair()
    derivation = device.last_derivation
    if derivation is None:
        raise RuntimeError("The device did not derive its second key.")

    # Exchange 2: the device sends A2 = g^a2.
    second_context = ProtocolExecutionContext()
    perform_key_exchange(device, second_peer, observer=second_context)

    first_exchange = summarize_exchange(first_context.events)
    second_exchange = summarize_exchange(second_context.events)

    # The attacker only uses what travelled over the network.
    attacker = backdoor.attacker
    recovery = attacker.recover(
        first_public_key=first_exchange.device_public_key,
        second_public_key=second_exchange.device_public_key,
        configuration=backdoor.configuration,
    )
    recovered_shared_secret = attacker.recover_shared_secret(
        first_public_key=first_exchange.device_public_key,
        second_public_key=second_exchange.device_public_key,
        peer_public_key=second_exchange.peer_public_key,
        configuration=backdoor.configuration,
    )

    return SetupRun(
        parameters=parameters,
        attacker=attacker,
        configuration=backdoor.configuration,
        first_exchange=first_exchange,
        second_exchange=second_exchange,
        derivation=derivation,
        recovery=recovery,
        recovered_shared_secret=recovered_shared_secret,
    )

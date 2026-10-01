"""The experiment of the encrypted channel section, without Streamlit.

It only orchestrates the ``crypto`` API: it runs the channel with the device
chosen for Alice and lets the attacker intercept it once.
"""

from __future__ import annotations

from collections.abc import Sequence

from kleptography.app.components.encrypted_channel import (
    ChannelExperiment,
    DeviceKind,
)
from kleptography.app.components.young_yung_setup import Backdoor
from kleptography.crypto.channel.protocol import run_channel
from kleptography.crypto.channel.records import PlainMessage
from kleptography.crypto.channel.setup.attacker import intercept_channel
from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.participant import DiffieHellmanParticipant
from kleptography.crypto.dh.setup.participant import (
    YoungYungDiffieHellmanParticipant,
)


def run_experiment(
    parameters: DiffieHellmanParameters,
    backdoor: Backdoor,
    device_kind: DeviceKind,
    sessions: Sequence[Sequence[PlainMessage]],
) -> ChannelExperiment:
    """Run the channel with the chosen device and intercept it once."""
    configuration = backdoor.configuration
    bob = DiffieHellmanParticipant(parameters)

    if device_kind is DeviceKind.COMPROMISED:
        device = YoungYungDiffieHellmanParticipant(parameters, configuration)
        run = run_channel(device, bob, sessions)
        derivations = device.derivations
    else:
        run = run_channel(DiffieHellmanParticipant(parameters), bob, sessions)
        derivations = ()

    return ChannelExperiment(
        device_kind=device_kind,
        attacker=backdoor.attacker,
        configuration=configuration,
        run=run,
        derivations=derivations,
        interception=intercept_channel(
            run.transcript,
            attacker=backdoor.attacker,
            configuration=configuration,
        ),
    )

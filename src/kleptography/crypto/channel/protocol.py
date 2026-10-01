"""The encrypted channel: several sessions in a row between the same two parties.

Every session uses fresh ephemeral DH keys, so with honest participants the
session keys are independent: learning one of them reveals nothing about the
others. A compromised device playing Alice breaks exactly this property while
the channel, and the transcript it produces, stay unchanged.
"""

from __future__ import annotations

from collections.abc import Sequence

from kleptography.crypto.channel.exceptions import InvalidChannelSessions
from kleptography.crypto.channel.records import ChannelRun, PlainMessage
from kleptography.crypto.channel.session import run_session
from kleptography.crypto.dh.exceptions import DiffieHellmanParametersMismatch
from kleptography.crypto.dh.participant import DiffieHellmanParticipant


def run_channel(
    alice: DiffieHellmanParticipant,
    bob: DiffieHellmanParticipant,
    sessions: Sequence[Sequence[PlainMessage]],
) -> ChannelRun:
    """Run the channel: one session per entry of ``sessions``, in order.

    Args:
        alice: The participant playing Alice. A compromised device can be
            passed here like any honest participant.
        bob: The participant playing Bob.
        sessions: For each session, its messages in sending order. A session
            may have no messages.

    Returns:
        The ``ChannelRun``, whose ``transcript`` is the public view.

    Raises:
        InvalidChannelSessions: If ``sessions`` is empty.
        DiffieHellmanParametersMismatch: If the participants use different
            groups. No session runs in that case.
    """
    if not sessions:
        raise InvalidChannelSessions("A channel needs at least one session.")
    if alice.parameters != bob.parameters:
        raise DiffieHellmanParametersMismatch(
            "Alice and Bob must use the same Diffie-Hellman parameters."
        )

    return ChannelRun(
        parameters=alice.parameters,
        sessions=tuple(
            run_session(alice, bob, messages, number=number)
            for number, messages in enumerate(sessions, start=1)
        ),
    )

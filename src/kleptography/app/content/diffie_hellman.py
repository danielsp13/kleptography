"""
Educational content for the interactive honest Diffie-Hellman section.

This module turns the presentation-agnostic protocol timeline emitted by
``perform_key_exchange`` into explanatory steps (text and LaTeX). It only
reads event data; it never performs cryptographic computations.
"""

from __future__ import annotations

from dataclasses import dataclass

from kleptography.app.content.callouts import CalloutComposer
from kleptography.app.content.composer import ContentComposer
from kleptography.app.content.numbers import is_small
from kleptography.crypto.dh.tracing.events import (
    Actor,
    ProtocolEvent,
    ProtocolEventType,
)

# Textbook notation used throughout the section.
PRIVATE_SYMBOL = {Actor.ALICE: "a", Actor.BOB: "b"}
PUBLIC_SYMBOL = {Actor.ALICE: "A", Actor.BOB: "B"}
SECRET_SYMBOL = {Actor.ALICE: "s_A", Actor.BOB: "s_B"}
PEER = {Actor.ALICE: Actor.BOB, Actor.BOB: Actor.ALICE}


@dataclass(frozen=True, slots=True)
class StepDefinition:
    """Static explanation of one phase of the protocol."""

    title: str
    explanation: str
    formula: str


STEP_DEFINITIONS: tuple[StepDefinition, ...] = (
    StepDefinition(
        title="Agree on the public parameters",
        explanation=(
            "Alice and Bob agree on a large prime $p$ and a number $g$, the "
            "*generator*. Raising $g$ to successive powers modulo $p$ produces "
            "$q$ distinct values before repeating, where $q$ is also prime. "
            "These values are **public**: anyone, including an eavesdropper, "
            "may know them."
        ),
        formula=r"p = 2q + 1, \qquad g^{q} \equiv 1 \pmod{p}",
    ),
    StepDefinition(
        title="Choose a private key and compute a public key",
        explanation=(
            "Each participant picks a secret number, the **private key**, "
            "between $1$ and $q - 1$, and never reveals it. From it they "
            "compute a **public key** by raising $g$ to that power modulo $p$. "
            "Computing the public key from the private key is fast. Going "
            "back from the public key to the private key is the *discrete "
            "logarithm problem*, which is believed to be infeasible for "
            "properly sized groups."
        ),
        formula=r"A = g^{a} \bmod p, \qquad B = g^{b} \bmod p",
    ),
    StepDefinition(
        title="Exchange the public keys",
        explanation=(
            "Alice sends $A$ to Bob and Bob sends $B$ to Alice. The channel "
            "is **not** secret: an eavesdropper can read both messages."
        ),
        formula=(
            r"\text{Alice} \xrightarrow{\;A\;} \text{Bob}, "
            r"\qquad \text{Bob} \xrightarrow{\;B\;} \text{Alice}"
        ),
    ),
    StepDefinition(
        title="Compute the shared secret",
        explanation=(
            "Each participant raises the public key they received to their "
            "own private key. Because exponents multiply, both arrive at the "
            "same value $g^{ab} \\bmod p$ without ever sending it."
        ),
        formula=(
            r"\begin{aligned}"
            r"s_A &= B^{a} = \left(g^{b}\right)^{a} = g^{ab} \bmod p \\"
            r"s_B &= A^{b} = \left(g^{a}\right)^{b} = g^{ab} \bmod p"
            r"\end{aligned}"
        ),
    ),
    StepDefinition(
        title="Check the result",
        explanation=(
            "Both secrets are compared to confirm the exchange worked. This "
            "comparison exists only for the demonstration: real participants "
            "never reveal their secrets, and instead confirm them indirectly, "
            "for example by successfully using keys derived from them."
        ),
        formula=r"s_A \overset{?}{=} s_B",
    ),
)

_STEP_OF_EVENT: dict[ProtocolEventType, int] = {
    ProtocolEventType.PARAMETERS_SELECTED: 1,
    ProtocolEventType.PARAMETERS_VALIDATED: 1,
    ProtocolEventType.PRIVATE_KEY_GENERATED: 2,
    ProtocolEventType.PRIVATE_KEY_PROVIDED: 2,
    ProtocolEventType.PUBLIC_KEY_COMPUTED: 2,
    ProtocolEventType.PUBLIC_KEY_SENT: 3,
    ProtocolEventType.PUBLIC_KEY_RECEIVED: 3,
    ProtocolEventType.SHARED_SECRET_COMPUTED: 4,
    ProtocolEventType.SHARED_SECRET_VERIFIED: 5,
}


@dataclass(frozen=True, slots=True)
class ProtocolStep:
    """One phase of an executed exchange: its explanation and its events."""

    number: int
    definition: StepDefinition
    events: tuple[ProtocolEvent, ...]

    def event(self, event_type: ProtocolEventType, actor: Actor) -> ProtocolEvent:
        """
        Return the first event of this step with the given type and actor.

        Raises:
            LookupError: If the step has no such event.
        """
        for event in self.events:
            if event.event_type is event_type and event.actor is actor:
                return event

        raise LookupError(f"No {event_type} event for {actor} in step {self.number}.")

    def events_of(self, *event_types: ProtocolEventType) -> tuple[ProtocolEvent, ...]:
        """Return the events of this step whose type is one of ``event_types``."""
        return tuple(event for event in self.events if event.event_type in event_types)


def build_protocol_steps(
    events: tuple[ProtocolEvent, ...],
) -> tuple[ProtocolStep, ...]:
    """
    Group a protocol timeline into the five explanatory steps.

    Event types that do not belong to any step (such as the reserved
    modular exponentiation events) are ignored. Steps without events are
    omitted.

    Args:
        events: The timeline recorded by a ``ProtocolExecutionContext``.

    Returns:
        The non-empty steps, in protocol order.
    """
    grouped: dict[int, list[ProtocolEvent]] = {}

    for event in events:
        number = _STEP_OF_EVENT.get(event.event_type)
        if number is not None:
            grouped.setdefault(number, []).append(event)

    return tuple(
        ProtocolStep(
            number=number,
            definition=STEP_DEFINITIONS[number - 1],
            events=tuple(grouped[number]),
        )
        for number in sorted(grouped)
    )


def public_key_formula(
    actor: Actor,
    *,
    generator: int,
    private_key: int,
    prime: int,
    public_key: int,
) -> str:
    """
    Return the LaTeX derivation of a participant's public key.

    Concrete values are substituted only when they are small enough to be
    readable; otherwise the symbolic formula is returned.
    """
    private = PRIVATE_SYMBOL[actor]
    public = PUBLIC_SYMBOL[actor]

    if not is_small(generator, private_key, prime, public_key):
        return rf"{public} = g^{{{private}}} \bmod p"

    return rf"{public} = {generator}^{{{private_key}}} \bmod {prime} = {public_key}"


def shared_secret_formula(
    actor: Actor,
    *,
    peer_public_key: int,
    private_key: int,
    prime: int,
    shared_secret: int,
) -> str:
    """
    Return the LaTeX derivation of a participant's shared secret.

    Concrete values are substituted only when they are small enough to be
    readable; otherwise the symbolic formula is returned.
    """
    secret = SECRET_SYMBOL[actor]
    peer_public = PUBLIC_SYMBOL[PEER[actor]]
    private = PRIVATE_SYMBOL[actor]

    if not is_small(peer_public_key, private_key, prime, shared_secret):
        return rf"{secret} = {peer_public}^{{{private}}} \bmod p"

    return (
        rf"{secret} = {peer_public_key}^{{{private_key}}} \bmod {prime}"
        rf" = {shared_secret}"
    )


def build_dh_intro_content() -> str:
    """Return the introduction of the Diffie-Hellman section as Markdown."""
    content = ContentComposer()

    content.paragraph(
        "Diffie-Hellman lets two people who have never met, Alice and Bob, agree on a ",
        content.bold("shared secret"),
        " while talking over a channel that anyone can listen to. It was "
        "published by Whitfield Diffie and Martin Hellman in 1976 and is "
        "still one of the building blocks of secure communication.",
    )

    content.paragraph(
        "This section runs an ",
        content.bold("honest"),
        " exchange: every participant follows the protocol exactly as "
        "specified. Choose the public parameters, run the exchange, and "
        "follow each step to see which values are computed, which ones "
        "travel over the network, and which ones never leave their owner.",
    )

    content.block(
        CalloutComposer.note(
            content=(
                "The kleptographic (backdoored) version of this exchange is "
                "not implemented yet. Understanding the honest version first "
                "is what makes the backdoor visible later."
            ),
            title="Why start with the honest version?",
        )
    )

    return content.build()


def build_toy_group_content() -> str:
    """Return the explanation shown when a toy group is selected."""
    return CalloutComposer.warning(
        content=(
            "Toy groups are generated on the fly with a few dozen bits so "
            "that every number fits on screen and formulas can show real "
            "values. They are <strong>deliberately insecure</strong>: the "
            "discrete logarithm in such a small group can be solved "
            "instantly by brute force."
        ),
        title="Educational toy group",
    ).build()


def build_standard_group_content() -> str:
    """Return the explanation shown when an RFC 7919 group is selected."""
    return CalloutComposer.info(
        content=(
            "RFC 7919 defines fixed, published finite-field groups "
            "(FFDHE) used by real protocols such as TLS. The number in the "
            "name is the size of <em>p</em> in bits. The values are huge, so the "
            "formulas stay symbolic, but every number is still shown in "
            "full below."
        ),
        title="Standardized group (RFC 7919)",
    ).build()


def build_eavesdropper_content() -> str:
    """Return the explanation of what a passive eavesdropper can observe."""
    return CalloutComposer.danger(
        content=(
            "An eavesdropper, usually called <strong>Eve</strong>, sees "
            "<em>p</em>, <em>g</em>, <em>A</em> and <em>B</em>. To compute "
            "the shared secret she would need <em>a</em> or <em>b</em>, which "
            "means finding the exponent <em>a</em> such that "
            "<em>g<sup>a</sup></em> ≡ <em>A</em> (mod <em>p</em>). That is "
            "the discrete logarithm "
            "problem. It is trivial in a toy group, and believed to be "
            "computationally infeasible in a properly sized group such as "
            "the RFC 7919 ones."
        ),
        title="What an eavesdropper sees",
    ).build()

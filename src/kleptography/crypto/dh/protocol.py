"""Execution of an honest Diffie-Hellman key exchange between two participants.

The exchange runs in five explicit phases:

1. Parameter agreement: both participants must use the same (p, g, q).
2. Key preparation: each participant uses the key pair it already holds
   (provided key) or generates a fresh one.
3. Public key exchange: each participant sends g^x mod p to the other.
4. Shared secret computation: each participant computes peer^x mod p.
5. Verification: both shared secrets are compared.

Every phase can be traced through an optional ``OperationObserver``.
"""

from __future__ import annotations

from collections.abc import Mapping

from kleptography.crypto.dh.exceptions import DiffieHellmanParametersMismatch
from kleptography.crypto.dh.exchange import DiffieHellmanExchangeResult
from kleptography.crypto.dh.participant import DiffieHellmanParticipant
from kleptography.crypto.dh.tracing.events import Actor, ProtocolEventType
from kleptography.crypto.dh.tracing.observer import OperationObserver


def perform_key_exchange(
    alice: DiffieHellmanParticipant,
    bob: DiffieHellmanParticipant,
    *,
    observer: OperationObserver | None = None,
) -> DiffieHellmanExchangeResult:
    """Perform a complete Diffie-Hellman exchange and optionally trace it.

    Participants that already hold a key pair keep it, which allows
    reproducible exchanges with known exponents. Participants without a key
    pair receive a fresh one. The key pairs remain on the participants after
    the exchange, so reusing them in another exchange reuses the same keys;
    call ``generate_keypair()`` or use new participants for fresh ones.

    Args:
        alice: The participant who sends her public value first.
        bob: The other participant.
        observer: An optional observer that receives every protocol event.

    Returns:
        Both shared secrets and whether they match.

    Raises:
        DiffieHellmanParametersMismatch: If both participants do not use the
            same parameters. Nothing is generated or traced in that case.
    """
    _agree_parameters(alice, bob, observer)

    _prepare_keypair(alice, Actor.ALICE, observer)
    _prepare_keypair(bob, Actor.BOB, observer)

    _send_public_key(alice, Actor.ALICE, Actor.BOB, observer)
    _send_public_key(bob, Actor.BOB, Actor.ALICE, observer)

    alice_secret = _compute_shared_secret(alice, bob, Actor.ALICE, observer)
    bob_secret = _compute_shared_secret(bob, alice, Actor.BOB, observer)

    result = DiffieHellmanExchangeResult(
        alice_shared_secret=alice_secret,
        bob_shared_secret=bob_secret,
    )

    _emit(
        observer,
        ProtocolEventType.SHARED_SECRET_VERIFIED,
        actor=Actor.SYSTEM,
        data={
            "alice_shared_secret": alice_secret,
            "bob_shared_secret": bob_secret,
            "successful": result.successful,
        },
    )

    return result


def _agree_parameters(
    alice: DiffieHellmanParticipant,
    bob: DiffieHellmanParticipant,
    observer: OperationObserver | None,
) -> None:
    """Check that both participants share the same public parameters."""
    if alice.parameters != bob.parameters:
        raise DiffieHellmanParametersMismatch(
            "Both participants must use the same DH parameters."
        )

    parameters = {
        "prime": alice.parameters.prime,
        "generator": alice.parameters.generator,
        "subgroup_order": alice.parameters.subgroup_order,
    }

    _emit(
        observer,
        ProtocolEventType.PARAMETERS_SELECTED,
        actor=Actor.SYSTEM,
        data=parameters,
    )
    _emit(
        observer,
        ProtocolEventType.PARAMETERS_VALIDATED,
        actor=Actor.SYSTEM,
        data=parameters,
    )


def _prepare_keypair(
    participant: DiffieHellmanParticipant,
    actor: Actor,
    observer: OperationObserver | None,
) -> None:
    """Keep the participant's key pair if it has one, otherwise generate it."""
    if participant.has_keypair:
        event_type = ProtocolEventType.PRIVATE_KEY_PROVIDED
    else:
        participant.generate_keypair()
        event_type = ProtocolEventType.PRIVATE_KEY_GENERATED

    parameters = participant.parameters

    _emit(
        observer,
        event_type,
        actor=actor,
        data={
            "private_key": participant.private_key,
            "subgroup_order": parameters.subgroup_order,
        },
    )
    _emit(
        observer,
        ProtocolEventType.PUBLIC_KEY_COMPUTED,
        actor=actor,
        data={
            "base": parameters.generator,
            "exponent": participant.private_key,
            "modulus": parameters.prime,
            "public_key": participant.public_key,
            "expression": (
                f"{parameters.generator}^{participant.private_key}"
                f" mod {parameters.prime}"
            ),
        },
    )


def _send_public_key(
    sender: DiffieHellmanParticipant,
    sender_actor: Actor,
    recipient_actor: Actor,
    observer: OperationObserver | None,
) -> None:
    """Trace the transmission of a public value over the public channel."""
    _emit(
        observer,
        ProtocolEventType.PUBLIC_KEY_SENT,
        actor=sender_actor,
        data={
            "recipient": recipient_actor.value,
            "public_key": sender.public_key,
        },
    )
    _emit(
        observer,
        ProtocolEventType.PUBLIC_KEY_RECEIVED,
        actor=recipient_actor,
        data={
            "sender": sender_actor.value,
            "public_key": sender.public_key,
        },
    )


def _compute_shared_secret(
    participant: DiffieHellmanParticipant,
    peer: DiffieHellmanParticipant,
    actor: Actor,
    observer: OperationObserver | None,
) -> int:
    """Compute the participant's shared secret from the peer's public value."""
    shared_secret = participant.compute_shared_secret(peer.public_key)
    modulus = participant.parameters.prime

    _emit(
        observer,
        ProtocolEventType.SHARED_SECRET_COMPUTED,
        actor=actor,
        data={
            "peer_public_key": peer.public_key,
            "private_key": participant.private_key,
            "modulus": modulus,
            "shared_secret": shared_secret,
            "expression": (
                f"{peer.public_key}^{participant.private_key} mod {modulus}"
            ),
        },
    )

    return shared_secret


def _emit(
    observer: OperationObserver | None,
    event_type: ProtocolEventType,
    *,
    actor: Actor,
    data: Mapping[str, object],
) -> None:
    """Forward an event to the observer, if any."""
    if observer is not None:
        observer.observe(event_type, actor=actor, data=data)

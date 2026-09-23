from __future__ import annotations

from src.kleptography.crypto.dh.exchange import DiffieHellmanExchangeResult
from src.kleptography.crypto.dh.participant import DiffieHellmanParticipant
from src.kleptography.crypto.dh.tracing.events import Actor, ProtocolEventType
from src.kleptography.crypto.dh.tracing.observer import OperationObserver


def perform_key_exchange(
    alice: DiffieHellmanParticipant,
    bob: DiffieHellmanParticipant,
    *,
    observer: OperationObserver | None = None,
) -> DiffieHellmanExchangeResult:
    """Perform a complete Diffie-Hellman exchange and optionally trace it."""

    if observer is not None:
        observer.observe(
            ProtocolEventType.PARAMETERS_SELECTED,
            actor=Actor.SYSTEM,
            data={
                "prime": alice.parameters.prime,
                "generator": alice.parameters.generator,
                "subgroup_order": alice.parameters.subgroup_order,
            },
        )

        observer.observe(
            ProtocolEventType.PARAMETERS_VALIDATED,
            actor=Actor.SYSTEM,
            data={
                "prime": alice.parameters.prime,
                "generator": alice.parameters.generator,
                "subgroup_order": alice.parameters.subgroup_order,
            },
        )

    alice.generate_keypair()
    bob.generate_keypair()

    if observer is not None:
        observer.observe(
            ProtocolEventType.PRIVATE_KEY_GENERATED,
            actor=Actor.ALICE,
            data={
                "private_key": alice.private_key,
                "subgroup_order": alice.parameters.subgroup_order,
            },
        )

        observer.observe(
            ProtocolEventType.PUBLIC_KEY_COMPUTED,
            actor=Actor.ALICE,
            data={
                "base": alice.parameters.generator,
                "exponent": alice.private_key,
                "modulus": alice.parameters.prime,
                "public_key": alice.public_key,
                "expression": (
                    f"{alice.parameters.generator}^{alice.private_key}"
                    f" mod {alice.parameters.prime}"
                ),
            },
        )

        observer.observe(
            ProtocolEventType.PRIVATE_KEY_GENERATED,
            actor=Actor.BOB,
            data={
                "private_key": bob.private_key,
                "subgroup_order": bob.parameters.subgroup_order,
            },
        )

        observer.observe(
            ProtocolEventType.PUBLIC_KEY_COMPUTED,
            actor=Actor.BOB,
            data={
                "base": bob.parameters.generator,
                "exponent": bob.private_key,
                "modulus": bob.parameters.prime,
                "public_key": bob.public_key,
                "expression": (
                    f"{bob.parameters.generator}^{bob.private_key}"
                    f" mod {bob.parameters.prime}"
                ),
            },
        )

    if observer is not None:
        observer.observe(
            ProtocolEventType.PUBLIC_KEY_SENT,
            actor=Actor.ALICE,
            data={
                "recipient": Actor.BOB.value,
                "public_key": alice.public_key,
            },
        )

        observer.observe(
            ProtocolEventType.PUBLIC_KEY_RECEIVED,
            actor=Actor.BOB,
            data={
                "sender": Actor.ALICE.value,
                "public_key": alice.public_key,
            },
        )

        observer.observe(
            ProtocolEventType.PUBLIC_KEY_SENT,
            actor=Actor.BOB,
            data={
                "recipient": Actor.ALICE.value,
                "public_key": bob.public_key,
            },
        )

        observer.observe(
            ProtocolEventType.PUBLIC_KEY_RECEIVED,
            actor=Actor.ALICE,
            data={
                "sender": Actor.BOB.value,
                "public_key": bob.public_key,
            },
        )

    alice_public_key = alice.public_key
    bob_public_key = bob.public_key

    alice_secret = alice.compute_shared_secret(bob_public_key)
    bob_secret = bob.compute_shared_secret(alice_public_key)

    result = DiffieHellmanExchangeResult(
        alice_shared_secret=alice_secret,
        bob_shared_secret=bob_secret,
    )

    if observer is not None:
        observer.observe(
            ProtocolEventType.SHARED_SECRET_COMPUTED,
            actor=Actor.ALICE,
            data={
                "peer_public_key": bob.public_key,
                "private_key": alice.private_key,
                "modulus": alice.parameters.prime,
                "shared_secret": alice_secret,
                "expression": (
                    f"{bob.public_key}^{alice.private_key} mod {alice.parameters.prime}"
                ),
            },
        )

        observer.observe(
            ProtocolEventType.SHARED_SECRET_COMPUTED,
            actor=Actor.BOB,
            data={
                "peer_public_key": alice.public_key,
                "private_key": bob.private_key,
                "modulus": bob.parameters.prime,
                "shared_secret": bob_secret,
                "expression": (
                    f"{alice.public_key}^{bob.private_key} mod {bob.parameters.prime}"
                ),
            },
        )

        observer.observe(
            ProtocolEventType.SHARED_SECRET_VERIFIED,
            actor=Actor.SYSTEM,
            data={
                "alice_shared_secret": alice_secret,
                "bob_shared_secret": bob_secret,
                "successful": result.successful,
            },
        )

    return result

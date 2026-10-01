"""Tests for ``perform_key_exchange``, the honest Diffie-Hellman protocol.

They use the toy group p = 23, g = 2, q = 11 with the keys 6 and 7, and
check the shared secret, the provided and generated key pairs, the exact
timeline of 13 events with its actors and data, and the rejection of
participants that use different groups.
"""

from unittest.mock import Mock

import pytest

from kleptography.crypto.dh.exceptions import DiffieHellmanParametersMismatch
from kleptography.crypto.dh.exchange import DiffieHellmanExchangeResult
from kleptography.crypto.dh.parameters import DiffieHellmanParameters
from kleptography.crypto.dh.participant import DiffieHellmanParticipant
from kleptography.crypto.dh.protocol import perform_key_exchange
from kleptography.crypto.dh.tracing.context import ProtocolExecutionContext
from kleptography.crypto.dh.tracing.events import (
    Actor,
    ProtocolEventType,
)


@pytest.fixture
def parameters() -> DiffieHellmanParameters:
    """Return the toy group p = 23, g = 2, q = 11."""
    return DiffieHellmanParameters(
        prime=23,
        generator=2,
        subgroup_order=11,
    )


@pytest.fixture
def participants(
    parameters: DiffieHellmanParameters,
) -> tuple[DiffieHellmanParticipant, DiffieHellmanParticipant]:
    """Return Alice and Bob with the private keys 6 and 7."""
    alice = DiffieHellmanParticipant(parameters)
    bob = DiffieHellmanParticipant(parameters)

    alice.load_private_key(6)
    bob.load_private_key(7)

    return alice, bob


def test_perform_key_exchange_returns_result(
    participants: tuple[
        DiffieHellmanParticipant,
        DiffieHellmanParticipant,
    ],
) -> None:
    """The exchange returns a successful result with equal secrets."""
    alice, bob = participants

    result = perform_key_exchange(alice, bob)

    assert isinstance(result, DiffieHellmanExchangeResult)
    assert result.alice_shared_secret == result.bob_shared_secret
    assert result.successful is True


def test_perform_key_exchange_computes_expected_shared_secret(
    participants: tuple[
        DiffieHellmanParticipant,
        DiffieHellmanParticipant,
    ],
) -> None:
    """The shared secret is B^a mod p."""
    alice, bob = participants

    result = perform_key_exchange(alice, bob)

    if bob.public_key is None or alice.private_key is None:
        pytest.fail("Key pair was not generated.")

    expected = pow(
        bob.public_key,
        alice.private_key,
        alice.parameters.prime,
    )

    assert result.alice_shared_secret == expected
    assert result.bob_shared_secret == expected


def test_perform_key_exchange_generates_alice_keypair(
    parameters: DiffieHellmanParameters,
) -> None:
    """Alice gets a key pair if she has none."""
    alice = DiffieHellmanParticipant(parameters)
    bob = DiffieHellmanParticipant(parameters)

    assert alice.private_key is None
    assert alice.public_key is None

    perform_key_exchange(alice, bob)

    assert alice.private_key is not None
    assert alice.public_key is not None


def test_perform_key_exchange_generates_bob_keypair(
    parameters: DiffieHellmanParameters,
) -> None:
    """Bob gets a key pair if he has none."""
    alice = DiffieHellmanParticipant(parameters)
    bob = DiffieHellmanParticipant(parameters)

    assert bob.private_key is None
    assert bob.public_key is None

    perform_key_exchange(alice, bob)

    assert bob.private_key is not None
    assert bob.public_key is not None


def test_protocol_without_observer_does_not_require_tracing(
    participants: tuple[
        DiffieHellmanParticipant,
        DiffieHellmanParticipant,
    ],
) -> None:
    """The exchange runs without an observer."""
    alice, bob = participants

    result = perform_key_exchange(alice, bob)

    assert result.successful is True


def test_protocol_emits_complete_high_level_timeline(
    participants: tuple[
        DiffieHellmanParticipant,
        DiffieHellmanParticipant,
    ],
) -> None:
    """The observer receives the 13 events in protocol order."""
    alice, bob = participants
    observer = ProtocolExecutionContext()

    perform_key_exchange(
        alice,
        bob,
        observer=observer,
    )

    event_types = [event.event_type for event in observer.events]

    assert event_types == [
        ProtocolEventType.PARAMETERS_SELECTED,
        ProtocolEventType.PARAMETERS_VALIDATED,
        ProtocolEventType.PRIVATE_KEY_PROVIDED,
        ProtocolEventType.PUBLIC_KEY_COMPUTED,
        ProtocolEventType.PRIVATE_KEY_PROVIDED,
        ProtocolEventType.PUBLIC_KEY_COMPUTED,
        ProtocolEventType.PUBLIC_KEY_SENT,
        ProtocolEventType.PUBLIC_KEY_RECEIVED,
        ProtocolEventType.PUBLIC_KEY_SENT,
        ProtocolEventType.PUBLIC_KEY_RECEIVED,
        ProtocolEventType.SHARED_SECRET_COMPUTED,
        ProtocolEventType.SHARED_SECRET_COMPUTED,
        ProtocolEventType.SHARED_SECRET_VERIFIED,
    ]


def test_protocol_events_have_sequential_numbers(
    participants: tuple[
        DiffieHellmanParticipant,
        DiffieHellmanParticipant,
    ],
) -> None:
    """Events are numbered consecutively from 1."""
    alice, bob = participants
    observer = ProtocolExecutionContext()

    perform_key_exchange(
        alice,
        bob,
        observer=observer,
    )

    assert [event.sequence for event in observer.events] == list(
        range(1, len(observer.events) + 1)
    )


def test_protocol_records_correct_actors(
    participants: tuple[
        DiffieHellmanParticipant,
        DiffieHellmanParticipant,
    ],
) -> None:
    """Each event is attributed to the right actor."""
    alice, bob = participants
    observer = ProtocolExecutionContext()

    perform_key_exchange(
        alice,
        bob,
        observer=observer,
    )

    actors = [event.actor for event in observer.events]

    assert actors == [
        Actor.SYSTEM,
        Actor.SYSTEM,
        Actor.ALICE,
        Actor.ALICE,
        Actor.BOB,
        Actor.BOB,
        Actor.ALICE,
        Actor.BOB,
        Actor.BOB,
        Actor.ALICE,
        Actor.ALICE,
        Actor.BOB,
        Actor.SYSTEM,
    ]


def test_protocol_records_parameters(
    participants: tuple[
        DiffieHellmanParticipant,
        DiffieHellmanParticipant,
    ],
) -> None:
    """The parameter events carry p, g and q."""
    alice, bob = participants
    observer = ProtocolExecutionContext()

    perform_key_exchange(
        alice,
        bob,
        observer=observer,
    )

    selected = observer.events[0]
    validated = observer.events[1]

    expected = {
        "prime": 23,
        "generator": 2,
        "subgroup_order": 11,
    }

    assert dict(selected.data) == expected
    assert dict(validated.data) == expected


def test_protocol_records_public_key_exchange(
    participants: tuple[
        DiffieHellmanParticipant,
        DiffieHellmanParticipant,
    ],
) -> None:
    """The send and receive events carry the right public keys."""
    alice, bob = participants
    observer = ProtocolExecutionContext()

    perform_key_exchange(
        alice,
        bob,
        observer=observer,
    )

    sent_events = [
        event
        for event in observer.events
        if event.event_type is ProtocolEventType.PUBLIC_KEY_SENT
    ]

    received_events = [
        event
        for event in observer.events
        if event.event_type is ProtocolEventType.PUBLIC_KEY_RECEIVED
    ]

    assert len(sent_events) == 2
    assert len(received_events) == 2

    assert sent_events[0].actor is Actor.ALICE
    assert sent_events[0].data["recipient"] == Actor.BOB.value
    assert sent_events[0].data["public_key"] == alice.public_key

    assert received_events[0].actor is Actor.BOB
    assert received_events[0].data["sender"] == Actor.ALICE.value
    assert received_events[0].data["public_key"] == alice.public_key

    assert sent_events[1].actor is Actor.BOB
    assert sent_events[1].data["recipient"] == Actor.ALICE.value
    assert sent_events[1].data["public_key"] == bob.public_key

    assert received_events[1].actor is Actor.ALICE
    assert received_events[1].data["sender"] == Actor.BOB.value
    assert received_events[1].data["public_key"] == bob.public_key


def test_protocol_records_shared_secret_computation(
    participants: tuple[
        DiffieHellmanParticipant,
        DiffieHellmanParticipant,
    ],
) -> None:
    """The secret events carry each participant's computation."""
    alice, bob = participants
    observer = ProtocolExecutionContext()

    result = perform_key_exchange(
        alice,
        bob,
        observer=observer,
    )

    secret_events = [
        event
        for event in observer.events
        if event.event_type is ProtocolEventType.SHARED_SECRET_COMPUTED
    ]

    assert len(secret_events) == 2

    alice_event = secret_events[0]
    bob_event = secret_events[1]

    assert alice_event.actor is Actor.ALICE
    assert alice_event.data["peer_public_key"] == bob.public_key
    assert alice_event.data["private_key"] == alice.private_key
    assert alice_event.data["shared_secret"] == result.alice_shared_secret

    assert bob_event.actor is Actor.BOB
    assert bob_event.data["peer_public_key"] == alice.public_key
    assert bob_event.data["private_key"] == bob.private_key
    assert bob_event.data["shared_secret"] == result.bob_shared_secret


def test_protocol_records_successful_verification(
    participants: tuple[
        DiffieHellmanParticipant,
        DiffieHellmanParticipant,
    ],
) -> None:
    """The verification event carries both secrets and the success."""
    alice, bob = participants
    observer = ProtocolExecutionContext()

    result = perform_key_exchange(
        alice,
        bob,
        observer=observer,
    )

    verification = observer.events[-1]

    assert verification.event_type is ProtocolEventType.SHARED_SECRET_VERIFIED
    assert verification.actor is Actor.SYSTEM
    assert verification.data["alice_shared_secret"] == result.alice_shared_secret
    assert verification.data["bob_shared_secret"] == result.bob_shared_secret
    assert verification.data["successful"] is True


def test_protocol_accepts_generic_observer(
    participants: tuple[
        DiffieHellmanParticipant,
        DiffieHellmanParticipant,
    ],
) -> None:
    """Any OperationObserver receives the events."""
    alice, bob = participants
    observer = Mock()

    perform_key_exchange(
        alice,
        bob,
        observer=observer,
    )

    assert observer.observe.call_count == 13


def test_protocol_does_not_depend_on_protocol_execution_context(
    participants: tuple[
        DiffieHellmanParticipant,
        DiffieHellmanParticipant,
    ],
) -> None:
    """The protocol only uses the observer interface."""
    alice, bob = participants
    observer = Mock()

    perform_key_exchange(
        alice,
        bob,
        observer=observer,
    )

    calls = observer.observe.call_args_list

    assert calls[0].args[0] is ProtocolEventType.PARAMETERS_SELECTED
    assert calls[-1].args[0] is ProtocolEventType.SHARED_SECRET_VERIFIED


def test_protocol_preserves_provided_keypairs(
    participants: tuple[
        DiffieHellmanParticipant,
        DiffieHellmanParticipant,
    ],
) -> None:
    """Provided key pairs are kept unchanged."""
    alice, bob = participants

    result = perform_key_exchange(alice, bob)

    assert alice.private_key == 6
    assert alice.public_key == 18
    assert bob.private_key == 7
    assert bob.public_key == 13
    assert result.alice_shared_secret == 6
    assert result.bob_shared_secret == 6


def test_protocol_is_reproducible_with_provided_keypairs(
    parameters: DiffieHellmanParameters,
) -> None:
    """Provided keys give the same timeline on every run."""
    timelines = []

    for _ in range(2):
        alice = DiffieHellmanParticipant(parameters)
        bob = DiffieHellmanParticipant(parameters)
        alice.load_private_key(6)
        bob.load_private_key(7)
        observer = ProtocolExecutionContext()

        perform_key_exchange(alice, bob, observer=observer)

        timelines.append(observer.events)

    assert timelines[0] == timelines[1]


def test_protocol_generates_keypairs_for_participants_without_one(
    parameters: DiffieHellmanParameters,
) -> None:
    """Missing key pairs are generated and traced as generated."""
    alice = DiffieHellmanParticipant(parameters)
    bob = DiffieHellmanParticipant(parameters)
    observer = ProtocolExecutionContext()

    result = perform_key_exchange(alice, bob, observer=observer)

    key_events = [
        event
        for event in observer.events
        if event.event_type is ProtocolEventType.PRIVATE_KEY_GENERATED
    ]

    assert [event.actor for event in key_events] == [Actor.ALICE, Actor.BOB]
    assert key_events[0].data["private_key"] == alice.private_key
    assert key_events[1].data["private_key"] == bob.private_key
    assert result.successful is True


def test_protocol_mixes_provided_and_generated_keypairs(
    parameters: DiffieHellmanParameters,
) -> None:
    """A provided and a generated key are traced as such."""
    alice = DiffieHellmanParticipant(parameters)
    bob = DiffieHellmanParticipant(parameters)
    alice.load_private_key(6)
    observer = ProtocolExecutionContext()

    result = perform_key_exchange(alice, bob, observer=observer)

    assert observer.events[2].event_type is ProtocolEventType.PRIVATE_KEY_PROVIDED
    assert observer.events[2].actor is Actor.ALICE
    assert observer.events[4].event_type is ProtocolEventType.PRIVATE_KEY_GENERATED
    assert observer.events[4].actor is Actor.BOB
    assert alice.private_key == 6
    assert result.successful is True


def test_protocol_reuses_keypairs_across_exchanges(
    parameters: DiffieHellmanParameters,
) -> None:
    """A second exchange reuses the same keys (static DH)."""
    alice = DiffieHellmanParticipant(parameters)
    bob = DiffieHellmanParticipant(parameters)

    first = perform_key_exchange(alice, bob)
    alice_private_key = alice.private_key
    bob_private_key = bob.private_key

    second = perform_key_exchange(alice, bob)

    assert alice.private_key == alice_private_key
    assert bob.private_key == bob_private_key
    assert first == second


def test_protocol_records_public_key_derivation(
    participants: tuple[
        DiffieHellmanParticipant,
        DiffieHellmanParticipant,
    ],
) -> None:
    """The public key event carries g, x, p, g^x and its expression."""
    alice, bob = participants
    observer = ProtocolExecutionContext()

    perform_key_exchange(alice, bob, observer=observer)

    alice_public = observer.events[3]

    assert alice_public.event_type is ProtocolEventType.PUBLIC_KEY_COMPUTED
    assert dict(alice_public.data) == {
        "base": 2,
        "exponent": 6,
        "modulus": 23,
        "public_key": 18,
        "expression": "2^6 mod 23",
    }


def test_protocol_rejects_mismatched_parameters(
    parameters: DiffieHellmanParameters,
) -> None:
    """Different groups are rejected before any key or event."""
    other_parameters = DiffieHellmanParameters(
        prime=47,
        generator=2,
        subgroup_order=23,
    )
    alice = DiffieHellmanParticipant(parameters)
    bob = DiffieHellmanParticipant(other_parameters)
    observer = ProtocolExecutionContext()

    with pytest.raises(DiffieHellmanParametersMismatch):
        perform_key_exchange(alice, bob, observer=observer)

    assert observer.events == ()
    assert alice.has_keypair is False
    assert bob.has_keypair is False


def test_protocol_accepts_equal_but_distinct_parameter_objects(
    parameters: DiffieHellmanParameters,
) -> None:
    """Equal parameters in distinct objects are accepted."""
    alice = DiffieHellmanParticipant(parameters)
    bob = DiffieHellmanParticipant(
        DiffieHellmanParameters(prime=23, generator=2, subgroup_order=11)
    )

    result = perform_key_exchange(alice, bob)

    assert result.successful is True

from types import MappingProxyType

from kleptography.crypto.dh.tracing.context import ProtocolExecutionContext
from kleptography.crypto.dh.tracing.events import (
    Actor,
    ProtocolEventType,
)
from kleptography.crypto.dh.tracing.observer import OperationObserver


def test_context_implements_operation_observer() -> None:
    context = ProtocolExecutionContext()

    assert isinstance(context, OperationObserver)


def test_context_starts_empty() -> None:
    context = ProtocolExecutionContext()

    assert context.events == ()


def test_observe_creates_protocol_event() -> None:
    context = ProtocolExecutionContext()

    context.observe(
        ProtocolEventType.PRIVATE_KEY_GENERATED,
        actor=Actor.ALICE,
        data={"private_key": 6},
    )

    assert len(context.events) == 1

    event = context.events[0]

    assert event.sequence == 1
    assert event.event_type is ProtocolEventType.PRIVATE_KEY_GENERATED
    assert event.actor is Actor.ALICE
    assert event.data["private_key"] == 6


def test_observe_assigns_incremental_sequences() -> None:
    context = ProtocolExecutionContext()

    context.observe(
        ProtocolEventType.PARAMETERS_SELECTED,
        actor=Actor.SYSTEM,
    )
    context.observe(
        ProtocolEventType.PRIVATE_KEY_GENERATED,
        actor=Actor.ALICE,
    )
    context.observe(
        ProtocolEventType.PUBLIC_KEY_COMPUTED,
        actor=Actor.ALICE,
    )

    assert [event.sequence for event in context.events] == [1, 2, 3]


def test_observe_preserves_order() -> None:
    context = ProtocolExecutionContext()

    context.observe(
        ProtocolEventType.PUBLIC_KEY_SENT,
        actor=Actor.ALICE,
    )
    context.observe(
        ProtocolEventType.PUBLIC_KEY_RECEIVED,
        actor=Actor.BOB,
    )
    context.observe(
        ProtocolEventType.PUBLIC_KEY_SENT,
        actor=Actor.BOB,
    )
    context.observe(
        ProtocolEventType.PUBLIC_KEY_RECEIVED,
        actor=Actor.ALICE,
    )

    assert [event.event_type for event in context.events] == [
        ProtocolEventType.PUBLIC_KEY_SENT,
        ProtocolEventType.PUBLIC_KEY_RECEIVED,
        ProtocolEventType.PUBLIC_KEY_SENT,
        ProtocolEventType.PUBLIC_KEY_RECEIVED,
    ]

    assert [event.actor for event in context.events] == [
        Actor.ALICE,
        Actor.BOB,
        Actor.BOB,
        Actor.ALICE,
    ]


def test_observe_without_data_creates_empty_mapping() -> None:
    context = ProtocolExecutionContext()

    context.observe(
        ProtocolEventType.PARAMETERS_VALIDATED,
        actor=Actor.SYSTEM,
    )

    assert context.events[0].data == {}
    assert isinstance(context.events[0].data, MappingProxyType)


def test_observe_copies_input_data() -> None:
    context = ProtocolExecutionContext()
    data = {"public_key": 18}

    context.observe(
        ProtocolEventType.PUBLIC_KEY_COMPUTED,
        actor=Actor.ALICE,
        data=data,
    )

    data["public_key"] = 99

    assert context.events[0].data["public_key"] == 18


def test_events_returns_tuple() -> None:
    context = ProtocolExecutionContext()

    context.observe(
        ProtocolEventType.PARAMETERS_SELECTED,
        actor=Actor.SYSTEM,
    )

    assert isinstance(context.events, tuple)


def test_events_snapshot_is_independent() -> None:
    context = ProtocolExecutionContext()

    context.observe(
        ProtocolEventType.PARAMETERS_SELECTED,
        actor=Actor.SYSTEM,
    )

    first_snapshot = context.events

    context.observe(
        ProtocolEventType.PARAMETERS_VALIDATED,
        actor=Actor.SYSTEM,
    )

    assert len(first_snapshot) == 1
    assert len(context.events) == 2

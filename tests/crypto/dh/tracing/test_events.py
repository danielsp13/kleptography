from types import MappingProxyType
from typing import cast

import pytest

from kleptography.crypto.dh.tracing.events import (
    Actor,
    ProtocolEvent,
    ProtocolEventType,
)


def test_actor_values() -> None:
    assert Actor.SYSTEM.value == "system"
    assert Actor.ALICE.value == "alice"
    assert Actor.BOB.value == "bob"


def test_protocol_event_type_values() -> None:
    assert ProtocolEventType.PARAMETERS_SELECTED.value == "parameters_selected"
    assert ProtocolEventType.PARAMETERS_VALIDATED.value == "parameters_validated"
    assert ProtocolEventType.PRIVATE_KEY_GENERATED.value == "private_key_generated"
    assert ProtocolEventType.PUBLIC_KEY_COMPUTED.value == "public_key_computed"
    assert ProtocolEventType.PUBLIC_KEY_SENT.value == "public_key_sent"
    assert ProtocolEventType.PUBLIC_KEY_RECEIVED.value == "public_key_received"
    assert ProtocolEventType.SHARED_SECRET_COMPUTED.value == "shared_secret_computed"
    assert ProtocolEventType.SHARED_SECRET_VERIFIED.value == "shared_secret_verified"


def test_protocol_event_stores_data_as_immutable_mapping() -> None:
    data = {
        "prime": 23,
        "generator": 5,
    }

    event = ProtocolEvent(
        sequence=1,
        event_type=ProtocolEventType.PARAMETERS_SELECTED,
        actor=Actor.SYSTEM,
        data=data,
    )

    assert event.data["prime"] == 23
    assert event.data["generator"] == 5
    assert isinstance(event.data, MappingProxyType)


def test_protocol_event_copies_input_data() -> None:
    data = {"value": 23}

    event = ProtocolEvent(
        sequence=1,
        event_type=ProtocolEventType.PARAMETERS_SELECTED,
        actor=Actor.SYSTEM,
        data=data,
    )

    data["value"] = 99

    assert event.data["value"] == 23


def test_protocol_event_data_cannot_be_modified() -> None:
    event = ProtocolEvent(
        sequence=1,
        event_type=ProtocolEventType.PARAMETERS_SELECTED,
        actor=Actor.SYSTEM,
        data={"value": 23},
    )

    data = cast(dict[str, object], event.data)

    with pytest.raises(TypeError):
        data["value"] = 99


def test_protocol_event_rejects_zero_sequence() -> None:
    with pytest.raises(
        ValueError,
        match="Protocol event sequence must be greater than zero",
    ):
        ProtocolEvent(
            sequence=0,
            event_type=ProtocolEventType.PARAMETERS_SELECTED,
            actor=Actor.SYSTEM,
        )


def test_protocol_event_rejects_negative_sequence() -> None:
    with pytest.raises(
        ValueError,
        match="Protocol event sequence must be greater than zero",
    ):
        ProtocolEvent(
            sequence=-1,
            event_type=ProtocolEventType.PARAMETERS_SELECTED,
            actor=Actor.SYSTEM,
        )


def test_protocol_event_default_data_is_empty() -> None:
    event = ProtocolEvent(
        sequence=1,
        event_type=ProtocolEventType.PARAMETERS_SELECTED,
        actor=Actor.SYSTEM,
    )

    assert event.data == {}

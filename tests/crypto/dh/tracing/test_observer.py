from __future__ import annotations

from typing import Mapping

import pytest

from kleptography.crypto.dh.tracing.events import Actor, ProtocolEventType
from kleptography.crypto.dh.tracing.observer import OperationObserver


class TestObserver(OperationObserver):
    def observe(
        self,
        event_type: ProtocolEventType,
        *,
        actor: Actor,
        data: Mapping[str, object] | None = None,
    ) -> None:
        pass


def test_operation_observer_observe_raises_not_implemented_error() -> None:
    class ConcreteObserver(OperationObserver):
        def observe(
            self,
            event_type: ProtocolEventType,
            *,
            actor: Actor,
            data: Mapping[str, object] | None = None,
        ) -> None:
            super().observe(
                event_type,
                actor=actor,
                data=data,
            )

    observer = ConcreteObserver()

    with pytest.raises(NotImplementedError):
        observer.observe(
            ProtocolEventType.PRIVATE_KEY_GENERATED,
            actor=Actor.ALICE,
            data={"private_key": 7},
        )


def test_operation_observer_is_abstract() -> None:
    with pytest.raises(TypeError):
        OperationObserver()


def test_operation_observer_can_be_implemented() -> None:
    observer = TestObserver()

    assert isinstance(observer, OperationObserver)


def test_operation_observer_requires_observe_implementation() -> None:
    class IncompleteObserver(OperationObserver):
        pass

    with pytest.raises(TypeError):
        IncompleteObserver()


def test_operation_observer_observe_accepts_event() -> None:
    observer = TestObserver()

    result = observer.observe(
        ProtocolEventType.PRIVATE_KEY_GENERATED,
        actor=Actor.ALICE,
        data={"private_key": 7},
    )

    assert result is None


def test_operation_observer_observe_accepts_event_without_data() -> None:
    observer = TestObserver()

    result = observer.observe(
        ProtocolEventType.PUBLIC_KEY_COMPUTED,
        actor=Actor.BOB,
    )

    assert result is None

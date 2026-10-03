# Compatibility shim bridging the packages in KMCS to the real events API.
#
# The real kmcs.core.events module exposes `Record` and
# `EventBus.emit(...)`, but several packages (campaigns, corpus,
# reproduction) were written against an earlier draft API that used
# `Event` and `EventBus.publish(...)`. This module provides both the
# legacy names and a process-wide default bus, so those packages work
# unchanged against the real events implementation.

from __future__ import annotations

import logging
from typing import Any, Mapping, Optional

from .core.events import EventBus

logger = logging.getLogger(__name__)

_DEFAULT_BUS: Optional[EventBus] = None


def get_default_bus() -> EventBus:
    """Return the process-wide default bus, creating it on first use.

    The bus is a process-wide singleton so that all components share
    the same event stream when no explicit bus is supplied.
    """
    global _DEFAULT_BUS
    if _DEFAULT_BUS is None:
        _DEFAULT_BUS = EventBus(name="kmcs-default")
    return _DEFAULT_BUS


class Event:
    """Compatibility wrapper for the legacy ``Event`` constructor shape.

    The real events module uses :class:`Record`, whose constructor
    takes ``topic`` and ``payload``. This shim accepts the older
    shape (``type``, ``source``, ``data``) and derives a topic from
    the source when one is not supplied.
    """

    __slots__ = ("type", "source", "data", "topic")

    def __init__(
        self,
        *,
        type: Any,
        source: str = "",
        data: Optional[Mapping[str, Any]] = None,
        topic: Optional[str] = None,
    ) -> None:
        self.type = type
        self.source = source
        self.data = dict(data or {})
        self.topic = (
            topic
            if topic is not None
            else f"kmcs.{source or 'anonymous'}"
        )

    def __repr__(self) -> str:
        return (
            f"Event(topic={self.topic!r}, "
            f"type={self.type!r}, source={self.source!r})"
        )


def publish_event(bus: Any, event: "Event") -> None:
    """Emit ``event`` on ``bus`` using the real events API.

    Never raises: subscriber errors are logged at debug level and
    swallowed, matching the contract the calling packages expect.
    """
    if bus is None or event is None:
        return
    try:
        emit = getattr(bus, "emit", None)
        if callable(emit):
            emit(
                event.topic,
                event.type,
                event.data,
                source=event.source,
            )
    except Exception as exc:  # noqa: BLE001 - subscribers are untrusted
        logger.debug("event emit failed: %s", exc)

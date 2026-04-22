"""Tests for logbook integration."""

from __future__ import annotations

from unittest.mock import MagicMock

from custom_components.aegis_ajax.const import ALL_EVENT_TYPES, DOMAIN
from custom_components.aegis_ajax.logbook import (
    _EVENT_DESCRIPTIONS,
    LOGBOOK_ENTRY_MESSAGE,
    LOGBOOK_ENTRY_NAME,
    async_describe_events,
)


def _make_event(event_type: str, **data: object) -> MagicMock:
    event = MagicMock()
    event.data = {"event_type": event_type, **data}
    return event


class TestAsyncDescribeEvents:
    def test_registers_handler(self) -> None:
        hass = MagicMock()
        async_describe_event = MagicMock()
        async_describe_events(hass, async_describe_event)
        async_describe_event.assert_called_once()
        call_args = async_describe_event.call_args[0]
        assert call_args[0] == DOMAIN
        assert call_args[1] == f"{DOMAIN}_event"
        assert callable(call_args[2])


class TestLogbookDescriptions:
    def _get_handler(self) -> object:
        async_describe_event = MagicMock()
        async_describe_events(MagicMock(), async_describe_event)
        return async_describe_event.call_args[0][2]

    def test_arm_event(self) -> None:
        handler = self._get_handler()
        result = handler(_make_event("arm", device_name="Keypad"))
        assert result[LOGBOOK_ENTRY_NAME] == "Aegis"
        assert "Armed" in result[LOGBOOK_ENTRY_MESSAGE]
        assert "Keypad" in result[LOGBOOK_ENTRY_MESSAGE]

    def test_disarm_event(self) -> None:
        handler = self._get_handler()
        result = handler(_make_event("disarm", device_name="App User"))
        assert "Disarmed" in result[LOGBOOK_ENTRY_MESSAGE]
        assert "App User" in result[LOGBOOK_ENTRY_MESSAGE]

    def test_alarm_event(self) -> None:
        handler = self._get_handler()
        result = handler(_make_event("alarm", device_name="Front Door"))
        assert "Alarm" in result[LOGBOOK_ENTRY_MESSAGE]
        assert "Front Door" in result[LOGBOOK_ENTRY_MESSAGE]

    def test_door_open_event(self) -> None:
        handler = self._get_handler()
        result = handler(_make_event("door_open", device_name="Main Entrance"))
        assert "Door opened" in result[LOGBOOK_ENTRY_MESSAGE]

    def test_motion_event(self) -> None:
        handler = self._get_handler()
        result = handler(_make_event("motion", device_name="Hallway"))
        assert "Motion" in result[LOGBOOK_ENTRY_MESSAGE]

    def test_room_name_appended(self) -> None:
        handler = self._get_handler()
        result = handler(_make_event("alarm", device_name="Sensor", room_name="Kitchen"))
        assert "(Kitchen)" in result[LOGBOOK_ENTRY_MESSAGE]

    def test_no_room_name(self) -> None:
        handler = self._get_handler()
        result = handler(_make_event("alarm", device_name="Sensor"))
        assert "Sensor" in result[LOGBOOK_ENTRY_MESSAGE]
        # No room appended
        assert result[LOGBOOK_ENTRY_MESSAGE].count("(") == 1  # only "(via Sensor)"

    def test_unknown_event_type(self) -> None:
        handler = self._get_handler()
        result = handler(_make_event("some_future_event", device_name="Device"))
        assert "Security event" in result[LOGBOOK_ENTRY_MESSAGE]

    def test_missing_device_name(self) -> None:
        handler = self._get_handler()
        result = handler(_make_event("arm"))
        assert "Unknown device" in result[LOGBOOK_ENTRY_MESSAGE]

    def test_panic_event(self) -> None:
        handler = self._get_handler()
        result = handler(_make_event("panic", device_name="Keypad"))
        assert "Panic" in result[LOGBOOK_ENTRY_MESSAGE]

    def test_fire_event(self) -> None:
        handler = self._get_handler()
        result = handler(_make_event("fire", device_name="Kitchen"))
        assert "Fire" in result[LOGBOOK_ENTRY_MESSAGE]

    def test_all_event_types_have_descriptions(self) -> None:
        for event_type in ALL_EVENT_TYPES:
            assert event_type in _EVENT_DESCRIPTIONS, f"Missing description for {event_type}"

"""Tests for logbook integration."""

from __future__ import annotations

from custom_components.aegis_ajax.logbook import describe_event


class TestDescribeEvent:
    def test_arm_event(self) -> None:
        result = describe_event("arm", {"user_name": "Carlos"})
        assert result["name"] == "Ajax Security"
        assert "Armed" in result["message"]
        assert "Carlos" in result["message"]

    def test_disarm_event(self) -> None:
        result = describe_event("disarm", {"user_name": "Ana"})
        assert "Disarmed" in result["message"]
        assert "Ana" in result["message"]

    def test_alarm_event(self) -> None:
        result = describe_event("alarm", {"device_name": "Front Door"})
        assert "Alarm" in result["message"]
        assert "Front Door" in result["message"]

    def test_door_open_event(self) -> None:
        result = describe_event("door_open", {"device_name": "Main Entrance"})
        assert "Opened" in result["message"]

    def test_motion_event(self) -> None:
        result = describe_event("motion", {"device_name": "Hallway"})
        assert "Motion" in result["message"]

    def test_unknown_event_type(self) -> None:
        result = describe_event("some_future_event", {})
        assert result["message"] is not None

    def test_event_without_data(self) -> None:
        result = describe_event("arm", {})
        assert "Armed" in result["message"]

    def test_panic_event(self) -> None:
        result = describe_event("panic", {"device_name": "Keypad"})
        assert "Panic" in result["message"]

    def test_fire_event(self) -> None:
        result = describe_event("fire", {"device_name": "Kitchen"})
        assert "Fire" in result["message"]

    def test_icon_present(self) -> None:
        result = describe_event("alarm", {})
        assert result["icon"].startswith("mdi:")

    def test_unknown_event_has_default_icon(self) -> None:
        result = describe_event("unknown_xyz", {})
        assert result["icon"] == "mdi:shield-home"

    def test_all_event_types_have_descriptions(self) -> None:
        from custom_components.aegis_ajax.const import ALL_EVENT_TYPES
        from custom_components.aegis_ajax.logbook import _EVENT_DESCRIPTIONS

        for event_type in ALL_EVENT_TYPES:
            assert event_type in _EVENT_DESCRIPTIONS, f"Missing description for {event_type}"

    def test_all_event_types_have_icons(self) -> None:
        from custom_components.aegis_ajax.const import ALL_EVENT_TYPES
        from custom_components.aegis_ajax.logbook import _EVENT_ICONS

        for event_type in ALL_EVENT_TYPES:
            assert event_type in _EVENT_ICONS, f"Missing icon for {event_type}"

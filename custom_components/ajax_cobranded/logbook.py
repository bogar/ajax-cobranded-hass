"""Logbook descriptions for Ajax Security events."""

from __future__ import annotations

from typing import Any

_EVENT_DESCRIPTIONS: dict[str, str] = {
    "alarm": "Alarm: {device_name}",
    "arm": "Armed by {user_name}",
    "arm_night": "Armed night by {user_name}",
    "battery_low": "Battery low: {device_name}",
    "co_alarm": "CO alarm: {device_name}",
    "connection_lost": "Connection lost: {device_name}",
    "disarm": "Disarmed by {user_name}",
    "disarm_night": "Disarmed night by {user_name}",
    "door_open": "Opened: {device_name}",
    "fire": "Fire: {device_name}",
    "flood": "Flood: {device_name}",
    "glass_break": "Glass break: {device_name}",
    "malfunction": "Malfunction: {device_name}",
    "motion": "Motion: {device_name}",
    "panic": "Panic: {device_name}",
    "tamper": "Tamper: {device_name}",
}

_EVENT_ICONS: dict[str, str] = {
    "alarm": "mdi:shield-alert",
    "arm": "mdi:shield-lock",
    "arm_night": "mdi:shield-moon",
    "battery_low": "mdi:battery-low",
    "co_alarm": "mdi:molecule-co",
    "connection_lost": "mdi:wifi-off",
    "disarm": "mdi:shield-off",
    "disarm_night": "mdi:shield-off",
    "door_open": "mdi:door-open",
    "fire": "mdi:fire",
    "flood": "mdi:water-alert",
    "glass_break": "mdi:window-shutter-alert",
    "malfunction": "mdi:alert-circle",
    "motion": "mdi:motion-sensor",
    "panic": "mdi:alert-octagon",
    "tamper": "mdi:alert",
}


def describe_event(event_type: str, data: dict[str, Any]) -> dict[str, str]:
    """Return a logbook description for an Ajax security event."""
    template = _EVENT_DESCRIPTIONS.get(event_type, f"Security event: {event_type}")
    device_name = data.get("device_name", "Unknown device")
    user_name = data.get("user_name", "Unknown user")

    message = template.format(device_name=device_name, user_name=user_name)
    icon = _EVENT_ICONS.get(event_type, "mdi:shield-home")

    return {"name": "Ajax Security", "message": message, "icon": icon}

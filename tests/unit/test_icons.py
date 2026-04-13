"""Tests for icons.json validity."""

from __future__ import annotations

import json
from pathlib import Path

_ICONS_PATH = Path(__file__).parent.parent.parent / "custom_components/ajax_cobranded/icons.json"


class TestIconsJson:
    def test_icons_json_is_valid(self) -> None:
        data = json.loads(_ICONS_PATH.read_text())
        assert "entity" in data

    def test_icons_has_binary_sensor(self) -> None:
        data = json.loads(_ICONS_PATH.read_text())
        assert "binary_sensor" in data["entity"]

    def test_icons_has_sensor(self) -> None:
        data = json.loads(_ICONS_PATH.read_text())
        assert "sensor" in data["entity"]

    def test_all_icons_start_with_mdi(self) -> None:
        data = json.loads(_ICONS_PATH.read_text())

        def _check_mdi(obj: dict | str, path: str = "") -> None:
            if isinstance(obj, str):
                assert obj.startswith("mdi:"), f"Icon at {path} not mdi: {obj}"
            elif isinstance(obj, dict):
                for k, v in obj.items():
                    _check_mdi(v, f"{path}.{k}")

        _check_mdi(data["entity"])

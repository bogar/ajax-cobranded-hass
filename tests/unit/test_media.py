"""Tests for media API."""

from __future__ import annotations

from custom_components.aegis_ajax.api.media import (
    _encode_embedded_message,
    _encode_string_field,
    _encode_varint,
)


class TestProtobufEncoding:
    def test_encode_varint_small(self) -> None:
        assert _encode_varint(1) == b"\x01"

    def test_encode_varint_medium(self) -> None:
        assert _encode_varint(300) == b"\xac\x02"

    def test_encode_varint_zero(self) -> None:
        assert _encode_varint(0) == b"\x00"

    def test_encode_string_field(self) -> None:
        result = _encode_string_field(1, "test")
        assert result[0] == 0x0A  # field 1, wire type 2
        assert result[1] == 4  # length
        assert result[2:] == b"test"

    def test_encode_embedded_message(self) -> None:
        inner = _encode_string_field(1, "hub123")
        result = _encode_embedded_message(2, inner)
        assert result[0] == 0x12  # field 2, wire type 2
        assert inner in result

    def test_stream_notification_media_request_encoding(self) -> None:
        """Verify the full request encoding for streamNotificationMedia."""
        notification_id = "ABC123"
        hub_hex_id = "E5F6A7B8"
        origin_msg = _encode_string_field(1, hub_hex_id)
        request = _encode_string_field(1, notification_id) + _encode_embedded_message(2, origin_msg)
        # Should contain both strings
        assert b"ABC123" in request
        assert b"E5F6A7B8" in request

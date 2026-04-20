"""Tests for HTS binary protocol framing."""

import pytest

from custom_components.aegis_ajax.api.hts.protocol import (
    crc16,
    decode_frame,
    encode_frame,
    escape,
    pad16,
    unescape,
)

STX = 0x02
ETX = 0x03
ESC = 0x04


# ---------------------------------------------------------------------------
# crc16
# ---------------------------------------------------------------------------


class TestCrc16:
    def test_empty(self) -> None:
        # CRC-16/CCITT with init 0xA001, no data → init value
        assert crc16(b"") == 0xA001

    def test_deterministic(self) -> None:
        assert crc16(b"123456789") == crc16(b"123456789")

    def test_single_byte(self) -> None:
        result = crc16(b"\x01")
        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFF

    def test_returns_int(self) -> None:
        assert isinstance(crc16(b"hello"), int)

    def test_different_inputs_different_crc(self) -> None:
        assert crc16(b"hello") != crc16(b"world")

    def test_different_inputs_different_outputs(self) -> None:
        assert crc16(b"abc") != crc16(b"abd")


# ---------------------------------------------------------------------------
# escape / unescape
# ---------------------------------------------------------------------------


class TestEscape:
    def test_escape_stx(self) -> None:
        assert escape(bytes([STX])) == bytes([ESC, 0x32])

    def test_escape_etx(self) -> None:
        assert escape(bytes([ETX])) == bytes([ESC, 0x33])

    def test_escape_esc(self) -> None:
        assert escape(bytes([ESC])) == bytes([ESC, 0x34])

    def test_no_special_bytes(self) -> None:
        data = b"\x00\x01\x05\xff"
        assert escape(data) == data

    def test_mixed(self) -> None:
        data = bytes([0x01, STX, 0x05, ETX, ESC, 0xFF])
        expected = bytes([0x01, ESC, 0x32, 0x05, ESC, 0x33, ESC, 0x34, 0xFF])
        assert escape(data) == expected

    def test_empty(self) -> None:
        assert escape(b"") == b""

    def test_multiple_stx(self) -> None:
        assert escape(bytes([STX, STX])) == bytes([ESC, 0x32, ESC, 0x32])


class TestUnescape:
    def test_unescape_stx(self) -> None:
        assert unescape(bytes([ESC, 0x32])) == bytes([STX])

    def test_unescape_etx(self) -> None:
        assert unescape(bytes([ESC, 0x33])) == bytes([ETX])

    def test_unescape_esc(self) -> None:
        assert unescape(bytes([ESC, 0x34])) == bytes([ESC])

    def test_no_special(self) -> None:
        data = b"\x00\x01\x05\xff"
        assert unescape(data) == data

    def test_mixed(self) -> None:
        escaped = bytes([0x01, ESC, 0x32, 0x05, ESC, 0x33, ESC, 0x34, 0xFF])
        expected = bytes([0x01, STX, 0x05, ETX, ESC, 0xFF])
        assert unescape(escaped) == expected

    def test_empty(self) -> None:
        assert unescape(b"") == b""

    def test_roundtrip(self) -> None:
        original = bytes(range(256))
        assert unescape(escape(original)) == original

    def test_invalid_escape_raises(self) -> None:
        with pytest.raises((ValueError, KeyError)):
            unescape(bytes([ESC, 0x99]))

    def test_trailing_esc_raises(self) -> None:
        with pytest.raises((ValueError, IndexError)):
            unescape(bytes([ESC]))


# ---------------------------------------------------------------------------
# pad16
# ---------------------------------------------------------------------------


class TestPad16:
    def test_output_multiple_of_16(self) -> None:
        for length in [0, 1, 5, 15, 16, 17, 31, 32, 33]:
            result = pad16(bytes(length))
            assert len(result) % 16 == 0, f"Failed for input length {length}"

    def test_padding_to_boundary(self) -> None:
        # Padding fills to next 16-byte boundary
        for length in [1, 5, 15, 17, 31]:
            original = bytes(length)
            result = pad16(original)
            expected = length + (16 - length % 16)
            assert len(result) == expected, f"Failed for input length {length}"

    def test_preserves_prefix(self) -> None:
        data = b"\x01\x02\x03\x04"
        result = pad16(data)
        assert result[: len(data)] == data

    def test_empty_input(self) -> None:
        # Empty input is already aligned, returned as-is
        result = pad16(b"")
        assert result == b""

    def test_returns_bytes(self) -> None:
        assert isinstance(pad16(b"hello"), bytes)

    def test_randomness(self) -> None:
        # Two calls with same input should not always produce identical output
        # (padding bytes are random); run several times to confirm
        data = b"x" * 5
        results = {pad16(data) for _ in range(20)}
        assert len(results) > 1, "pad16 padding does not appear random"


# ---------------------------------------------------------------------------
# encode_frame / decode_frame
# ---------------------------------------------------------------------------


class TestEncodeFrame:
    def test_starts_with_stx(self) -> None:
        frame = encode_frame(b"\xaa\xbb")
        assert frame[0] == STX

    def test_ends_with_etx(self) -> None:
        frame = encode_frame(b"\xaa\xbb")
        assert frame[-1] == ETX

    def test_no_raw_stx_etx_in_middle(self) -> None:
        frame = encode_frame(bytes(range(256)))
        inner = frame[1:-1]
        assert STX not in inner
        assert ETX not in inner

    def test_returns_bytes(self) -> None:
        assert isinstance(encode_frame(b"test"), bytes)

    def test_empty_body(self) -> None:
        frame = encode_frame(b"")
        assert frame[0] == STX
        assert frame[-1] == ETX


class TestDecodeFrame:
    def test_roundtrip(self) -> None:
        body = b"\x11\x22\x33\x44"
        frame = encode_frame(body)
        assert decode_frame(frame) == body

    def test_roundtrip_empty(self) -> None:
        frame = encode_frame(b"")
        assert decode_frame(frame) == b""

    def test_roundtrip_all_bytes(self) -> None:
        body = bytes(range(256))
        frame = encode_frame(body)
        assert decode_frame(frame) == body

    def test_bad_crc_raises(self) -> None:
        body = b"\x01\x02\x03"
        frame = encode_frame(body)
        # Corrupt a byte in the middle of the frame
        frame_list = bytearray(frame)
        frame_list[2] ^= 0xFF
        with pytest.raises(ValueError):
            decode_frame(bytes(frame_list))

    def test_missing_stx_raises(self) -> None:
        frame = encode_frame(b"\x01\x02")
        with pytest.raises(ValueError):
            decode_frame(frame[1:])  # strip STX

    def test_missing_etx_raises(self) -> None:
        frame = encode_frame(b"\x01\x02")
        with pytest.raises(ValueError):
            decode_frame(frame[:-1])  # strip ETX

    def test_frame_too_short_raises(self) -> None:
        with pytest.raises(ValueError):
            decode_frame(b"")

    def test_only_stx_etx_raises(self) -> None:
        # Frame with no CRC bytes
        with pytest.raises(ValueError):
            decode_frame(bytes([STX, ETX]))

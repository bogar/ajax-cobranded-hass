# HTS Binary Protocol Client — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a client for the Ajax HTS binary protocol to get hub network state (ethernet, wifi, gsm, power) that isn't available via gRPC, resolving issues #2, #3, #5.

**Architecture:** Six modules in `api/hts/` — protocol framing, AES crypto, message parsing, auth flow, async TCP client, and hub state parser. Pure functions for protocol layers, asyncio only in the client. Integrates with existing coordinator as a parallel data source alongside gRPC.

**Tech Stack:** Python 3.12, asyncio (ssl+streams), pycryptodome for AES-128-CBC, pytest, Docker

---

## File Map

| File | Responsibility |
|------|----------------|
| `custom_components/aegis_ajax/api/hts/__init__.py` | Package exports |
| `custom_components/aegis_ajax/api/hts/protocol.py` | Frame encode/decode: STX/ETX, escape, CRC-16, pad |
| `custom_components/aegis_ajax/api/hts/crypto.py` | AES-128-CBC encrypt/decrypt |
| `custom_components/aegis_ajax/api/hts/messages.py` | Message build/parse, TLV params |
| `custom_components/aegis_ajax/api/hts/auth.py` | Auth handshake orchestration |
| `custom_components/aegis_ajax/api/hts/client.py` | Async TCP+TLS client with ACK/ping |
| `custom_components/aegis_ajax/api/hts/hub_state.py` | Parse updates → HubNetworkState |
| `tests/unit/hts/__init__.py` | Test package |
| `tests/unit/hts/test_protocol.py` | Protocol unit tests |
| `tests/unit/hts/test_crypto.py` | Crypto unit tests |
| `tests/unit/hts/test_messages.py` | Message unit tests |
| `tests/unit/hts/test_hub_state.py` | Hub state parser tests |
| `tests/unit/hts/test_auth.py` | Auth flow tests |
| `tests/unit/hts/test_client.py` | Client tests (mocked socket) |
| `scripts/test_hts_connection.py` | E2E script against real HTS |
| `Dockerfile.dev` | Add pycryptodome dependency |
| `pyproject.toml` | Add pycryptodome dependency |
| `custom_components/aegis_ajax/coordinator.py` | Add HTS integration |
| `custom_components/aegis_ajax/binary_sensor.py` | Add ethernet/power sensors |
| `custom_components/aegis_ajax/sensor.py` | Add network sensors |

---

### Task 1: Add pycryptodome dependency

**Files:**
- Modify: `pyproject.toml`
- Modify: `Dockerfile.dev`

- [ ] **Step 1: Add pycryptodome to pyproject.toml**

In `pyproject.toml`, add `pycryptodome>=3.20` to the `dependencies` list (same section as `grpcio`, `protobuf`).

- [ ] **Step 2: Rebuild Docker image**

Run: `docker build -f Dockerfile.dev -t ajax-cobranded-dev .`
Expected: Builds successfully with pycryptodome installed.

- [ ] **Step 3: Verify import works**

Run: `docker run --rm ajax-cobranded-dev python -c "from Crypto.Cipher import AES; print('OK')"`
Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml Dockerfile.dev
git commit -m "chore: add pycryptodome dependency for HTS crypto"
```

---

### Task 2: Implement protocol.py (frame encoding/decoding)

**Files:**
- Create: `custom_components/aegis_ajax/api/hts/__init__.py`
- Create: `custom_components/aegis_ajax/api/hts/protocol.py`
- Create: `tests/unit/hts/__init__.py`
- Create: `tests/unit/hts/test_protocol.py`

- [ ] **Step 1: Write failing tests for CRC-16**

```python
"""Tests for HTS protocol framing."""
from __future__ import annotations

import pytest


class TestCrc16:
    def test_empty(self):
        from custom_components.aegis_ajax.api.hts.protocol import crc16
        assert crc16(b"") == 0xFFFF  # initial value, no data

    def test_known_value(self):
        from custom_components.aegis_ajax.api.hts.protocol import crc16
        # CRC-16/MODBUS of "123456789" is 0x4B37
        result = crc16(b"123456789")
        assert result == 0x4B37

    def test_single_byte(self):
        from custom_components.aegis_ajax.api.hts.protocol import crc16
        result = crc16(b"\x00")
        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFF
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker run --rm -v $(pwd):/app -w /app ajax-cobranded-dev pytest tests/unit/hts/test_protocol.py -v`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement CRC-16**

Create `custom_components/aegis_ajax/api/hts/__init__.py` (empty).
Create `tests/unit/hts/__init__.py` (empty).

Create `custom_components/aegis_ajax/api/hts/protocol.py`:

```python
"""HTS binary protocol framing: STX/ETX, escaping, CRC-16, padding."""
from __future__ import annotations

import os

# Frame delimiters
STX = 0x02
ETX = 0x03
ESC = 0x04
ESC_OFFSET = 0x30  # escaped = ESC + (original + 0x30)

# CRC-16/MODBUS lookup table (polynomial 0xA001)
_CRC_TABLE: list[int] = []
for _i in range(256):
    _crc = _i
    for _ in range(8):
        if _crc & 1:
            _crc = (_crc >> 1) ^ 0xA001
        else:
            _crc >>= 1
    _CRC_TABLE.append(_crc)


def crc16(data: bytes) -> int:
    """Compute CRC-16/MODBUS checksum."""
    crc = 0xFFFF
    for byte in data:
        crc = (_CRC_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)) & 0xFFFF
    return crc


def escape(data: bytes) -> bytes:
    """Escape STX/ETX/ESC bytes in frame body."""
    out = bytearray()
    for b in data:
        if b in (STX, ETX, ESC):
            out.append(ESC)
            out.append(b + ESC_OFFSET)
        else:
            out.append(b)
    return bytes(out)


def unescape(data: bytes) -> bytes:
    """Reverse escape sequences in frame body."""
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == ESC and i + 1 < len(data):
            out.append(data[i + 1] - ESC_OFFSET)
            i += 2
        else:
            out.append(data[i])
            i += 1
    return bytes(out)


def pad16(data: bytes) -> bytes:
    """Pad data to multiple of 16 bytes with random bytes >= 10."""
    remainder = len(data) % 16
    if remainder == 0:
        return data
    pad_len = 16 - remainder
    padding = bytes(max(b, 10) for b in os.urandom(pad_len))
    return data + padding


def encode_frame(encrypted_body: bytes) -> bytes:
    """Wrap encrypted body in STX + escaped(body + CRC) + ETX."""
    crc = crc16(encrypted_body)
    body_with_crc = encrypted_body + bytes([crc >> 8, crc & 0xFF])
    escaped = escape(body_with_crc)
    return bytes([STX]) + escaped + bytes([ETX])


def decode_frame(frame: bytes) -> bytes:
    """Strip STX/ETX, unescape, verify CRC, return encrypted body."""
    if len(frame) < 3 or frame[0] != STX or frame[-1] != ETX:
        raise ValueError("Invalid frame: missing STX/ETX")
    inner = unescape(frame[1:-1])
    if len(inner) < 2:
        raise ValueError("Frame too short for CRC")
    body = inner[:-2]
    crc_bytes = inner[-2:]
    expected_crc = (crc_bytes[0] << 8) | crc_bytes[1]
    actual_crc = crc16(body)
    if actual_crc != expected_crc:
        raise ValueError(f"CRC mismatch: expected 0x{expected_crc:04X}, got 0x{actual_crc:04X}")
    return body
```

- [ ] **Step 4: Run CRC tests to verify they pass**

Run: `docker run --rm -v $(pwd):/app -w /app ajax-cobranded-dev pytest tests/unit/hts/test_protocol.py::TestCrc16 -v`
Expected: 3 PASSED.

- [ ] **Step 5: Write tests for escape/unescape**

Add to `tests/unit/hts/test_protocol.py`:

```python
class TestEscape:
    def test_no_special_bytes(self):
        from custom_components.aegis_ajax.api.hts.protocol import escape, unescape
        data = b"\x01\x05\x10\xFF"
        assert escape(data) == data
        assert unescape(data) == data

    def test_stx_escaped(self):
        from custom_components.aegis_ajax.api.hts.protocol import escape, unescape
        data = b"\x02"
        escaped = escape(data)
        assert escaped == b"\x04\x32"
        assert unescape(escaped) == data

    def test_etx_escaped(self):
        from custom_components.aegis_ajax.api.hts.protocol import escape, unescape
        escaped = escape(b"\x03")
        assert escaped == b"\x04\x33"
        assert unescape(escaped) == b"\x03"

    def test_esc_escaped(self):
        from custom_components.aegis_ajax.api.hts.protocol import escape, unescape
        escaped = escape(b"\x04")
        assert escaped == b"\x04\x34"
        assert unescape(escaped) == b"\x04"

    def test_roundtrip_mixed(self):
        from custom_components.aegis_ajax.api.hts.protocol import escape, unescape
        data = b"\x01\x02\x03\x04\x05"
        assert unescape(escape(data)) == data


class TestPad16:
    def test_already_aligned(self):
        from custom_components.aegis_ajax.api.hts.protocol import pad16
        data = b"\x00" * 16
        assert pad16(data) == data
        assert len(pad16(data)) == 16

    def test_padding_added(self):
        from custom_components.aegis_ajax.api.hts.protocol import pad16
        data = b"\x00" * 10
        padded = pad16(data)
        assert len(padded) == 16
        assert padded[:10] == data
        assert all(b >= 10 for b in padded[10:])

    def test_empty(self):
        from custom_components.aegis_ajax.api.hts.protocol import pad16
        assert pad16(b"") == b""


class TestEncodeDecodeFrame:
    def test_roundtrip(self):
        from custom_components.aegis_ajax.api.hts.protocol import decode_frame, encode_frame
        body = b"\x10\x20\x30\x40\x50"
        frame = encode_frame(body)
        assert frame[0] == 0x02
        assert frame[-1] == 0x03
        decoded = decode_frame(frame)
        assert decoded == body

    def test_bad_crc_raises(self):
        from custom_components.aegis_ajax.api.hts.protocol import encode_frame, decode_frame
        frame = bytearray(encode_frame(b"\xAA\xBB"))
        # Corrupt a byte in the middle
        frame[2] ^= 0xFF
        with pytest.raises(ValueError, match="CRC mismatch"):
            decode_frame(bytes(frame))

    def test_missing_stx_raises(self):
        from custom_components.aegis_ajax.api.hts.protocol import decode_frame
        with pytest.raises(ValueError, match="missing STX"):
            decode_frame(b"\x00\x01\x03")
```

- [ ] **Step 6: Run all protocol tests**

Run: `docker run --rm -v $(pwd):/app -w /app ajax-cobranded-dev pytest tests/unit/hts/test_protocol.py -v`
Expected: All PASSED.

- [ ] **Step 7: Commit**

```bash
git add custom_components/aegis_ajax/api/hts/__init__.py \
        custom_components/aegis_ajax/api/hts/protocol.py \
        tests/unit/hts/__init__.py \
        tests/unit/hts/test_protocol.py
git commit -m "feat(hts): implement protocol framing (STX/ETX, escape, CRC-16)"
```

---

### Task 3: Implement crypto.py (AES-128-CBC)

**Files:**
- Create: `custom_components/aegis_ajax/api/hts/crypto.py`
- Create: `tests/unit/hts/test_crypto.py`

- [ ] **Step 1: Write failing tests**

```python
"""Tests for HTS AES-128-CBC encryption."""
from __future__ import annotations


class TestEncryptDecrypt:
    def test_roundtrip_single_block(self):
        from custom_components.aegis_ajax.api.hts.crypto import decrypt, encrypt
        plaintext = b"\x00" * 16
        ciphertext = encrypt(plaintext)
        assert ciphertext != plaintext
        assert len(ciphertext) == 16
        assert decrypt(ciphertext) == plaintext

    def test_roundtrip_multi_block(self):
        from custom_components.aegis_ajax.api.hts.crypto import decrypt, encrypt
        plaintext = b"A" * 32
        ciphertext = encrypt(plaintext)
        assert len(ciphertext) == 32
        assert decrypt(ciphertext) == plaintext

    def test_decrypt_known_vector(self):
        """Encrypt a known plaintext and verify decrypt returns it."""
        from custom_components.aegis_ajax.api.hts.crypto import decrypt, encrypt
        plaintext = b"HTS_TEST_DATA!!!"  # exactly 16 bytes
        ct = encrypt(plaintext)
        assert decrypt(ct) == plaintext

    def test_input_must_be_block_aligned(self):
        from custom_components.aegis_ajax.api.hts.crypto import encrypt
        import pytest
        with pytest.raises(ValueError):
            encrypt(b"short")  # not 16-byte aligned
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker run --rm -v $(pwd):/app -w /app ajax-cobranded-dev pytest tests/unit/hts/test_crypto.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement crypto.py**

```python
"""AES-128-CBC encryption for HTS protocol."""
from __future__ import annotations

from Crypto.Cipher import AES

# Hardcoded in libajax-uclw-lib.so (getK / getIV)
_KEY = b"We@zEd;80Z1@pc2Y"  # 16 bytes = AES-128
_IV = b"V:e<*tMv6qVU#WRC"   # 16 bytes


def encrypt(data: bytes) -> bytes:
    """Encrypt data with AES-128-CBC. Input must be 16-byte aligned."""
    if len(data) == 0 or len(data) % 16 != 0:
        raise ValueError(f"Data must be 16-byte aligned, got {len(data)}")
    cipher = AES.new(_KEY, AES.MODE_CBC, _IV)
    return cipher.encrypt(data)


def decrypt(data: bytes) -> bytes:
    """Decrypt AES-128-CBC data. Input must be 16-byte aligned."""
    if len(data) == 0 or len(data) % 16 != 0:
        raise ValueError(f"Data must be 16-byte aligned, got {len(data)}")
    cipher = AES.new(_KEY, AES.MODE_CBC, _IV)
    return cipher.decrypt(data)
```

- [ ] **Step 4: Run tests**

Run: `docker run --rm -v $(pwd):/app -w /app ajax-cobranded-dev pytest tests/unit/hts/test_crypto.py -v`
Expected: All PASSED.

- [ ] **Step 5: Commit**

```bash
git add custom_components/aegis_ajax/api/hts/crypto.py tests/unit/hts/test_crypto.py
git commit -m "feat(hts): implement AES-128-CBC encrypt/decrypt"
```

---

### Task 4: Implement messages.py (message builder/parser + TLV)

**Files:**
- Create: `custom_components/aegis_ajax/api/hts/messages.py`
- Create: `tests/unit/hts/test_messages.py`

- [ ] **Step 1: Write failing tests**

```python
"""Tests for HTS message builder/parser and TLV parameters."""
from __future__ import annotations

import pytest


class TestTlvParams:
    def test_encode_single_param(self):
        from custom_components.aegis_ajax.api.hts.messages import tlv_encode
        result = tlv_encode([b"\x3F"])
        assert result == b"\x05\x3F"

    def test_encode_multiple_params(self):
        from custom_components.aegis_ajax.api.hts.messages import tlv_encode
        result = tlv_encode([b"\x01", b"\x02\x03"])
        assert result == b"\x05\x01\x05\x02\x03"

    def test_encode_escapes_delimiter(self):
        from custom_components.aegis_ajax.api.hts.messages import tlv_encode
        result = tlv_encode([b"\x05"])
        assert result == b"\x05\x06\x35"

    def test_encode_escapes_escape(self):
        from custom_components.aegis_ajax.api.hts.messages import tlv_encode
        result = tlv_encode([b"\x06"])
        assert result == b"\x05\x06\x36"

    def test_decode_roundtrip(self):
        from custom_components.aegis_ajax.api.hts.messages import tlv_decode, tlv_encode
        params = [b"\x3F", b"hello", b"\x05\x06"]
        encoded = tlv_encode(params)
        decoded = tlv_decode(encoded)
        assert decoded == params

    def test_decode_empty(self):
        from custom_components.aegis_ajax.api.hts.messages import tlv_decode
        assert tlv_decode(b"") == []


class TestMessageHeader:
    def test_build_and_parse(self):
        from custom_components.aegis_ajax.api.hts.messages import (
            HtsMessage,
            MsgType,
            build_message,
            parse_message,
        )
        msg = HtsMessage(
            sender=1, receiver=2, seq_num=100,
            link=0, flags=0, msg_type=MsgType.PING, payload=b"",
        )
        raw = build_message(msg)
        assert len(raw) >= 14
        parsed = parse_message(raw)
        assert parsed.sender == 1
        assert parsed.receiver == 2
        assert parsed.seq_num == 100
        assert parsed.msg_type == MsgType.PING
        assert parsed.payload == b""

    def test_parse_with_payload(self):
        from custom_components.aegis_ajax.api.hts.messages import (
            HtsMessage,
            MsgType,
            build_message,
            parse_message,
        )
        payload = b"\x05\x3F\x05\x01\x02"
        msg = HtsMessage(
            sender=0, receiver=0, seq_num=0,
            link=0, flags=0, msg_type=MsgType.USER_REGISTRATION, payload=payload,
        )
        raw = build_message(msg)
        parsed = parse_message(raw)
        assert parsed.payload == payload
        assert parsed.msg_type == MsgType.USER_REGISTRATION

    def test_parse_too_short_raises(self):
        from custom_components.aegis_ajax.api.hts.messages import parse_message
        with pytest.raises(ValueError, match="too short"):
            parse_message(b"\x00" * 10)

    def test_seq_num_3_bytes(self):
        from custom_components.aegis_ajax.api.hts.messages import (
            HtsMessage,
            MsgType,
            build_message,
            parse_message,
        )
        msg = HtsMessage(
            sender=0, receiver=0, seq_num=0xABCDEF,
            link=0, flags=0, msg_type=MsgType.ACK, payload=b"",
        )
        raw = build_message(msg)
        parsed = parse_message(raw)
        assert parsed.seq_num == 0xABCDEF

    def test_flags_preserved(self):
        from custom_components.aegis_ajax.api.hts.messages import (
            HtsMessage,
            MsgType,
            build_message,
            parse_message,
        )
        flags = 0b00100000  # isNoAck
        msg = HtsMessage(
            sender=0, receiver=0, seq_num=0,
            link=5, flags=flags, msg_type=MsgType.PING, payload=b"",
        )
        raw = build_message(msg)
        parsed = parse_message(raw)
        assert parsed.flags == flags
        assert parsed.link == 5
        assert parsed.is_no_ack is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker run --rm -v $(pwd):/app -w /app ajax-cobranded-dev pytest tests/unit/hts/test_messages.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement messages.py**

```python
"""HTS message builder/parser and TLV parameter encoding."""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

# TLV parameter delimiters
TLV_DELIM = 0x05
TLV_ESC = 0x06
TLV_ESC_OFFSET = 0x30


class MsgType(IntEnum):
    """HTS message types."""
    READ_PARAMETER = 0x06
    WRITE_PARAMETER = 0x07
    HUB_REGISTRATION = 0x09
    PING = 0x0D
    ADM_CONTROL = 0x10
    USER_REGISTRATION = 0x11
    AUTHENTICATION = 0x15
    ACK = 0x16
    CONNECTION = 0x18
    UPDATES = 0x19
    HUB_SERVICE = 0x1D


# Auth sub-keys
AUTH_KEY_CONNECT_CLIENT_NEW = 0x3F
AUTH_KEY_AUTHENTICATION_REQUEST = 0x00
AUTH_KEY_AUTHENTICATION_RESPONSE = 0x01
AUTH_KEY_CONNECTED = 0x0F
ACK_KEY_RECEIVED = 0x00

# Flag bit positions
FLAG_NO_ACK = 0x20  # bit 5


@dataclass
class HtsMessage:
    """Parsed HTS message."""
    sender: int       # 4 bytes
    receiver: int     # 4 bytes
    seq_num: int      # 3 bytes (0–16777215)
    link: int         # 1 byte
    flags: int        # 1 byte
    msg_type: MsgType | int  # 1 byte
    payload: bytes

    @property
    def is_no_ack(self) -> bool:
        return bool(self.flags & FLAG_NO_ACK)

    @property
    def is_duplicate(self) -> bool:
        return bool(self.flags & 0x08)

    @property
    def send_try(self) -> int:
        return self.flags & 0x07


def build_message(msg: HtsMessage) -> bytes:
    """Serialize an HtsMessage to bytes."""
    out = bytearray()
    out.extend(msg.sender.to_bytes(4, "big"))
    out.extend(msg.receiver.to_bytes(4, "big"))
    out.extend(msg.seq_num.to_bytes(3, "big"))
    out.append(msg.link & 0xFF)
    out.append(msg.flags & 0xFF)
    out.append(int(msg.msg_type) & 0xFF)
    out.extend(msg.payload)
    return bytes(out)


def parse_message(data: bytes) -> HtsMessage:
    """Parse bytes into an HtsMessage."""
    if len(data) < 14:
        raise ValueError(f"Message too short: {len(data)} bytes, need >= 14")
    sender = int.from_bytes(data[0:4], "big")
    receiver = int.from_bytes(data[4:8], "big")
    seq_num = int.from_bytes(data[8:11], "big")
    link = data[11]
    flags = data[12]
    raw_type = data[13]
    try:
        msg_type = MsgType(raw_type)
    except ValueError:
        msg_type = raw_type
    payload = data[14:]
    return HtsMessage(
        sender=sender, receiver=receiver, seq_num=seq_num,
        link=link, flags=flags, msg_type=msg_type, payload=payload,
    )


def tlv_escape_param(param: bytes) -> bytes:
    """Escape TLV delimiter bytes within a parameter."""
    out = bytearray()
    for b in param:
        if b == TLV_DELIM:
            out.append(TLV_ESC)
            out.append(TLV_DELIM + TLV_ESC_OFFSET)
        elif b == TLV_ESC:
            out.append(TLV_ESC)
            out.append(TLV_ESC + TLV_ESC_OFFSET)
        else:
            out.append(b)
    return bytes(out)


def tlv_unescape_param(data: bytes) -> bytes:
    """Unescape TLV parameter bytes."""
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == TLV_ESC and i + 1 < len(data):
            out.append(data[i + 1] - TLV_ESC_OFFSET)
            i += 2
        else:
            out.append(data[i])
            i += 1
    return bytes(out)


def tlv_encode(params: list[bytes]) -> bytes:
    """Encode a list of parameters into TLV format."""
    out = bytearray()
    for param in params:
        out.append(TLV_DELIM)
        out.extend(tlv_escape_param(param))
    return bytes(out)


def tlv_decode(data: bytes) -> list[bytes]:
    """Decode TLV-formatted bytes into parameter list."""
    if not data:
        return []
    params: list[bytes] = []
    current = bytearray()
    i = 0
    while i < len(data):
        if data[i] == TLV_DELIM:
            if current:
                params.append(tlv_unescape_param(bytes(current)))
                current = bytearray()
            i += 1
        else:
            current.append(data[i])
            i += 1
    if current:
        params.append(tlv_unescape_param(bytes(current)))
    return params
```

- [ ] **Step 4: Run tests**

Run: `docker run --rm -v $(pwd):/app -w /app ajax-cobranded-dev pytest tests/unit/hts/test_messages.py -v`
Expected: All PASSED.

- [ ] **Step 5: Commit**

```bash
git add custom_components/aegis_ajax/api/hts/messages.py tests/unit/hts/test_messages.py
git commit -m "feat(hts): implement message builder/parser and TLV encoding"
```

---

### Task 5: Implement hub_state.py (hub network state parser)

**Files:**
- Create: `custom_components/aegis_ajax/api/hts/hub_state.py`
- Create: `tests/unit/hts/test_hub_state.py`

- [ ] **Step 1: Write failing tests**

```python
"""Tests for HTS hub state parser."""
from __future__ import annotations


class TestHubNetworkState:
    def test_default_values(self):
        from custom_components.aegis_ajax.api.hts.hub_state import HubNetworkState
        state = HubNetworkState()
        assert state.ethernet_connected is False
        assert state.wifi_connected is False
        assert state.gsm_connected is False
        assert state.externally_powered is False
        assert state.ethernet_ip == ""
        assert state.gsm_signal_level == "unknown"

    def test_from_active_channels_bitmask(self):
        from custom_components.aegis_ajax.api.hts.hub_state import HubNetworkState
        # bit0=eth, bit1=wifi, bit2=gsm → 0b111 = 7 = all connected
        state = HubNetworkState(
            ethernet_connected=True, wifi_connected=True, gsm_connected=True,
        )
        assert state.ethernet_connected is True
        assert state.wifi_connected is True
        assert state.gsm_connected is True

    def test_primary_connection(self):
        from custom_components.aegis_ajax.api.hts.hub_state import HubNetworkState
        eth = HubNetworkState(ethernet_connected=True, wifi_connected=True, gsm_connected=True)
        assert eth.primary_connection == "ethernet"
        wifi = HubNetworkState(wifi_connected=True, gsm_connected=True)
        assert wifi.primary_connection == "wifi"
        gsm = HubNetworkState(gsm_connected=True)
        assert gsm.primary_connection == "gsm"
        none = HubNetworkState()
        assert none.primary_connection == "none"


class TestParseHubUpdate:
    def test_parse_active_channels(self):
        from custom_components.aegis_ajax.api.hts.hub_state import parse_hub_params
        # key 72 = activeChannels, value = 0x03 (eth + wifi)
        params = {72: b"\x03"}
        state = parse_hub_params(params)
        assert state.ethernet_connected is True
        assert state.wifi_connected is True
        assert state.gsm_connected is False

    def test_parse_ethernet_ip(self):
        from custom_components.aegis_ajax.api.hts.hub_state import parse_hub_params
        import struct
        # key 35 = eth_ip, stored as 4-byte int (network byte order)
        ip_int = struct.unpack("!I", bytes([192, 168, 1, 100]))[0]
        params = {35: ip_int.to_bytes(4, "big")}
        state = parse_hub_params(params)
        assert state.ethernet_ip == "192.168.1.100"

    def test_parse_hub_powered(self):
        from custom_components.aegis_ajax.api.hts.hub_state import parse_hub_params
        # key 3 = hubPowered, value 1 = powered
        params = {3: b"\x01"}
        state = parse_hub_params(params)
        assert state.externally_powered is True

    def test_parse_gsm_signal_level(self):
        from custom_components.aegis_ajax.api.hts.hub_state import parse_hub_params
        # key 4 = gsmSignalLvl, value 2 = normal (range 0-3)
        params = {4: b"\x02"}
        state = parse_hub_params(params)
        assert state.gsm_signal_level == "normal"

    def test_parse_gsm_network_status(self):
        from custom_components.aegis_ajax.api.hts.hub_state import parse_hub_params
        # key 122 = gsmNetworkStatus, value 4 = 4G
        params = {122: b"\x04"}
        state = parse_hub_params(params)
        assert state.gsm_network_type == "4g"

    def test_parse_wifi_ssid(self):
        from custom_components.aegis_ajax.api.hts.hub_state import parse_hub_params
        # key 39 = wifi_ssid
        params = {39: b"MyNetwork"}
        state = parse_hub_params(params)
        assert state.wifi_ssid == "MyNetwork"

    def test_parse_eth_dhcp(self):
        from custom_components.aegis_ajax.api.hts.hub_state import parse_hub_params
        # key 16 = eth_dhcp, value 1 = DHCP enabled
        params = {16: b"\x01"}
        state = parse_hub_params(params)
        assert state.ethernet_dhcp is True

    def test_merge_with_existing(self):
        from custom_components.aegis_ajax.api.hts.hub_state import HubNetworkState, parse_hub_params
        # Updates are incremental — only changed fields arrive
        existing = HubNetworkState(ethernet_connected=True, ethernet_ip="10.0.0.1")
        params = {72: b"\x05"}  # eth=true, wifi=false, gsm=true
        updated = parse_hub_params(params, existing)
        assert updated.ethernet_connected is True
        assert updated.gsm_connected is True
        assert updated.ethernet_ip == "10.0.0.1"  # preserved from existing
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker run --rm -v $(pwd):/app -w /app ajax-cobranded-dev pytest tests/unit/hts/test_hub_state.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement hub_state.py**

```python
"""Parse HTS hub updates into HubNetworkState."""
from __future__ import annotations

import struct
from dataclasses import dataclass, field, replace

# TLV key constants (from AsprelisHub / C50008uF8 decompilation)
KEY_HUB_POWERED = 3
KEY_GSM_SIGNAL_LVL = 4
KEY_ETH_DHCP = 16
KEY_WIFI_LEVEL = 18
KEY_ETH_IP = 35
KEY_ETH_MASK = 36
KEY_ETH_GATE = 37
KEY_ETH_DNS = 38
KEY_WIFI_SSID = 39
KEY_WIFI_CHANNEL = 41
KEY_WIFI_IP = 42
KEY_WIFI_MASK = 43
KEY_WIFI_GATE = 44
KEY_WIFI_DNS = 45
KEY_WIFI_DHCP = 46
KEY_ACTIVE_CHANNELS = 72
KEY_ETH_ENABLED = 74
KEY_WIFI_ENABLED = 75
KEY_GPRS_ENABLED = 76
KEY_GSM_NETWORK_STATUS = 122

GSM_SIGNAL_MAP = {0: "unknown", 1: "weak", 2: "normal", 3: "strong"}
GSM_NETWORK_MAP = {0: "unknown", 1: "gsm", 2: "2g", 3: "3g", 4: "4g"}
WIFI_SIGNAL_MAP = {0: "unknown", 1: "weak", 2: "normal", 3: "strong"}


def _int_to_ip(val: bytes) -> str:
    """Convert 4-byte big-endian int to dotted IP string."""
    if len(val) < 4:
        return ""
    a, b, c, d = val[0], val[1], val[2], val[3]
    return f"{a}.{b}.{c}.{d}"


def _byte_val(val: bytes) -> int:
    """Get first byte as int, or 0."""
    return val[0] if val else 0


def _bool_val(val: bytes) -> bool:
    """Get first byte as bool."""
    return bool(_byte_val(val))


def _str_val(val: bytes) -> str:
    """Decode bytes as UTF-8 string."""
    return val.decode("utf-8", errors="ignore")


@dataclass(frozen=True)
class HubNetworkState:
    """Hub network state from HTS updates."""

    # Active channels
    ethernet_connected: bool = False
    wifi_connected: bool = False
    gsm_connected: bool = False

    # Ethernet
    ethernet_enabled: bool = False
    ethernet_ip: str = ""
    ethernet_mask: str = ""
    ethernet_gateway: str = ""
    ethernet_dns: str = ""
    ethernet_dhcp: bool = False

    # WiFi
    wifi_enabled: bool = False
    wifi_ssid: str = ""
    wifi_signal_level: str = "unknown"
    wifi_ip: str = ""

    # GSM
    gsm_signal_level: str = "unknown"
    gsm_network_type: str = "unknown"

    # Power
    externally_powered: bool = False

    @property
    def primary_connection(self) -> str:
        """Return the primary active connection type."""
        if self.ethernet_connected:
            return "ethernet"
        if self.wifi_connected:
            return "wifi"
        if self.gsm_connected:
            return "gsm"
        return "none"


def parse_hub_params(
    params: dict[int, bytes],
    existing: HubNetworkState | None = None,
) -> HubNetworkState:
    """Parse TLV key-value params into HubNetworkState.

    If existing is provided, only overwrite fields present in params.
    """
    state = existing or HubNetworkState()
    updates: dict[str, object] = {}

    for key, val in params.items():
        if key == KEY_ACTIVE_CHANNELS:
            bitmask = _byte_val(val)
            updates["ethernet_connected"] = bool(bitmask & 0x01)
            updates["wifi_connected"] = bool(bitmask & 0x02)
            updates["gsm_connected"] = bool(bitmask & 0x04)
        elif key == KEY_HUB_POWERED:
            updates["externally_powered"] = _bool_val(val)
        elif key == KEY_ETH_ENABLED:
            updates["ethernet_enabled"] = _bool_val(val)
        elif key == KEY_ETH_IP:
            updates["ethernet_ip"] = _int_to_ip(val)
        elif key == KEY_ETH_MASK:
            updates["ethernet_mask"] = _int_to_ip(val)
        elif key == KEY_ETH_GATE:
            updates["ethernet_gateway"] = _int_to_ip(val)
        elif key == KEY_ETH_DNS:
            updates["ethernet_dns"] = _int_to_ip(val)
        elif key == KEY_ETH_DHCP:
            updates["ethernet_dhcp"] = _bool_val(val)
        elif key == KEY_WIFI_ENABLED:
            updates["wifi_enabled"] = _bool_val(val)
        elif key == KEY_WIFI_SSID:
            updates["wifi_ssid"] = _str_val(val)
        elif key == KEY_WIFI_IP:
            updates["wifi_ip"] = _int_to_ip(val)
        elif key == KEY_WIFI_LEVEL:
            updates["wifi_signal_level"] = WIFI_SIGNAL_MAP.get(_byte_val(val), "unknown")
        elif key == KEY_GSM_SIGNAL_LVL:
            updates["gsm_signal_level"] = GSM_SIGNAL_MAP.get(_byte_val(val), "unknown")
        elif key == KEY_GSM_NETWORK_STATUS:
            updates["gsm_network_type"] = GSM_NETWORK_MAP.get(_byte_val(val), "unknown")

    if updates:
        return replace(state, **updates)
    return state
```

- [ ] **Step 4: Run tests**

Run: `docker run --rm -v $(pwd):/app -w /app ajax-cobranded-dev pytest tests/unit/hts/test_hub_state.py -v`
Expected: All PASSED.

- [ ] **Step 5: Commit**

```bash
git add custom_components/aegis_ajax/api/hts/hub_state.py tests/unit/hts/test_hub_state.py
git commit -m "feat(hts): implement hub network state parser with TLV key mappings"
```

---

### Task 6: Implement auth.py (authentication handshake)

**Files:**
- Create: `custom_components/aegis_ajax/api/hts/auth.py`
- Create: `tests/unit/hts/test_auth.py`

- [ ] **Step 1: Write failing tests**

```python
"""Tests for HTS authentication flow."""
from __future__ import annotations


class TestSolveChallenge:
    def test_basic(self):
        from custom_components.aegis_ajax.api.hts.auth import solve_challenge
        a, b = 0x10, 0x20
        result = solve_challenge(a, b)
        assert result == bytes([a ^ b, (b & a) << 2])

    def test_zero(self):
        from custom_components.aegis_ajax.api.hts.auth import solve_challenge
        result = solve_challenge(0, 0)
        assert result == bytes([0, 0])

    def test_all_ones(self):
        from custom_components.aegis_ajax.api.hts.auth import solve_challenge
        result = solve_challenge(0xFF, 0xFF)
        # 0xFF ^ 0xFF = 0, (0xFF & 0xFF) << 2 = 0xFF << 2 = 0x3FC, truncated to byte = 0xFC
        assert result == bytes([0x00, 0xFC])


class TestBuildConnectRequest:
    def test_contains_password_hash(self):
        from custom_components.aegis_ajax.api.hts.auth import build_connect_request
        from custom_components.aegis_ajax.api.hts.messages import tlv_decode
        payload = build_connect_request(
            password_hash="abc123", device_id="dev1", app_label="Protegim_alarma",
        )
        params = tlv_decode(payload)
        # First param is key 0x3F
        assert params[0] == bytes([0x3F])
        # Second param is the password hash
        assert params[1] == b"abc123"

    def test_contains_app_label(self):
        from custom_components.aegis_ajax.api.hts.auth import build_connect_request
        from custom_components.aegis_ajax.api.hts.messages import tlv_decode
        payload = build_connect_request(
            password_hash="x", device_id="d", app_label="MyApp",
        )
        params = tlv_decode(payload)
        # Params are key-value alternating after the initial key
        # key=0x3F, pw, key=7, device_id, key=8, app_label, ...
        # Find app_label: param after key byte 8
        found = False
        for i, p in enumerate(params):
            if p == bytes([8]) and i + 1 < len(params):
                assert params[i + 1] == b"MyApp"
                found = True
                break
        assert found, "app_label not found in params"


class TestParseConnectedResponse:
    def test_parse_hubs(self):
        from custom_components.aegis_ajax.api.hts.auth import parse_connected_response
        from custom_components.aegis_ajax.api.hts.messages import tlv_encode
        # Params: key=0x0F, token, hub_data
        # hub_data = 4-byte hub_id + 1-byte is_master
        token = b"\xAA\xBB\xCC\xDD"
        hub1_id = b"\x00\x2B\x1A\x51"
        hub1_master = b"\x01"
        payload = tlv_encode([
            bytes([0x0F]),
            token,
            hub1_id + hub1_master,
        ])
        result = parse_connected_response(payload)
        assert result.token == token
        assert len(result.hubs) == 1
        assert result.hubs[0].hub_id == "002B1A51"
        assert result.hubs[0].is_master is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker run --rm -v $(pwd):/app -w /app ajax-cobranded-dev pytest tests/unit/hts/test_auth.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement auth.py**

```python
"""HTS authentication handshake."""
from __future__ import annotations

from dataclasses import dataclass

from custom_components.aegis_ajax.api.hts.messages import (
    AUTH_KEY_CONNECT_CLIENT_NEW,
    AUTH_KEY_CONNECTED,
    tlv_decode,
    tlv_encode,
)


@dataclass(frozen=True)
class HubInfo:
    """Hub returned in CONNECTED response."""
    hub_id: str  # hex string
    is_master: bool


@dataclass(frozen=True)
class ConnectedResponse:
    """Parsed CONNECTED response."""
    token: bytes
    hubs: list[HubInfo]


def solve_challenge(a: int, b: int) -> bytes:
    """Solve the HTS auth challenge: [a^b, (b&a)<<2]."""
    return bytes([(a ^ b) & 0xFF, ((b & a) << 2) & 0xFF])


def build_connect_request(
    password_hash: str,
    device_id: str,
    app_label: str,
    client_os: str = "Android",
    client_version: str = "3.30",
    connection_type: int = 5,  # 4G
    device_model: str = "SM-A536B",
) -> bytes:
    """Build TLV payload for CONNECT_CLIENT_NEW message."""
    params: list[bytes] = [
        bytes([AUTH_KEY_CONNECT_CLIENT_NEW]),  # sub-key
        password_hash.encode("utf-8"),         # key 1: password hash
        bytes([3]),                             # key 3: push token type (FCM=3)
        b"",                                   # key 4: push token (empty)
        bytes([0]),                             # key 5: isProLoginRequest=false
        bytes([7]),                             # key 7 marker
        device_id.encode("utf-8"),             # device_id value
        bytes([8]),                             # key 8 marker
        app_label.encode("utf-8"),             # app_label value
        bytes([9]),                             # key 9 marker
        bytes([2]),                             # client_os type: Android=2
        bytes([10]),                            # key 10 marker
        client_version.encode("utf-8"),        # version
        bytes([11]),                            # key 11 marker
        bytes([connection_type]),              # connection type
        bytes([13]),                            # key 13 marker
        device_model.encode("utf-8"),          # device model
    ]
    return tlv_encode(params)


def parse_connected_response(payload: bytes) -> ConnectedResponse:
    """Parse CONNECTED response payload to extract token and hub list."""
    params = tlv_decode(payload)
    if not params or params[0] != bytes([AUTH_KEY_CONNECTED]):
        raise ValueError(f"Expected CONNECTED key 0x0F, got {params[0] if params else 'empty'}")

    token = params[1] if len(params) > 1 else b""
    hubs: list[HubInfo] = []

    for i in range(2, len(params)):
        hub_data = params[i]
        if len(hub_data) >= 5:
            hub_id = hub_data[:4].hex().upper()
            is_master = bool(hub_data[4])
            hubs.append(HubInfo(hub_id=hub_id, is_master=is_master))

    return ConnectedResponse(token=token, hubs=hubs)
```

- [ ] **Step 4: Run tests**

Run: `docker run --rm -v $(pwd):/app -w /app ajax-cobranded-dev pytest tests/unit/hts/test_auth.py -v`
Expected: All PASSED.

- [ ] **Step 5: Commit**

```bash
git add custom_components/aegis_ajax/api/hts/auth.py tests/unit/hts/test_auth.py
git commit -m "feat(hts): implement authentication handshake (challenge-response)"
```

---

### Task 7: Implement client.py (async TCP+TLS client)

**Files:**
- Create: `custom_components/aegis_ajax/api/hts/client.py`
- Create: `tests/unit/hts/test_client.py`

- [ ] **Step 1: Write failing tests**

```python
"""Tests for HTS async TCP client."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestHtsClientInit:
    def test_initial_state(self):
        from custom_components.aegis_ajax.api.hts.client import HtsClient
        client = HtsClient(
            password_hash="abc", device_id="dev1", app_label="Ajax",
        )
        assert client.is_connected is False
        assert client._seq_num == 0

    def test_next_seq_wraps(self):
        from custom_components.aegis_ajax.api.hts.client import HtsClient
        client = HtsClient(password_hash="x", device_id="d", app_label="A")
        client._seq_num = 0xFFFFFE
        seq = client._next_seq()
        assert seq == 0xFFFFFE
        seq = client._next_seq()
        assert seq == 0xFFFFFF
        seq = client._next_seq()
        assert seq == 0  # wraps


class TestHtsClientSendReceive:
    @pytest.mark.asyncio
    async def test_send_encodes_frame(self):
        from custom_components.aegis_ajax.api.hts.client import HtsClient
        from custom_components.aegis_ajax.api.hts.messages import MsgType

        client = HtsClient(password_hash="x", device_id="d", app_label="A")
        client._writer = MagicMock()
        client._writer.write = MagicMock()
        client._writer.drain = AsyncMock()
        client._connected = True

        await client._send_message(MsgType.PING, b"")

        client._writer.write.assert_called_once()
        raw = client._writer.write.call_args[0][0]
        # Frame must start with STX and end with ETX
        assert raw[0] == 0x02
        assert raw[-1] == 0x03
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `docker run --rm -v $(pwd):/app -w /app ajax-cobranded-dev pytest tests/unit/hts/test_client.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement client.py**

```python
"""Async TCP+TLS client for the HTS binary protocol."""
from __future__ import annotations

import asyncio
import logging
import ssl
from typing import Any, Callable

from custom_components.aegis_ajax.api.hts.auth import (
    ConnectedResponse,
    build_connect_request,
    parse_connected_response,
    solve_challenge,
)
from custom_components.aegis_ajax.api.hts.crypto import decrypt, encrypt
from custom_components.aegis_ajax.api.hts.hub_state import HubNetworkState, parse_hub_params
from custom_components.aegis_ajax.api.hts.messages import (
    ACK_KEY_RECEIVED,
    AUTH_KEY_AUTHENTICATION_REQUEST,
    AUTH_KEY_AUTHENTICATION_RESPONSE,
    AUTH_KEY_CONNECTED,
    FLAG_NO_ACK,
    HtsMessage,
    MsgType,
    build_message,
    parse_message,
    tlv_decode,
    tlv_encode,
)
from custom_components.aegis_ajax.api.hts.protocol import (
    ETX,
    STX,
    decode_frame,
    encode_frame,
    pad16,
)

_LOGGER = logging.getLogger(__name__)

HTS_HOST = "hts.prod.ajax.systems"
HTS_PORT = 443
HTS_PORT_FALLBACK = 4343
PING_INTERVAL = 30  # seconds
READ_TIMEOUT = 40  # seconds
RECONNECT_BASE_DELAY = 2.0
RECONNECT_MAX_DELAY = 60.0


class HtsConnectionError(Exception):
    """HTS connection failed."""


class HtsAuthError(Exception):
    """HTS authentication failed."""


class HtsClient:
    """Async client for the Ajax HTS binary protocol."""

    def __init__(
        self,
        password_hash: str,
        device_id: str,
        app_label: str,
        host: str = HTS_HOST,
        port: int = HTS_PORT,
    ) -> None:
        self._password_hash = password_hash
        self._device_id = device_id
        self._app_label = app_label
        self._host = host
        self._port = port
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._connected = False
        self._seq_num = 0
        self._sender_id = 0
        self._receiver_id = 0
        self._connection_token: bytes = b""
        self._hubs: list[Any] = []
        self._ping_task: asyncio.Task[None] | None = None
        self._hub_states: dict[str, HubNetworkState] = {}
        self._on_state_update: Callable[[str, HubNetworkState], None] | None = None

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def hub_states(self) -> dict[str, HubNetworkState]:
        return dict(self._hub_states)

    def _next_seq(self) -> int:
        """Get next sequence number (3 bytes, wraps at 0xFFFFFF)."""
        seq = self._seq_num
        self._seq_num = (self._seq_num + 1) & 0xFFFFFF
        return seq

    async def connect(self) -> ConnectedResponse:
        """Connect to HTS, authenticate, and return hub list."""
        ctx = ssl.create_default_context()
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self._host, self._port, ssl=ctx),
                timeout=10,
            )
        except Exception as e:
            raise HtsConnectionError(f"TCP connect failed: {e}") from e

        self._connected = True
        _LOGGER.debug("Connected to %s:%d", self._host, self._port)

        try:
            return await self._authenticate()
        except Exception:
            await self.close()
            raise

    async def _authenticate(self) -> ConnectedResponse:
        """Run the 3-step auth handshake."""
        # Step 1: Send CONNECT_CLIENT_NEW
        payload = build_connect_request(
            password_hash=self._password_hash,
            device_id=self._device_id,
            app_label=self._app_label,
        )
        await self._send_message(MsgType.USER_REGISTRATION, payload)
        _LOGGER.debug("Sent CONNECT_CLIENT_NEW")

        # Step 2: Receive AUTHENTICATION_REQUEST
        msg = await self._receive_message()
        if msg.msg_type != MsgType.AUTHENTICATION:
            raise HtsAuthError(f"Expected AUTHENTICATION, got {msg.msg_type}")
        params = tlv_decode(msg.payload)
        if not params or params[0] != bytes([AUTH_KEY_AUTHENTICATION_REQUEST]):
            raise HtsAuthError("Expected AUTHENTICATION_REQUEST key")
        if len(params) < 2 or len(params[1]) < 2:
            raise HtsAuthError("Challenge too short")
        challenge = params[1]
        _LOGGER.debug("Received auth challenge")

        # Step 3: Send AUTHENTICATION_RESPONSE
        solution = solve_challenge(challenge[0], challenge[1])
        resp_payload = tlv_encode([
            bytes([AUTH_KEY_AUTHENTICATION_RESPONSE]),
            solution,
        ])
        await self._send_message(MsgType.AUTHENTICATION, resp_payload)
        _LOGGER.debug("Sent auth response")

        # Step 4: Receive CONNECTED
        msg = await self._receive_message()
        if msg.msg_type != MsgType.USER_REGISTRATION:
            raise HtsAuthError(f"Expected USER_REGISTRATION (CONNECTED), got {msg.msg_type}")
        result = parse_connected_response(msg.payload)
        self._connection_token = result.token
        self._hubs = result.hubs
        _LOGGER.info(
            "HTS authenticated, %d hub(s): %s",
            len(result.hubs),
            [h.hub_id for h in result.hubs],
        )
        return result

    async def _send_message(self, msg_type: MsgType, payload: bytes) -> None:
        """Build, encrypt, frame, and send a message."""
        if not self._writer:
            raise HtsConnectionError("Not connected")
        msg = HtsMessage(
            sender=self._sender_id,
            receiver=self._receiver_id,
            seq_num=self._next_seq(),
            link=0,
            flags=0,
            msg_type=msg_type,
            payload=payload,
        )
        raw = build_message(msg)
        padded = pad16(raw)
        encrypted = encrypt(padded)
        frame = encode_frame(encrypted)
        self._writer.write(frame)
        await self._writer.drain()

    async def _send_ack(self, original: HtsMessage) -> None:
        """Send ACK for a received message."""
        seq_bytes = original.seq_num.to_bytes(3, "big")
        payload = tlv_encode([bytes([ACK_KEY_RECEIVED]), seq_bytes])
        msg = HtsMessage(
            sender=self._sender_id,
            receiver=self._receiver_id,
            seq_num=self._next_seq(),
            link=original.link,
            flags=FLAG_NO_ACK,
            msg_type=MsgType.ACK,
            payload=payload,
        )
        raw = build_message(msg)
        padded = pad16(raw)
        encrypted = encrypt(padded)
        frame = encode_frame(encrypted)
        if self._writer:
            self._writer.write(frame)
            await self._writer.drain()

    async def _receive_message(self) -> HtsMessage:
        """Read one frame from the socket, decrypt, and parse."""
        if not self._reader:
            raise HtsConnectionError("Not connected")
        frame = await self._read_frame()
        encrypted_body = decode_frame(frame)
        decrypted = decrypt(encrypted_body)
        return parse_message(decrypted)

    async def _read_frame(self) -> bytes:
        """Read bytes until ETX, collecting a complete frame."""
        if not self._reader:
            raise HtsConnectionError("Not connected")
        buf = bytearray()
        found_stx = False
        while True:
            byte = await asyncio.wait_for(self._reader.read(1), timeout=READ_TIMEOUT)
            if not byte:
                raise HtsConnectionError("Connection closed by server")
            b = byte[0]
            if b == STX:
                buf = bytearray([STX])
                found_stx = True
            elif found_stx:
                buf.append(b)
                if b == ETX:
                    return bytes(buf)

    async def listen(
        self,
        on_state_update: Callable[[str, HubNetworkState], None] | None = None,
    ) -> None:
        """Main receive loop: dispatch updates, send ACKs and pings."""
        self._on_state_update = on_state_update
        self._ping_task = asyncio.create_task(self._ping_loop())
        try:
            while self._connected:
                try:
                    msg = await self._receive_message()
                except asyncio.TimeoutError:
                    _LOGGER.warning("HTS read timeout, closing")
                    break
                except HtsConnectionError:
                    _LOGGER.warning("HTS connection lost")
                    break

                # ACK if needed
                if not msg.is_no_ack and msg.msg_type != MsgType.ACK:
                    await self._send_ack(msg)

                # Dispatch
                if msg.msg_type == MsgType.UPDATES:
                    self._handle_update(msg)
                elif msg.msg_type == MsgType.PING:
                    pass  # ACK already sent
                elif msg.msg_type == MsgType.ACK:
                    pass  # TODO: track pending ACKs in future
                else:
                    _LOGGER.debug("Unhandled msg type: 0x%02X", int(msg.msg_type))
        finally:
            if self._ping_task:
                self._ping_task.cancel()

    def _handle_update(self, msg: HtsMessage) -> None:
        """Parse an UPDATE message and update hub state."""
        params = tlv_decode(msg.payload)
        if not params:
            return

        # Extract key-value pairs from TLV params
        # First param is the update sub-key, rest are key-value alternating
        kv: dict[int, bytes] = {}
        i = 1  # skip sub-key
        while i + 1 < len(params):
            key_param = params[i]
            val_param = params[i + 1]
            if len(key_param) == 1:
                kv[key_param[0]] = val_param
            i += 2

        if not kv:
            _LOGGER.debug("UPDATE with no parseable key-value params (raw: %d params)", len(params))
            return

        # For now, apply to first hub (single-hub support)
        hub_id = self._hubs[0].hub_id if self._hubs else "unknown"
        existing = self._hub_states.get(hub_id)
        new_state = parse_hub_params(kv, existing)
        self._hub_states[hub_id] = new_state
        _LOGGER.debug("Hub %s state updated: %s", hub_id, new_state)

        if self._on_state_update:
            self._on_state_update(hub_id, new_state)

    async def _ping_loop(self) -> None:
        """Send PING every PING_INTERVAL seconds."""
        while self._connected:
            await asyncio.sleep(PING_INTERVAL)
            if self._connected and self._writer:
                try:
                    await self._send_message(MsgType.PING, b"")
                except Exception:
                    _LOGGER.debug("Failed to send ping")
                    break

    async def close(self) -> None:
        """Close the connection."""
        self._connected = False
        if self._ping_task:
            self._ping_task.cancel()
            self._ping_task = None
        if self._writer:
            self._writer.close()
            with contextlib.suppress(Exception):
                await self._writer.wait_closed()
            self._writer = None
        self._reader = None
        _LOGGER.debug("HTS connection closed")
```

Note: add `import contextlib` at the top of the file.

- [ ] **Step 4: Run tests**

Run: `docker run --rm -v $(pwd):/app -w /app ajax-cobranded-dev pytest tests/unit/hts/test_client.py -v`
Expected: All PASSED.

- [ ] **Step 5: Commit**

```bash
git add custom_components/aegis_ajax/api/hts/client.py tests/unit/hts/test_client.py
git commit -m "feat(hts): implement async TCP+TLS client with ACK and ping"
```

---

### Task 8: E2E test script

**Files:**
- Create: `scripts/test_hts_connection.py`

- [ ] **Step 1: Create the E2E script**

```python
#!/usr/bin/env python3
"""E2E test: connect to real HTS server and log hub updates.

READ-ONLY: Does NOT modify any settings or alarm state.

Usage:
    docker run --rm -v $(pwd):/app -w /app \
      -e AJAX_EMAIL=your@email.com \
      -e AJAX_PASSWORD=yourpass \
      ajax-cobranded-dev python scripts/test_hts_connection.py
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from custom_components.aegis_ajax.api.hts.client import HtsClient
from custom_components.aegis_ajax.api.hts.hub_state import HubNetworkState

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(name)s %(levelname)s %(message)s")


def on_update(hub_id: str, state: HubNetworkState) -> None:
    print(f"\n{'='*60}")
    print(f"Hub {hub_id} state update:")
    print(f"  Ethernet: connected={state.ethernet_connected}, enabled={state.ethernet_enabled}")
    print(f"    IP={state.ethernet_ip}, mask={state.ethernet_mask}, gw={state.ethernet_gateway}")
    print(f"    DNS={state.ethernet_dns}, DHCP={state.ethernet_dhcp}")
    print(f"  WiFi: connected={state.wifi_connected}, enabled={state.wifi_enabled}")
    print(f"    SSID={state.wifi_ssid}, signal={state.wifi_signal_level}, IP={state.wifi_ip}")
    print(f"  GSM: connected={state.gsm_connected}")
    print(f"    signal={state.gsm_signal_level}, network={state.gsm_network_type}")
    print(f"  Power: externally_powered={state.externally_powered}")
    print(f"  Primary connection: {state.primary_connection}")
    print(f"{'='*60}\n")


async def main() -> None:
    email = os.environ.get("AJAX_EMAIL")
    password = os.environ.get("AJAX_PASSWORD")
    if not email or not password:
        print("Error: Set AJAX_EMAIL and AJAX_PASSWORD environment variables.")
        sys.exit(1)

    password_hash = hashlib.sha256(password.encode()).hexdigest()
    device_id = str(uuid.uuid4())
    app_label = os.environ.get("AJAX_APP_LABEL", "Protegim_alarma")

    print(f"Connecting to HTS as {email} (app: {app_label})...")

    client = HtsClient(
        password_hash=password_hash,
        device_id=device_id,
        app_label=app_label,
    )

    try:
        result = await client.connect()
        print(f"Authenticated! Token: {result.token.hex()[:16]}...")
        print(f"Hubs: {[(h.hub_id, h.is_master) for h in result.hubs]}")
        print("\nListening for updates (Ctrl+C to stop)...\n")
        await client.listen(on_state_update=on_update)
    except KeyboardInterrupt:
        print("\nStopped by user.")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await client.close()
        print("Disconnected.")


if __name__ == "__main__":
    asyncio.run(main())
```

- [ ] **Step 2: Run against real server (manual verification)**

Run:
```bash
docker run --rm -v $(pwd):/app -w /app \
  -e AJAX_EMAIL='basilio.vera+ha@gmail.com' \
  -e AJAX_PASSWORD='0!R@Eso&LDJ9Wxs#' \
  ajax-cobranded-dev python scripts/test_hts_connection.py
```

Expected: Connects, authenticates, shows hub list, receives at least one update with network data. If TLV key mappings are wrong, the debug logs will show raw bytes for manual verification.

**This is the critical validation step.** If it fails, we need to adjust the TLV parsing or auth flow based on the error output before proceeding.

- [ ] **Step 3: Commit**

```bash
git add scripts/test_hts_connection.py
git commit -m "feat(hts): add E2E test script for real HTS connection"
```

---

### Task 9: Integrate HTS client into coordinator

**Files:**
- Modify: `custom_components/aegis_ajax/coordinator.py`
- Modify: `custom_components/aegis_ajax/const.py`

**Important:** Only proceed with this task after Task 8's E2E test succeeds and confirms the data flow works.

- [ ] **Step 1: Add HTS constants to const.py**

Add to `custom_components/aegis_ajax/const.py`:

```python
# HTS (Hub-To-Server) protocol
HTS_HOST = "hts.prod.ajax.systems"
HTS_PORT = 443
HTS_RECONNECT_BASE_DELAY = 2.0
HTS_RECONNECT_MAX_DELAY = 60.0
```

- [ ] **Step 2: Add HTS client to coordinator**

In `custom_components/aegis_ajax/coordinator.py`, add imports and modify `__init__` and `_async_update_data` to start the HTS client alongside gRPC:

Add to imports:
```python
from custom_components.aegis_ajax.api.hts.client import HtsClient, HtsConnectionError
from custom_components.aegis_ajax.api.hts.hub_state import HubNetworkState
```

Add to `__init__`:
```python
self._hts_client: HtsClient | None = None
self._hts_task: asyncio.Task[None] | None = None
self._hts_reconnect_delay = HTS_RECONNECT_BASE_DELAY
self.hub_network: dict[str, HubNetworkState] = {}
```

Add method `_start_hts`:
```python
async def _start_hts(self) -> None:
    """Start HTS connection for hub network data."""
    if self._hts_client and self._hts_client.is_connected:
        return
    try:
        password_hash = self._client.session.get_login_params()["password_sha256_hash"]
        device_id = self._client.session._device_id
        app_label = self._client.session._app_label
        self._hts_client = HtsClient(
            password_hash=password_hash,
            device_id=device_id,
            app_label=app_label,
        )
        await self._hts_client.connect()
        self._hts_reconnect_delay = HTS_RECONNECT_BASE_DELAY
        self._hts_task = asyncio.create_task(
            self._hts_client.listen(on_state_update=self._on_hts_update)
        )
        _LOGGER.info("HTS connection established")
    except (HtsConnectionError, Exception) as e:
        _LOGGER.warning("HTS connection failed: %s (will retry)", e)
        self._hts_client = None
```

Add callback:
```python
def _on_hts_update(self, hub_id: str, state: HubNetworkState) -> None:
    """Handle HTS hub state update."""
    self.hub_network[hub_id] = state
    self.async_set_updated_data(self.data)
```

Call `_start_hts` at the end of `_async_update_data` (after the gRPC polling):
```python
# Start HTS for network data (non-blocking, graceful degradation)
if not self._hts_task or self._hts_task.done():
    asyncio.create_task(self._start_hts())
```

Add cleanup in the coordinator's shutdown:
```python
if self._hts_client:
    await self._hts_client.close()
```

- [ ] **Step 3: Run existing tests to verify no regressions**

Run: `docker run --rm -v $(pwd):/app -w /app ajax-cobranded-dev make test`
Expected: All existing tests PASS.

- [ ] **Step 4: Commit**

```bash
git add custom_components/aegis_ajax/coordinator.py custom_components/aegis_ajax/const.py
git commit -m "feat(hts): integrate HTS client into coordinator for hub network data"
```

---

### Task 10: Add network sensor and binary_sensor entities

**Files:**
- Modify: `custom_components/aegis_ajax/binary_sensor.py`
- Modify: `custom_components/aegis_ajax/sensor.py`

- [ ] **Step 1: Add binary sensors for ethernet and power**

In `binary_sensor.py`, add new entity classes for hub-level binary sensors sourced from `coordinator.hub_network`:

- `AjaxHubEthernetConnectedSensor` — `binary_sensor.<hub>_ethernet_connected`, device_class=CONNECTIVITY
- `AjaxHubExternallyPoweredSensor` — `binary_sensor.<hub>_externally_powered`, device_class=POWER

Each reads from `self.coordinator.hub_network.get(hub_id)` and returns `None` (unavailable) if HTS data isn't present yet. Follow the existing pattern in `binary_sensor.py` for device_info, unique_id, etc.

- [ ] **Step 2: Add network sensors**

In `sensor.py`, add:

- `AjaxHubActiveConnectionSensor` — `sensor.<hub>_active_connection`, values: "ethernet"/"wifi"/"gsm"/"none"
- `AjaxHubGsmSignalSensor` — `sensor.<hub>_gsm_signal`, values: "unknown"/"weak"/"normal"/"strong"
- `AjaxHubWifiSignalSensor` — `sensor.<hub>_wifi_signal`, values: "unknown"/"weak"/"normal"/"strong"
- `AjaxHubEthernetIpSensor` — `sensor.<hub>_ethernet_ip`, diagnostic entity, extra_state_attributes: mask, gateway, dns, dhcp

Each reads from `self.coordinator.hub_network.get(hub_id)` and returns `None` if HTS data unavailable.

- [ ] **Step 3: Register entities in async_setup_entry**

In both `binary_sensor.py` and `sensor.py`, modify the `async_setup_entry` to create the new entities for each space/hub.

- [ ] **Step 4: Add translations**

In `strings.json` and `translations/`, add translation keys for the new entities.

- [ ] **Step 5: Run full checks**

Run: `docker run --rm -v $(pwd):/app -w /app ajax-cobranded-dev make check`
Expected: All PASS (lint, format, typecheck, tests).

- [ ] **Step 6: Commit**

```bash
git add custom_components/aegis_ajax/binary_sensor.py \
        custom_components/aegis_ajax/sensor.py \
        custom_components/aegis_ajax/strings.json
git commit -m "feat: add ethernet, wifi, gsm, and power sensors from HTS data"
```

---

### Task 11: Clean up test script and run full validation

**Files:**
- Remove: `scripts/test_ethernet_probe.py` (no longer needed)

- [ ] **Step 1: Delete the probe script**

```bash
rm scripts/test_ethernet_probe.py
```

- [ ] **Step 2: Run full check suite**

Run: `docker run --rm -v $(pwd):/app -w /app ajax-cobranded-dev make check`
Expected: All PASS.

- [ ] **Step 3: Run E2E HTS test**

```bash
docker run --rm -v $(pwd):/app -w /app \
  -e AJAX_EMAIL='basilio.vera+ha@gmail.com' \
  -e AJAX_PASSWORD='0!R@Eso&LDJ9Wxs#' \
  ajax-cobranded-dev python scripts/test_hts_connection.py
```

Expected: Connects, receives network data, displays hub state.

- [ ] **Step 4: Commit cleanup**

```bash
git add -A
git commit -m "chore: remove probe script, finalize HTS implementation"
```

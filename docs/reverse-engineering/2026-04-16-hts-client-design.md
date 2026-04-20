# HTS Binary Protocol Client — Design Spec

**Date:** 2026-04-16
**Resolves:** Issues #2 (power supply), #3 (ethernet status), #5 (GSM signal)
**Scope:** Incremental — minimal viable client with clean architecture for extension

## Background

The Ajax mobile app gets hub network data (ethernet, wifi, gsm, power) via a proprietary binary protocol called HTS (Hub-To-Server), not via the gRPC mobile gateway. This was confirmed by:

1. Full APK decompilation (jadx, 45k classes)
2. Tracing all data flows for ethernet/wifi/gsm fields
3. Live testing of all gRPC endpoints (none return network data)
4. Extraction of crypto keys from native `.so` library

The gRPC gateway only provides: security state, device list, SIM info, battery, monitoring status. All network-level hub data (ethernet IP, wifi signal, gsm status, active channels, power supply) is exclusive to HTS.

## Architecture

### Module Structure

```
api/hts/
  __init__.py
  protocol.py      # Frame encoding/decoding: STX/ETX, escaping, CRC-16, padding
  crypto.py        # AES-128-CBC encrypt/decrypt with hardcoded key/IV
  messages.py      # Z91 message builder/parser, TLV parameter encoding
  auth.py          # Login flow: CONNECT_CLIENT_NEW → challenge → response
  client.py        # HtsClient: async TCP+TLS, send/receive loop, ACK, ping
  hub_state.py     # Parse hub updates → HubNetworkState dataclass
```

### Design Principles

- `protocol.py`, `crypto.py`, `messages.py` are **pure functions** — no I/O, fully unit-testable
- `client.py` is the **only module with asyncio/sockets**
- `hub_state.py` is the **only module with hub domain knowledge**
- `auth.py` orchestrates the login handshake using primitives from the other modules

### Data Flow

```
TCP+TLS socket
  → protocol.decode_frame()     # unescape, verify CRC, strip STX/ETX
  → crypto.decrypt()            # AES-128-CBC
  → messages.parse()            # extract header + TLV params
  → hub_state.parse_update()    # interpret params → HubNetworkState
  → coordinator                 # update entities
```

## Protocol Details

### Transport

- TCP + TLS to `hts.prod.ajax.systems:443` (fallback `:4343`)
- Standard TLS (no pinning)

### Frame Format

```
STX (0x02) + escaped_body + ETX (0x03)
```

Body before escaping: `encrypt(pad16(message_bytes)) + crc16`

**Escape sequences** (applied after encryption, before framing):
| Raw | Escaped |
|-----|---------|
| 0x02 | 0x04 0x32 |
| 0x03 | 0x04 0x33 |
| 0x04 | 0x04 0x34 |

**CRC-16**: Polynomial 0xA001 (CRC-16/MODBUS variant), appended big-endian.

**Padding**: Message bytes padded to multiple of 16 before encryption. Pad bytes are random values ≥ 10.

### Encryption

- Algorithm: AES-128-CBC
- Key: `We@zEd;80Z1@pc2Y` (16 bytes, hardcoded in `libajax-uclw-lib.so`)
- IV: `V:e<*tMv6qVU#WRC` (16 bytes, hardcoded in `libajax-uclw-lib.so`)
- Static IV (reused per message — this is the app's actual behavior)

### Message Format

After decryption and unpadding, minimum 14 bytes:

| Offset | Size | Field |
|--------|------|-------|
| 0-3 | 4 bytes | sender (client/server ID) |
| 4-7 | 4 bytes | receiver (destination ID) |
| 8-10 | 3 bytes | sequence number (0–16777215) |
| 11 | 1 byte | link (session/script ID) |
| 12 | 1 byte | flags: bit3=isDuplicate, bit4=isRetain, bit5=isNoAck, bits0-2=sendTry |
| 13 | 1 byte | msgType |
| 14+ | variable | TLV payload |

### TLV Parameter Format

Parameters delimited by `0x05`:
```
0x05 <param1_bytes> 0x05 <param2_bytes> 0x05 ...
```

Escape within params: `0x05` → `0x06 0x35`, `0x06` → `0x06 0x36`.

First parameter is typically the message sub-key. Key-value pairs use alternating params: `key_byte, value_bytes, key_byte, value_bytes, ...`

### Authentication Flow

1. **Client → CONNECT_CLIENT_NEW** (msgType=0x11, key=0x3F)
   - Params: password_hash, push_token_type, push_token, device_id, app_label, client_os, client_version, connection_type, device_model

2. **Server → AUTHENTICATION_REQUEST** (msgType=0x15, key=0x00)
   - Payload: 2 bytes `[a, b]`

3. **Client → AUTHENTICATION_RESPONSE** (msgType=0x15, key=0x01)
   - Payload: `[a ^ b, (b & a) << 2]`

4. **Server → CONNECTED** (msgType=0x11, key=0x0F)
   - Payload: connection_token + pairs of (4-byte hub_id, 1-byte is_master)

### Post-Auth Protocol

- **ACK**: msgType=0x16, key=0x00. Sent for every received message unless `isNoAck` flag is set. ACK payload contains the original message's 3-byte sequence number.
- **Ping**: msgType=0x0D, empty payload. Sent every 30s if no writes.
- **Read timeout**: Close connection if no data received for 40s.
- **Resend**: Unacknowledged messages retried every 2s, up to 4 times, then close.

### Message Types

| Byte | Name | Implemented |
|------|------|-------------|
| 0x0D | PING | Yes |
| 0x11 | USER_REGISTRATION | Yes (auth only) |
| 0x15 | AUTHENTICATION | Yes |
| 0x16 | ANSWER/ACK | Yes |
| 0x19 | UPDATES | Yes (receive only) |
| 0x06 | READ_PARAMETER | No (future) |
| 0x07 | WRITE_PARAMETER | No (future) |
| 0x09 | HUB_REGISTRATION | No |
| 0x10 | ADM_CONTROL | No |
| 0x18 | CONNECTION | No |

## Data Model

### HubNetworkState

```python
@dataclass(frozen=True)
class HubNetworkState:
    # Active channels (bitmask byte, TLV key 72)
    ethernet_connected: bool
    wifi_connected: bool
    gsm_connected: bool

    # Ethernet (TLV keys from AsprelisHub)
    ethernet_enabled: bool
    ethernet_ip: str
    ethernet_mask: str
    ethernet_gateway: str
    ethernet_dns: str
    ethernet_dhcp: bool

    # WiFi
    wifi_enabled: bool
    wifi_ssid: str
    wifi_signal_level: str  # "no_signal", "weak", "normal", "strong"
    wifi_ip: str

    # GSM
    gsm_signal_level: str  # "no_signal", "weak", "normal", "strong"
    gsm_network_type: str  # "gsm", "2g", "3g", "4g"

    # Power
    externally_powered: bool
```

### TLV Key Mapping (from AsprelisHub decompilation)

The exact TLV key numbers need to be verified with live traffic (debug mode). Known mappings from the `C50008uF8` class:

- Key 72: `activeChannels` bitmask (bit0=eth, bit1=wifi, bit2=gsm)
- Ethernet: `eth_enabled`, `eth_ip`, `eth_mask`, `eth_gate`, `eth_dns`, `eth_dhcp`
- WiFi: `wifi_enabled`, `wifi_ssid`, `wifi_ip`, `wifi_channel`, `wifi_signal_level`
- GSM: `gsm_signal_level`, `gsm_network_status`, `gsm_connected`
- Power: `externally_powered`

## Coordinator Integration

```python
class AjaxCobrandedCoordinator:
    def __init__(self, ...):
        ...
        self._hts_client: HtsClient | None = None
        self.hub_network: dict[str, HubNetworkState] = {}
```

- HtsClient created on first `_async_update_data()`, runs as long-lived connection
- Updates `self.hub_network[hub_id]` and calls `async_set_updated_data()` on change
- Reconnects with exponential backoff on connection loss
- **Graceful degradation**: if HTS fails, network sensors become `unavailable`, rest of integration works normally via gRPC

## New Entities

| Entity | Type | Source field | Issue |
|--------|------|-------------|-------|
| `binary_sensor.<hub>_ethernet_connected` | BinarySensor | `ethernet_connected` | #3 |
| `binary_sensor.<hub>_externally_powered` | BinarySensor | `externally_powered` | #2 |
| `sensor.<hub>_active_connection` | Sensor | primary from active_channels | #3 |
| `sensor.<hub>_gsm_signal` | Sensor | `gsm_signal_level` | #5 |
| `sensor.<hub>_wifi_signal` | Sensor | `wifi_signal_level` | — |
| `sensor.<hub>_ethernet_ip` | Sensor (diagnostic) | `ethernet_ip` | #3 |

Extra details (wifi_ssid, mask, gateway, dns) exposed as entity attributes, not separate entities.

## Testing Strategy

- **Unit tests**: Each pure module (protocol, crypto, messages, hub_state) tested with byte fixtures
- **E2E script**: `scripts/test_hts_connection.py` — connects to real HTS, logs raw updates
- **Debug mode**: Initial implementation logs raw TLV bytes to verify key mappings
- **All in Docker**: No local dependencies

## Risks

1. **Hardcoded crypto keys**: If Ajax rotates keys in an app update, breaks until we extract new ones. Keys isolated in `crypto.py` for easy update.
2. **Protocol changes**: Proprietary protocol could change. Modular design limits blast radius.
3. **Client detection**: Ajax could fingerprint/block non-official clients. We send identical headers.
4. **TLV key mapping uncertainty**: Exact parameter keys need live verification. Debug mode addresses this.

## Out of Scope (future extensions)

- READ_PARAMETER / WRITE_PARAMETER commands
- Hub configuration changes via HTS
- Multiple simultaneous hub connections
- SVEP local protocol

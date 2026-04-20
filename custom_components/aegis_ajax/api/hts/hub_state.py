"""Hub network state parser for the Ajax HTS binary protocol."""

from __future__ import annotations

import dataclasses

# ---------------------------------------------------------------------------
# TLV key constants
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Signal / network maps
# ---------------------------------------------------------------------------

GSM_SIGNAL_MAP: dict[int, str] = {0: "unknown", 1: "weak", 2: "normal", 3: "strong"}
GSM_NETWORK_MAP: dict[int, str] = {
    0: "unknown",
    1: "gsm",
    2: "2g",
    3: "3g",
    4: "4g",
}
WIFI_SIGNAL_MAP: dict[int, str] = {0: "unknown", 1: "weak", 2: "normal", 3: "strong"}

# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

_ACTIVE_CHANNELS_ETH_BIT = 0  # bit 0
_ACTIVE_CHANNELS_WIFI_BIT = 1  # bit 1
_ACTIVE_CHANNELS_GSM_BIT = 2  # bit 2


@dataclasses.dataclass(frozen=True)
class HubNetworkState:
    """Immutable snapshot of hub network connectivity."""

    # Active connection flags (derived from KEY_ACTIVE_CHANNELS bitmask)
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

    # Wi-Fi
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
        """Return the highest-priority active connection type."""
        if self.ethernet_connected:
            return "ethernet"
        if self.wifi_connected:
            return "wifi"
        if self.gsm_connected:
            return "gsm"
        return "none"


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _int_to_ip(val: int) -> str:
    """Convert a 32-bit big-endian integer to a dotted IPv4 string."""
    return f"{(val >> 24) & 0xFF}.{(val >> 16) & 0xFF}.{(val >> 8) & 0xFF}.{val & 0xFF}"


def _byte_val(val: bytes) -> int:
    """Return the integer value of the first byte in *val*."""
    return val[0] if val else 0


def _bool_val(val: bytes) -> bool:
    """Return True if the first byte is non-zero."""
    return bool(_byte_val(val))


def _str_val(val: bytes) -> str:
    """Decode bytes as a null-terminated UTF-8 string."""
    null_pos = val.find(b"\x00")
    if null_pos >= 0:
        val = val[:null_pos]
    return val.decode("utf-8", errors="replace")


def _ip_val(val: bytes) -> str:
    """Parse a 4-byte big-endian value as a dotted IPv4 string."""
    if len(val) < 4:
        return ""
    ip_int = int.from_bytes(val[:4], "big")
    return _int_to_ip(ip_int)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def parse_hub_params(
    params: dict[int, bytes],
    existing: HubNetworkState | None = None,
) -> HubNetworkState:
    """Parse a TLV key-value dict into a HubNetworkState.

    If *existing* is provided only fields whose keys are present in *params*
    are updated; all other fields retain their values from *existing*.  This
    supports incremental (delta) updates sent by the hub.

    Args:
        params: Mapping of TLV key → raw bytes value.
        existing: Optional prior state to merge into.

    Returns:
        A new frozen HubNetworkState instance.
    """
    base = existing if existing is not None else HubNetworkState()

    updates: dict[str, object] = {}

    # Active channels bitmask ------------------------------------------------
    if KEY_ACTIVE_CHANNELS in params:
        mask = _byte_val(params[KEY_ACTIVE_CHANNELS])
        updates["ethernet_connected"] = bool(mask & (1 << _ACTIVE_CHANNELS_ETH_BIT))
        updates["wifi_connected"] = bool(mask & (1 << _ACTIVE_CHANNELS_WIFI_BIT))
        updates["gsm_connected"] = bool(mask & (1 << _ACTIVE_CHANNELS_GSM_BIT))

    # Power ------------------------------------------------------------------
    if KEY_HUB_POWERED in params:
        updates["externally_powered"] = _bool_val(params[KEY_HUB_POWERED])

    # Ethernet ---------------------------------------------------------------
    if KEY_ETH_ENABLED in params:
        updates["ethernet_enabled"] = _bool_val(params[KEY_ETH_ENABLED])
    if KEY_ETH_DHCP in params:
        updates["ethernet_dhcp"] = _bool_val(params[KEY_ETH_DHCP])
    if KEY_ETH_IP in params:
        updates["ethernet_ip"] = _ip_val(params[KEY_ETH_IP])
    if KEY_ETH_MASK in params:
        updates["ethernet_mask"] = _ip_val(params[KEY_ETH_MASK])
    if KEY_ETH_GATE in params:
        updates["ethernet_gateway"] = _ip_val(params[KEY_ETH_GATE])
    if KEY_ETH_DNS in params:
        updates["ethernet_dns"] = _ip_val(params[KEY_ETH_DNS])

    # Wi-Fi ------------------------------------------------------------------
    if KEY_WIFI_ENABLED in params:
        updates["wifi_enabled"] = _bool_val(params[KEY_WIFI_ENABLED])
    if KEY_WIFI_SSID in params:
        updates["wifi_ssid"] = _str_val(params[KEY_WIFI_SSID])
    if KEY_WIFI_LEVEL in params:
        updates["wifi_signal_level"] = WIFI_SIGNAL_MAP.get(
            _byte_val(params[KEY_WIFI_LEVEL]), "unknown"
        )
    if KEY_WIFI_IP in params:
        updates["wifi_ip"] = _ip_val(params[KEY_WIFI_IP])

    # GSM --------------------------------------------------------------------
    if KEY_GSM_SIGNAL_LVL in params:
        raw = params[KEY_GSM_SIGNAL_LVL]
        # May be 1 or 2 bytes; use last byte for the signal level
        sig = raw[-1] if raw else 0
        updates["gsm_signal_level"] = GSM_SIGNAL_MAP.get(sig, "unknown")
    if KEY_GSM_NETWORK_STATUS in params:
        updates["gsm_network_type"] = GSM_NETWORK_MAP.get(
            _byte_val(params[KEY_GSM_NETWORK_STATUS]), "unknown"
        )

    return dataclasses.replace(base, **updates)  # type: ignore[arg-type]

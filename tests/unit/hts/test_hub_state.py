"""Tests for hub network state parser (TLV key-value → HubNetworkState)."""

import dataclasses

import pytest

from custom_components.ajax_cobranded.api.hts.hub_state import (
    KEY_ACTIVE_CHANNELS,
    KEY_ETH_DHCP,
    KEY_ETH_DNS,
    KEY_ETH_GATE,
    KEY_ETH_IP,
    KEY_ETH_MASK,
    KEY_GSM_NETWORK_STATUS,
    KEY_GSM_SIGNAL_LVL,
    KEY_HUB_POWERED,
    KEY_WIFI_SSID,
    HubNetworkState,
    _bool_val,
    _byte_val,
    _int_to_ip,
    _ip_val,
    _str_val,
    parse_hub_params,
)

# ---------------------------------------------------------------------------
# HubNetworkState defaults
# ---------------------------------------------------------------------------


class TestHubNetworkStateDefaults:
    def test_connections_default_false(self) -> None:
        s = HubNetworkState()
        assert s.ethernet_connected is False
        assert s.wifi_connected is False
        assert s.gsm_connected is False

    def test_signal_levels_default_unknown(self) -> None:
        s = HubNetworkState()
        assert s.gsm_signal_level == "unknown"
        assert s.gsm_network_type == "unknown"
        assert s.wifi_signal_level == "unknown"

    def test_externally_powered_default_false(self) -> None:
        assert HubNetworkState().externally_powered is False

    def test_primary_connection_none_by_default(self) -> None:
        assert HubNetworkState().primary_connection == "none"

    def test_is_frozen(self) -> None:
        s = HubNetworkState()
        with pytest.raises(dataclasses.FrozenInstanceError):
            s.ethernet_connected = True  # type: ignore[misc]


# ---------------------------------------------------------------------------
# primary_connection priority
# ---------------------------------------------------------------------------


class TestPrimaryConnection:
    def test_ethernet_wins_over_all(self) -> None:
        s = HubNetworkState(ethernet_connected=True, wifi_connected=True, gsm_connected=True)
        assert s.primary_connection == "ethernet"

    def test_wifi_wins_over_gsm(self) -> None:
        s = HubNetworkState(wifi_connected=True, gsm_connected=True)
        assert s.primary_connection == "wifi"

    def test_gsm_only(self) -> None:
        s = HubNetworkState(gsm_connected=True)
        assert s.primary_connection == "gsm"

    def test_none_when_all_false(self) -> None:
        assert HubNetworkState().primary_connection == "none"


# ---------------------------------------------------------------------------
# active_channels bitmask (bit0=eth, bit1=wifi, bit2=gsm)
# ---------------------------------------------------------------------------


class TestActiveChannelsBitmask:
    def test_bit0_sets_ethernet(self) -> None:
        state = parse_hub_params({KEY_ACTIVE_CHANNELS: bytes([0b001])})
        assert state.ethernet_connected is True
        assert state.wifi_connected is False
        assert state.gsm_connected is False

    def test_bit1_sets_wifi(self) -> None:
        state = parse_hub_params({KEY_ACTIVE_CHANNELS: bytes([0b010])})
        assert state.wifi_connected is True
        assert state.ethernet_connected is False
        assert state.gsm_connected is False

    def test_bit2_sets_gsm(self) -> None:
        state = parse_hub_params({KEY_ACTIVE_CHANNELS: bytes([0b100])})
        assert state.gsm_connected is True
        assert state.ethernet_connected is False
        assert state.wifi_connected is False

    def test_all_bits_set(self) -> None:
        state = parse_hub_params({KEY_ACTIVE_CHANNELS: bytes([0b111])})
        assert state.ethernet_connected is True
        assert state.wifi_connected is True
        assert state.gsm_connected is True

    def test_zero_clears_all(self) -> None:
        state = parse_hub_params({KEY_ACTIVE_CHANNELS: bytes([0x00])})
        assert state.ethernet_connected is False
        assert state.wifi_connected is False
        assert state.gsm_connected is False


# ---------------------------------------------------------------------------
# Ethernet IP parsing
# ---------------------------------------------------------------------------


class TestEthernetIP:
    def test_parse_ip_192_168_1_1(self) -> None:
        ip_bytes = bytes([192, 168, 1, 1])
        state = parse_hub_params({KEY_ETH_IP: ip_bytes})
        assert state.ethernet_ip == "192.168.1.1"

    def test_parse_ip_10_0_0_1(self) -> None:
        ip_bytes = bytes([10, 0, 0, 1])
        state = parse_hub_params({KEY_ETH_IP: ip_bytes})
        assert state.ethernet_ip == "10.0.0.1"

    def test_parse_mask(self) -> None:
        mask_bytes = bytes([255, 255, 255, 0])
        state = parse_hub_params({KEY_ETH_MASK: mask_bytes})
        assert state.ethernet_mask == "255.255.255.0"

    def test_parse_gateway(self) -> None:
        gw_bytes = bytes([10, 0, 0, 254])
        state = parse_hub_params({KEY_ETH_GATE: gw_bytes})
        assert state.ethernet_gateway == "10.0.0.254"

    def test_parse_dns(self) -> None:
        dns_bytes = bytes([8, 8, 8, 8])
        state = parse_hub_params({KEY_ETH_DNS: dns_bytes})
        assert state.ethernet_dns == "8.8.8.8"


# ---------------------------------------------------------------------------
# hub_powered
# ---------------------------------------------------------------------------


class TestHubPowered:
    def test_powered_on(self) -> None:
        state = parse_hub_params({KEY_HUB_POWERED: bytes([1])})
        assert state.externally_powered is True

    def test_powered_off(self) -> None:
        state = parse_hub_params({KEY_HUB_POWERED: bytes([0])})
        assert state.externally_powered is False

    def test_nonzero_is_true(self) -> None:
        state = parse_hub_params({KEY_HUB_POWERED: bytes([0xFF])})
        assert state.externally_powered is True


# ---------------------------------------------------------------------------
# GSM signal
# ---------------------------------------------------------------------------


class TestGsmSignal:
    @pytest.mark.parametrize(
        "code, expected",
        [(0, "unknown"), (1, "weak"), (2, "normal"), (3, "strong")],
    )
    def test_gsm_signal_map(self, code: int, expected: str) -> None:
        state = parse_hub_params({KEY_GSM_SIGNAL_LVL: bytes([code])})
        assert state.gsm_signal_level == expected

    def test_unknown_code_returns_unknown(self) -> None:
        state = parse_hub_params({KEY_GSM_SIGNAL_LVL: bytes([99])})
        assert state.gsm_signal_level == "unknown"


# ---------------------------------------------------------------------------
# GSM network type
# ---------------------------------------------------------------------------


class TestGsmNetwork:
    @pytest.mark.parametrize(
        "code, expected",
        [(0, "unknown"), (1, "gsm"), (2, "2g"), (3, "3g"), (4, "4g")],
    )
    def test_gsm_network_map(self, code: int, expected: str) -> None:
        state = parse_hub_params({KEY_GSM_NETWORK_STATUS: bytes([code])})
        assert state.gsm_network_type == expected

    def test_unknown_code_returns_unknown(self) -> None:
        state = parse_hub_params({KEY_GSM_NETWORK_STATUS: bytes([99])})
        assert state.gsm_network_type == "unknown"


# ---------------------------------------------------------------------------
# Wi-Fi SSID
# ---------------------------------------------------------------------------


class TestWifiSsid:
    def test_plain_ssid(self) -> None:
        state = parse_hub_params({KEY_WIFI_SSID: b"MyNetwork"})
        assert state.wifi_ssid == "MyNetwork"

    def test_null_terminated_ssid(self) -> None:
        state = parse_hub_params({KEY_WIFI_SSID: b"MyNetwork\x00garbage"})
        assert state.wifi_ssid == "MyNetwork"

    def test_empty_ssid(self) -> None:
        state = parse_hub_params({KEY_WIFI_SSID: b""})
        assert state.wifi_ssid == ""


# ---------------------------------------------------------------------------
# Ethernet DHCP
# ---------------------------------------------------------------------------


class TestEthernetDhcp:
    def test_dhcp_enabled(self) -> None:
        state = parse_hub_params({KEY_ETH_DHCP: bytes([1])})
        assert state.ethernet_dhcp is True

    def test_dhcp_disabled(self) -> None:
        state = parse_hub_params({KEY_ETH_DHCP: bytes([0])})
        assert state.ethernet_dhcp is False


# ---------------------------------------------------------------------------
# Merge with existing state (incremental updates)
# ---------------------------------------------------------------------------


class TestMergeWithExisting:
    def test_unmentioned_fields_preserved(self) -> None:
        existing = HubNetworkState(
            ethernet_connected=True,
            ethernet_ip="10.0.0.1",
            gsm_signal_level="strong",
        )
        # Only update hub_powered; all other fields must stay
        updated = parse_hub_params({KEY_HUB_POWERED: bytes([1])}, existing=existing)
        assert updated.ethernet_connected is True
        assert updated.ethernet_ip == "10.0.0.1"
        assert updated.gsm_signal_level == "strong"
        assert updated.externally_powered is True

    def test_updated_field_overwrites(self) -> None:
        existing = HubNetworkState(ethernet_ip="192.168.0.1")
        updated = parse_hub_params({KEY_ETH_IP: bytes([10, 0, 0, 2])}, existing=existing)
        assert updated.ethernet_ip == "10.0.0.2"

    def test_empty_params_returns_clone_of_existing(self) -> None:
        existing = HubNetworkState(wifi_connected=True, wifi_ssid="Home")
        updated = parse_hub_params({}, existing=existing)
        assert updated == existing

    def test_none_existing_uses_defaults(self) -> None:
        state = parse_hub_params({KEY_HUB_POWERED: bytes([1])}, existing=None)
        assert state.externally_powered is True
        assert state.ethernet_connected is False  # default

    def test_multiple_keys_merged(self) -> None:
        existing = HubNetworkState(gsm_connected=True)
        params = {
            KEY_ACTIVE_CHANNELS: bytes([0b011]),  # eth + wifi, clear gsm
            KEY_WIFI_SSID: b"Office",
            KEY_HUB_POWERED: bytes([1]),
        }
        updated = parse_hub_params(params, existing=existing)
        assert updated.ethernet_connected is True
        assert updated.wifi_connected is True
        assert updated.gsm_connected is False
        assert updated.wifi_ssid == "Office"
        assert updated.externally_powered is True


# ---------------------------------------------------------------------------
# Helper function unit tests
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_int_to_ip(self) -> None:
        assert _int_to_ip(0xC0A80101) == "192.168.1.1"
        assert _int_to_ip(0x00000000) == "0.0.0.0"
        assert _int_to_ip(0xFFFFFFFF) == "255.255.255.255"

    def test_byte_val(self) -> None:
        assert _byte_val(b"\x05") == 5
        assert _byte_val(b"\x00") == 0
        assert _byte_val(b"\xff\x01") == 255

    def test_bool_val(self) -> None:
        assert _bool_val(b"\x01") is True
        assert _bool_val(b"\x00") is False
        assert _bool_val(b"\xff") is True

    def test_str_val_plain(self) -> None:
        assert _str_val(b"hello") == "hello"

    def test_str_val_null_terminated(self) -> None:
        assert _str_val(b"hello\x00world") == "hello"

    def test_ip_val_four_bytes(self) -> None:
        assert _ip_val(bytes([192, 168, 0, 1])) == "192.168.0.1"

    def test_ip_val_too_short_returns_empty(self) -> None:
        assert _ip_val(bytes([192, 168])) == ""

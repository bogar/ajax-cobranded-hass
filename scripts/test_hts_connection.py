#!/usr/bin/env python3
"""E2E test: connect to real HTS server and log hub updates.

READ-ONLY: Does NOT modify any settings or alarm state.

First logs in via gRPC to get the session token, then uses it for HTS auth.

Usage:
    docker run --rm -v $(pwd):/app -w /app \
      -e AJAX_EMAIL=your@email.com \
      -e AJAX_PASSWORD=yourpass \
      aegis-ajax-dev python scripts/test_hts_connection.py
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import TYPE_CHECKING

from custom_components.aegis_ajax.api.client import AjaxGrpcClient
from custom_components.aegis_ajax.api.hts.client import HtsClient

if TYPE_CHECKING:
    from custom_components.aegis_ajax.api.hts.hub_state import HubNetworkState

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)


def on_update(hub_id: str, state: HubNetworkState) -> None:
    print(f"\n{'=' * 60}")
    print(f"Hub {hub_id} state update:")
    print(f"  Primary connection: {state.primary_connection}")
    print(f"  Ethernet: connected={state.ethernet_connected}, enabled={state.ethernet_enabled}")
    print(f"    IP={state.ethernet_ip}, mask={state.ethernet_mask}")
    print(f"    GW={state.ethernet_gateway}, DNS={state.ethernet_dns}, DHCP={state.ethernet_dhcp}")
    print(f"  WiFi: connected={state.wifi_connected}, enabled={state.wifi_enabled}")
    print(f"    SSID={state.wifi_ssid}, signal={state.wifi_signal_level}, IP={state.wifi_ip}")
    print(f"  GSM: connected={state.gsm_connected}")
    print(f"    signal={state.gsm_signal_level}, network={state.gsm_network_type}")
    print(f"  Power: externally_powered={state.externally_powered}")
    print(f"{'=' * 60}\n")


async def main() -> None:
    email = os.environ.get("AJAX_EMAIL")
    password = os.environ.get("AJAX_PASSWORD")
    if not email or not password:
        print("Error: Set AJAX_EMAIL and AJAX_PASSWORD environment variables.")
        sys.exit(1)

    app_label = os.environ.get("AJAX_APP_LABEL", "Protegim_alarma")

    # Step 1: Login via gRPC to get session token
    print(f"Step 1: gRPC login as {email}...")
    grpc_client = AjaxGrpcClient(email=email, password=password, app_label=app_label)
    await grpc_client.connect()
    await grpc_client.login()

    # Get the raw session token bytes
    session_token_hex = grpc_client.session._session_token
    if not session_token_hex:
        print("Error: No session token after gRPC login")
        await grpc_client.close()
        sys.exit(1)
    session_token = bytes.fromhex(session_token_hex)
    device_id = grpc_client.session._device_id
    user_hex_id = grpc_client.session._user_hex_id

    print(f"  Session token: {session_token_hex[:16]}...")
    print(f"  Device ID: {device_id}")
    print(f"  User hex ID: {user_hex_id}")

    # Step 2: Connect to HTS with the session token
    print(f"\nStep 2: HTS connect (app: {app_label})...")
    hts_client = HtsClient(
        login_token=session_token,
        user_hex_id=user_hex_id,
        device_id=device_id,
        app_label=app_label,
    )

    try:
        result = await hts_client.connect()
        print(f"HTS authenticated! Connection token: {result.token.hex()[:16]}...")
        print(f"Hubs: {[(h.hub_id, h.is_master) for h in result.hubs]}")

        # listen() automatically requests hub data

        print("\nListening for updates (Ctrl+C to stop)...\n")
        await hts_client.listen(on_state_update=on_update)
    except KeyboardInterrupt:
        print("\nStopped by user.")
    except Exception as e:
        print(f"Error: {e}")
        import traceback

        traceback.print_exc()
    finally:
        await hts_client.close()
        await grpc_client.close()
        print("Disconnected.")


if __name__ == "__main__":
    asyncio.run(main())

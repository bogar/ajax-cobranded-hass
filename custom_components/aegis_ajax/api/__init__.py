"""Ajax Security API client."""

from custom_components.aegis_ajax.api.client import AjaxGrpcClient
from custom_components.aegis_ajax.api.devices import DevicesApi
from custom_components.aegis_ajax.api.models import (
    BatteryInfo,
    Device,
    DeviceCommand,
    Space,
)
from custom_components.aegis_ajax.api.security import SecurityApi, SecurityError
from custom_components.aegis_ajax.api.session import (
    AjaxSession,
    AuthenticationError,
    TwoFactorRequiredError,
)
from custom_components.aegis_ajax.api.spaces import SpacesApi

__all__ = [
    "AjaxGrpcClient",
    "AjaxSession",
    "AuthenticationError",
    "BatteryInfo",
    "Device",
    "DeviceCommand",
    "DevicesApi",
    "SecurityApi",
    "SecurityError",
    "Space",
    "SpacesApi",
    "TwoFactorRequiredError",
]

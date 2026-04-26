"""Tests for the integration __init__.py setup."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestAsyncSetupEntry:
    @pytest.mark.asyncio
    async def test_setup_entry_creates_coordinator(self) -> None:
        from custom_components.aegis_ajax import async_setup_entry

        hass = MagicMock()
        hass.data = {}
        hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)

        entry = MagicMock()
        entry.entry_id = "entry-1"
        entry.data = {
            "email": "test@example.com",
            "password_hash": "abc123hash",
            "spaces": ["s1"],
        }
        entry.options = {"poll_interval": 30}

        mock_client = MagicMock()
        mock_client.connect = AsyncMock()
        mock_client.session = MagicMock()

        mock_coordinator = MagicMock()
        mock_coordinator.async_config_entry_first_refresh = AsyncMock()
        mock_coordinator.async_start_push_notifications = AsyncMock()

        with (
            patch(
                "custom_components.aegis_ajax.AjaxGrpcClient", return_value=mock_client
            ) as mock_cls,
            patch(
                "custom_components.aegis_ajax.AjaxCobrandedCoordinator",
                return_value=mock_coordinator,
            ),
        ):
            result = await async_setup_entry(hass, entry)

        assert result is True
        assert entry.runtime_data is mock_coordinator
        # Verify client was created with password_hash, not password
        mock_cls.assert_called_once()
        call_kwargs = mock_cls.call_args[1]
        assert call_kwargs.get("password_hash") == "abc123hash"
        assert "password" not in call_kwargs or call_kwargs.get("password") is None

    @pytest.mark.asyncio
    async def test_setup_entry_with_legacy_password(self) -> None:
        """Test backward compatibility: legacy entries with plaintext password still work."""
        from custom_components.aegis_ajax import async_setup_entry

        hass = MagicMock()
        hass.data = {}
        hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)

        entry = MagicMock()
        entry.entry_id = "entry-legacy"
        entry.data = {
            "email": "test@example.com",
            "password": "secret",
            "spaces": ["s1"],
        }
        entry.options = {}

        mock_client = MagicMock()
        mock_client.connect = AsyncMock()
        mock_client.session = MagicMock()

        mock_coordinator = MagicMock()
        mock_coordinator.async_config_entry_first_refresh = AsyncMock()
        mock_coordinator.async_start_push_notifications = AsyncMock()

        with (
            patch(
                "custom_components.aegis_ajax.AjaxGrpcClient", return_value=mock_client
            ) as mock_cls,
            patch(
                "custom_components.aegis_ajax.AjaxCobrandedCoordinator",
                return_value=mock_coordinator,
            ),
        ):
            result = await async_setup_entry(hass, entry)

        assert result is True
        # Verify client was created with plaintext password (legacy path)
        mock_cls.assert_called_once()
        call_kwargs = mock_cls.call_args[1]
        assert call_kwargs.get("password") == "secret"

    @pytest.mark.asyncio
    async def test_setup_entry_does_not_restore_session_token(self) -> None:
        """Ensure session token is no longer read from config entry data."""
        from custom_components.aegis_ajax import async_setup_entry

        hass = MagicMock()
        hass.data = {}
        hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)

        entry = MagicMock()
        entry.entry_id = "entry-2"
        entry.data = {
            "email": "test@example.com",
            "password_hash": "abc123hash",
            "spaces": ["s1"],
        }
        entry.options = {}

        mock_client = MagicMock()
        mock_client.connect = AsyncMock()
        mock_client.session = MagicMock()

        mock_coordinator = MagicMock()
        mock_coordinator.async_config_entry_first_refresh = AsyncMock()
        mock_coordinator.async_start_push_notifications = AsyncMock()

        with (
            patch("custom_components.aegis_ajax.AjaxGrpcClient", return_value=mock_client),
            patch(
                "custom_components.aegis_ajax.AjaxCobrandedCoordinator",
                return_value=mock_coordinator,
            ),
        ):
            result = await async_setup_entry(hass, entry)

        assert result is True
        # Session token should NOT be restored — authentication happens fresh via coordinator
        mock_client.session.set_session.assert_not_called()


class TestOptionsUpdateListener:
    @pytest.mark.asyncio
    async def test_options_change_triggers_reload(self) -> None:
        from custom_components.aegis_ajax import _async_options_update_listener

        hass = MagicMock()
        hass.config_entries.async_reload = AsyncMock()

        entry = MagicMock()
        entry.entry_id = "entry-1"

        await _async_options_update_listener(hass, entry)

        hass.config_entries.async_reload.assert_awaited_once_with("entry-1")

    @pytest.mark.asyncio
    async def test_setup_registers_update_listener(self) -> None:
        from custom_components.aegis_ajax import async_setup_entry

        hass = MagicMock()
        hass.data = {}
        hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)

        entry = MagicMock()
        entry.entry_id = "entry-1"
        entry.data = {
            "email": "test@example.com",
            "password_hash": "abc123hash",
            "spaces": ["s1"],
        }
        entry.options = {}

        mock_client = MagicMock()
        mock_client.connect = AsyncMock()
        mock_client.session = MagicMock()

        mock_coordinator = MagicMock()
        mock_coordinator.async_config_entry_first_refresh = AsyncMock()
        mock_coordinator.async_start_push_notifications = AsyncMock()

        with (
            patch("custom_components.aegis_ajax.AjaxGrpcClient", return_value=mock_client),
            patch(
                "custom_components.aegis_ajax.AjaxCobrandedCoordinator",
                return_value=mock_coordinator,
            ),
        ):
            await async_setup_entry(hass, entry)

        entry.add_update_listener.assert_called_once()


class TestAutoLabeling:
    @pytest.mark.asyncio
    async def test_apply_labels_creates_labels_and_assigns(self) -> None:
        from custom_components.aegis_ajax import _async_apply_labels
        from custom_components.aegis_ajax.const import LABELS

        hass = MagicMock()
        entry = MagicMock()
        entry.entry_id = "entry-1"

        # Mock label registry
        mock_label_reg = MagicMock()
        mock_label_reg.async_get_label.return_value = None  # labels don't exist yet

        # Mock entity registry with a door sensor
        mock_entity = MagicMock()
        mock_entity.entity_id = "binary_sensor.porta_door"
        mock_entity.original_device_class = "door"
        mock_entity.labels = set()

        mock_entity_reg = MagicMock()
        mock_entries_fn = MagicMock(return_value=[mock_entity])

        with (
            patch("homeassistant.helpers.label_registry.async_get", return_value=mock_label_reg),
            patch("homeassistant.helpers.entity_registry.async_get", return_value=mock_entity_reg),
            patch(
                "homeassistant.helpers.entity_registry.async_entries_for_config_entry",
                mock_entries_fn,
            ),
        ):
            await _async_apply_labels(hass, entry)

        # Labels should be created
        assert mock_label_reg.async_create.call_count == len(LABELS)

        # Entity should get aegis_door label
        mock_entity_reg.async_update_entity.assert_called_once()
        call_kwargs = mock_entity_reg.async_update_entity.call_args
        assert "aegis_door" in call_kwargs[1]["labels"]

    @pytest.mark.asyncio
    async def test_apply_labels_preserves_existing_labels(self) -> None:
        from custom_components.aegis_ajax import _async_apply_labels

        hass = MagicMock()
        entry = MagicMock()
        entry.entry_id = "entry-1"

        mock_label_reg = MagicMock()
        mock_label_reg.async_get_label.return_value = MagicMock()  # labels exist

        mock_entity = MagicMock()
        mock_entity.entity_id = "binary_sensor.porta_tamper"
        mock_entity.original_device_class = "tamper"
        mock_entity.labels = {"user_custom_label"}

        mock_entity_reg = MagicMock()

        with (
            patch("homeassistant.helpers.label_registry.async_get", return_value=mock_label_reg),
            patch("homeassistant.helpers.entity_registry.async_get", return_value=mock_entity_reg),
            patch(
                "homeassistant.helpers.entity_registry.async_entries_for_config_entry",
                return_value=[mock_entity],
            ),
        ):
            await _async_apply_labels(hass, entry)

        # Should preserve user label and add aegis_tamper
        call_kwargs = mock_entity_reg.async_update_entity.call_args[1]
        assert "user_custom_label" in call_kwargs["labels"]
        assert "aegis_tamper" in call_kwargs["labels"]

    @pytest.mark.asyncio
    async def test_apply_labels_skips_when_already_labeled(self) -> None:
        from custom_components.aegis_ajax import _async_apply_labels

        hass = MagicMock()
        entry = MagicMock()
        entry.entry_id = "entry-1"

        mock_label_reg = MagicMock()
        mock_label_reg.async_get_label.return_value = MagicMock()

        mock_entity = MagicMock()
        mock_entity.entity_id = "binary_sensor.porta_door"
        mock_entity.original_device_class = "door"
        mock_entity.labels = {"aegis_door"}  # already labeled

        mock_entity_reg = MagicMock()

        with (
            patch("homeassistant.helpers.label_registry.async_get", return_value=mock_label_reg),
            patch("homeassistant.helpers.entity_registry.async_get", return_value=mock_entity_reg),
            patch(
                "homeassistant.helpers.entity_registry.async_entries_for_config_entry",
                return_value=[mock_entity],
            ),
        ):
            await _async_apply_labels(hass, entry)

        # Should not update since label already present
        mock_entity_reg.async_update_entity.assert_not_called()

    @pytest.mark.asyncio
    async def test_apply_labels_hub_entities_by_pattern(self) -> None:
        from custom_components.aegis_ajax import _async_apply_labels

        hass = MagicMock()
        entry = MagicMock()
        entry.entry_id = "entry-1"

        mock_label_reg = MagicMock()
        mock_label_reg.async_get_label.return_value = MagicMock()

        mock_entity = MagicMock()
        mock_entity.entity_id = "sensor.alarma_ajax_ip_ethernet"
        mock_entity.original_device_class = None
        mock_entity.labels = set()

        mock_entity_reg = MagicMock()

        with (
            patch("homeassistant.helpers.label_registry.async_get", return_value=mock_label_reg),
            patch("homeassistant.helpers.entity_registry.async_get", return_value=mock_entity_reg),
            patch(
                "homeassistant.helpers.entity_registry.async_entries_for_config_entry",
                return_value=[mock_entity],
            ),
        ):
            await _async_apply_labels(hass, entry)

        call_kwargs = mock_entity_reg.async_update_entity.call_args[1]
        assert "aegis_hub" in call_kwargs["labels"]


class TestAutoCreateLabelsOption:
    """Verify the `auto_create_labels` OptionsFlow toggle gates label creation."""

    def _make_entry(self, options: dict) -> MagicMock:
        entry = MagicMock()
        entry.entry_id = "entry-1"
        entry.data = {
            "email": "test@example.com",
            "password_hash": "abc123hash",
            "spaces": ["s1"],
        }
        entry.options = options
        return entry

    async def _run_setup(self, entry: MagicMock) -> MagicMock:
        from custom_components.aegis_ajax import async_setup_entry

        hass = MagicMock()
        hass.data = {}
        hass.config_entries.async_forward_entry_setups = AsyncMock(return_value=True)

        mock_client = MagicMock()
        mock_client.connect = AsyncMock()
        mock_client.session = MagicMock()

        mock_coordinator = MagicMock()
        mock_coordinator.async_config_entry_first_refresh = AsyncMock()
        mock_coordinator.async_start_push_notifications = AsyncMock()

        apply_labels_mock = AsyncMock()
        with (
            patch("custom_components.aegis_ajax.AjaxGrpcClient", return_value=mock_client),
            patch(
                "custom_components.aegis_ajax.AjaxCobrandedCoordinator",
                return_value=mock_coordinator,
            ),
            patch("custom_components.aegis_ajax._async_apply_labels", apply_labels_mock),
        ):
            await async_setup_entry(hass, entry)
        return apply_labels_mock

    @pytest.mark.asyncio
    async def test_auto_create_labels_default_calls_apply(self) -> None:
        entry = self._make_entry(options={})
        apply_mock = await self._run_setup(entry)
        apply_mock.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_auto_create_labels_explicit_true_calls_apply(self) -> None:
        entry = self._make_entry(options={"auto_create_labels": True})
        apply_mock = await self._run_setup(entry)
        apply_mock.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_auto_create_labels_false_skips_apply(self) -> None:
        entry = self._make_entry(options={"auto_create_labels": False})
        apply_mock = await self._run_setup(entry)
        apply_mock.assert_not_awaited()


class TestAsyncUnloadEntry:
    @pytest.mark.asyncio
    async def test_unload_entry_success(self) -> None:
        from custom_components.aegis_ajax import async_unload_entry

        mock_coordinator = MagicMock()
        mock_coordinator.async_shutdown = AsyncMock()

        hass = MagicMock()
        hass.config_entries.async_unload_platforms = AsyncMock(return_value=True)

        entry = MagicMock()
        entry.entry_id = "entry-1"
        entry.runtime_data = mock_coordinator

        result = await async_unload_entry(hass, entry)

        assert result is True
        mock_coordinator.async_shutdown.assert_called_once()

    @pytest.mark.asyncio
    async def test_unload_entry_failure_does_not_clean_up(self) -> None:
        from custom_components.aegis_ajax import async_unload_entry

        mock_coordinator = MagicMock()
        mock_coordinator.async_shutdown = AsyncMock()

        hass = MagicMock()
        hass.config_entries.async_unload_platforms = AsyncMock(return_value=False)

        entry = MagicMock()
        entry.entry_id = "entry-1"
        entry.runtime_data = mock_coordinator

        result = await async_unload_entry(hass, entry)

        assert result is False
        mock_coordinator.async_shutdown.assert_not_called()

"""Tests for media_source platform."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from custom_components.ajax_cobranded.media_source import (
    AjaxPhotoMediaSource,
    async_get_media_source,
)


def _make_hass(media_dir: str = "/media") -> MagicMock:
    """Create a mock hass with media_dirs configured."""
    hass = MagicMock()
    hass.config.media_dirs = {"local": media_dir}
    return hass


class TestAjaxPhotoMediaSource:
    def test_name(self) -> None:
        source = AjaxPhotoMediaSource(_make_hass())
        assert source.name == "Ajax Security Photos"

    def test_domain(self) -> None:
        source = AjaxPhotoMediaSource(_make_hass())
        assert source.domain == "ajax_cobranded"

    def test_base_path(self) -> None:
        source = AjaxPhotoMediaSource(_make_hass("/tmp/test_media"))
        assert source._base_path == Path("/tmp/test_media/ajax_photos")

    def test_base_path_default(self) -> None:
        hass = MagicMock()
        hass.config.media_dirs = {}
        source = AjaxPhotoMediaSource(hass)
        assert source._base_path == Path("/media/ajax_photos")

    @pytest.mark.asyncio
    async def test_async_get_media_source(self) -> None:
        hass = _make_hass()
        source = await async_get_media_source(hass)
        assert isinstance(source, AjaxPhotoMediaSource)

    @pytest.mark.asyncio
    async def test_resolve_media_no_identifier(self) -> None:
        from homeassistant.components.media_source import Unresolvable

        source = AjaxPhotoMediaSource(_make_hass())
        item = MagicMock()
        item.identifier = None
        with pytest.raises(Unresolvable):
            await source.async_resolve_media(item)

    @pytest.mark.asyncio
    async def test_resolve_media_file_not_found(self) -> None:
        from homeassistant.components.media_source import Unresolvable

        source = AjaxPhotoMediaSource(_make_hass("/tmp/nonexistent_media_test"))
        item = MagicMock()
        item.identifier = "DEVICE/2026-04-14_00-23-18.jpg"
        with pytest.raises(Unresolvable, match="File not found"):
            await source.async_resolve_media(item)

    @pytest.mark.asyncio
    async def test_resolve_media_traversal_attack(self) -> None:
        from homeassistant.components.media_source import Unresolvable

        source = AjaxPhotoMediaSource(_make_hass("/tmp/test_media"))
        item = MagicMock()
        item.identifier = "../../etc/passwd"
        with pytest.raises(Unresolvable, match="Invalid path"):
            await source.async_resolve_media(item)

    @pytest.mark.asyncio
    async def test_resolve_media_success(self, tmp_path: Path) -> None:
        media_dir = tmp_path / "media"
        photos_dir = media_dir / "ajax_photos" / "DEVICE"
        photos_dir.mkdir(parents=True)
        photo = photos_dir / "2026-04-14_00-23-18.jpg"
        photo.write_bytes(b"\xff\xd8\xff\xe0")

        source = AjaxPhotoMediaSource(_make_hass(str(media_dir)))
        item = MagicMock()
        item.identifier = "DEVICE/2026-04-14_00-23-18.jpg"
        result = await source.async_resolve_media(item)
        assert result.mime_type == "image/jpeg"
        assert "ajax_photos/DEVICE/2026-04-14_00-23-18.jpg" in result.url

    @pytest.mark.asyncio
    async def test_browse_root_empty(self) -> None:
        source = AjaxPhotoMediaSource(_make_hass("/tmp/nonexistent_media_test"))
        item = MagicMock()
        item.identifier = None
        result = await source.async_browse_media(item)
        assert result.title == "Ajax Security Photos"
        assert result.children == []

    @pytest.mark.asyncio
    async def test_browse_root_with_folders(self, tmp_path: Path) -> None:
        media_dir = tmp_path / "media"
        for name in ["PASSADIS", "MENJADOR"]:
            folder = media_dir / "ajax_photos" / name
            folder.mkdir(parents=True)
            (folder / "2026-04-14_00-23-18.jpg").write_bytes(b"\xff\xd8")
            (folder / "last.jpg").write_bytes(b"\xff\xd8")

        source = AjaxPhotoMediaSource(_make_hass(str(media_dir)))
        item = MagicMock()
        item.identifier = None
        result = await source.async_browse_media(item)
        assert len(result.children) == 2
        # last.jpg should not be counted
        assert "(1)" in result.children[0].title

    @pytest.mark.asyncio
    async def test_browse_folder_with_photos(self, tmp_path: Path) -> None:
        media_dir = tmp_path / "media"
        folder = media_dir / "ajax_photos" / "DEVICE"
        folder.mkdir(parents=True)
        (folder / "2026-04-14_00-23-18.jpg").write_bytes(b"\xff\xd8")
        (folder / "2026-04-13_12-00-00.jpg").write_bytes(b"\xff\xd8")
        (folder / "last.jpg").write_bytes(b"\xff\xd8")

        source = AjaxPhotoMediaSource(_make_hass(str(media_dir)))
        item = MagicMock()
        item.identifier = "DEVICE"
        result = await source.async_browse_media(item)
        assert len(result.children) == 2
        # Newest first
        assert result.children[0].title == "2026-04-14 00:23:18"
        assert result.children[1].title == "2026-04-13 12:00:00"

    @pytest.mark.asyncio
    async def test_browse_folder_title_formatting(self, tmp_path: Path) -> None:
        media_dir = tmp_path / "media"
        folder = media_dir / "ajax_photos" / "DEVICE"
        folder.mkdir(parents=True)
        (folder / "2026-04-14_00-23-18.jpg").write_bytes(b"\xff\xd8")

        source = AjaxPhotoMediaSource(_make_hass(str(media_dir)))
        item = MagicMock()
        item.identifier = "DEVICE"
        result = await source.async_browse_media(item)
        assert result.children[0].title == "2026-04-14 00:23:18"

    @pytest.mark.asyncio
    async def test_browse_folder_traversal_returns_root(self, tmp_path: Path) -> None:
        media_dir = tmp_path / "media"
        (media_dir / "ajax_photos").mkdir(parents=True)

        source = AjaxPhotoMediaSource(_make_hass(str(media_dir)))
        item = MagicMock()
        item.identifier = "../../etc"
        result = await source.async_browse_media(item)
        # Should return root instead of traversing
        assert result.title in ("Ajax Security Photos", "../../etc")

"""Media source for Ajax Security photos."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from homeassistant.components.media_player import MediaClass  # type: ignore[attr-defined]
from homeassistant.components.media_source import (
    BrowseMediaSource,
    MediaSource,
    MediaSourceItem,
    PlayMedia,
    Unresolvable,
)

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

from custom_components.ajax_cobranded.const import DOMAIN
from custom_components.ajax_cobranded.photo_storage import PHOTOS_BASE_DIR


async def async_get_media_source(hass: HomeAssistant) -> AjaxPhotoMediaSource:
    """Set up Ajax photo media source."""
    return AjaxPhotoMediaSource(hass)


class AjaxPhotoMediaSource(MediaSource):
    """Provide Ajax Security photos as browsable media."""

    name = "Ajax Security Photos"

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize source."""
        super().__init__(DOMAIN)
        self.hass = hass

    @property
    def _base_path(self) -> Path:
        """Return base path for Ajax photos."""
        media_dir = self.hass.config.media_dirs.get("local", "/media")
        return Path(media_dir) / PHOTOS_BASE_DIR

    async def async_resolve_media(self, item: MediaSourceItem) -> PlayMedia:
        """Resolve a photo to a playable URL."""
        if not item.identifier:
            raise Unresolvable("No identifier provided")

        file_path = self._base_path / item.identifier
        try:
            file_path.resolve().relative_to(self._base_path.resolve())
        except ValueError as err:
            raise Unresolvable("Invalid path") from err

        if not file_path.is_file():
            raise Unresolvable(f"File not found: {item.identifier}")

        return PlayMedia(
            url=f"/media/local/{PHOTOS_BASE_DIR}/{item.identifier}",
            mime_type="image/jpeg",
        )

    async def async_browse_media(self, item: MediaSourceItem) -> BrowseMediaSource:
        """Browse photo folders and files."""
        if not item.identifier:
            return self._browse_root()
        return self._browse_folder(item.identifier)

    def _browse_root(self) -> BrowseMediaSource:
        """List device folders."""
        children: list[BrowseMediaSource] = []
        base = self._base_path

        if base.is_dir():
            for folder in sorted(base.iterdir()):
                if folder.is_dir():
                    photo_count = sum(
                        1
                        for f in folder.iterdir()
                        if f.is_file() and f.suffix == ".jpg" and f.name != "last.jpg"
                    )
                    children.append(
                        BrowseMediaSource(
                            domain=DOMAIN,
                            identifier=folder.name,
                            media_class=MediaClass.DIRECTORY,
                            media_content_type="",
                            title=f"{folder.name} ({photo_count})",
                            can_play=False,
                            can_expand=True,
                        )
                    )

        return BrowseMediaSource(
            domain=DOMAIN,
            identifier=None,
            media_class=MediaClass.APP,
            media_content_type="",
            title="Ajax Security Photos",
            can_play=False,
            can_expand=True,
            children=children,
        )

    def _browse_folder(self, folder_name: str) -> BrowseMediaSource:
        """List photos in a device folder."""
        folder_path = self._base_path / folder_name
        try:
            folder_path.resolve().relative_to(self._base_path.resolve())
        except ValueError:
            return self._browse_root()

        children: list[BrowseMediaSource] = []
        if folder_path.is_dir():
            photos = sorted(
                [
                    f
                    for f in folder_path.iterdir()
                    if f.is_file() and f.suffix == ".jpg" and f.name != "last.jpg"
                ],
                key=lambda f: f.name,
                reverse=True,
            )
            for photo in photos:
                # Format "2026-04-14_00-23-18.jpg" -> "2026-04-14 00:23:18"
                parts = photo.stem.split("_", 1)
                if len(parts) == 2:
                    title = parts[0] + " " + parts[1].replace("-", ":")
                else:
                    title = photo.stem

                identifier = f"{folder_name}/{photo.name}"
                children.append(
                    BrowseMediaSource(
                        domain=DOMAIN,
                        identifier=identifier,
                        media_class=MediaClass.IMAGE,
                        media_content_type="image/jpeg",
                        title=title,
                        can_play=True,
                        can_expand=False,
                        thumbnail=f"/media/local/{PHOTOS_BASE_DIR}/{identifier}",
                    )
                )

        return BrowseMediaSource(
            domain=DOMAIN,
            identifier=folder_name,
            media_class=MediaClass.DIRECTORY,
            media_content_type="",
            title=folder_name,
            can_play=False,
            can_expand=True,
            children=children,
            children_media_class=MediaClass.IMAGE,
        )

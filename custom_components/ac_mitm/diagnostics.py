"""Diagnostics: the AC's last status exactly as it reported it, with secrets removed."""

from __future__ import annotations

from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .features import redact


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    data = coordinator.data or {}
    return {
        "entry": redact(dict(entry.data)),
        "status": redact(dict(data.get("ac") or {})),
        "local": redact(dict(data.get("local") or {})),
        "last_update_success": coordinator.last_update_success,
    }

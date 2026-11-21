"""Shared polling for the Panasonic native local control bridge."""

from __future__ import annotations

import asyncio
from datetime import timedelta
import logging
import time

from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import AcMitmApiError
from .const import DOMAIN, POLL_TIMEOUT, SCAN_INTERVAL
from .health import Health

_LOGGER = logging.getLogger(__name__)


class AcMitmCoordinator(DataUpdateCoordinator):
    def __init__(self, hass, api, entry):
        super().__init__(
            hass,
            _LOGGER,
            name="Panasonic AC Local",
            config_entry=entry,
            update_interval=timedelta(seconds=SCAN_INTERVAL),
        )
        self.api = api
        self.entry_id = entry.entry_id
        self.health = Health(time.time())
        # For the log: which AC, since every entry has the same name
        self.label = (getattr(entry, "data", None) or {}).get("host") or getattr(entry, "title", "")

    async def _async_update_data(self):
        now = time.time()
        try:
            # Bounded, so a reply that never comes can't stall polling: Home Assistant only
            # schedules the next poll once this one returns
            async with asyncio.timeout(POLL_TIMEOUT):
                data = await self.api.async_get_state()
        except (AcMitmApiError, TimeoutError) as error:
            reason = str(error) or f"no answer within {POLL_TIMEOUT} s"
            gap = self.health.missed_poll(now)
            if self.health.missed == 1:
                _LOGGER.warning(
                    "The AC at %s missed a poll (%s); keeping its last state", self.label, reason
                )
            else:
                _LOGGER.debug(
                    "The AC at %s missed %d polls in a row, %.0f s without an answer",
                    self.label,
                    self.health.missed,
                    gap,
                )
            if self.data and not self.health.stale(now):
                return self.data
            raise UpdateFailed(f"No answer for {gap:.0f} s ({reason})") from error
        if self.health.missed:
            _LOGGER.info(
                "The AC at %s answered again after %d missed polls", self.label, self.health.missed
            )
        status = (data or {}).get("ac") if isinstance(data, dict) else None
        if status:
            was_following = self.health.following
            self.health.answered(status, now)
            if was_following and not self.health.following:
                _LOGGER.warning(
                    "The AC at %s answers, but its status hasn't changed by itself since %s, "
                    "through %d minutes of running: it isn't following the unit, so changes "
                    "made on the remote won't show. Its room reading is reported as unknown "
                    "until the status moves again",
                    self.label,
                    self.health.attributes().get("status_unchanged_since"),
                    int((now - self.health.on_since) // 60) if self.health.on_since else 0,
                )
            elif not was_following and self.health.following:
                _LOGGER.info("The AC at %s is following the unit again", self.label)
        return data

    async def async_command(self, action, value, **kwargs):
        """Immediately publish confirmed readback instead of waiting for poll debounce."""
        result = await self.api.async_command(action, value, **kwargs)
        if isinstance(result, dict) and result.get("ac"):
            self.health.commanded(result["ac"], time.time())
            self.async_set_updated_data({**(self.data or {}), **result})
        else:
            await self.async_request_refresh()
        return result

    @property
    def device_info(self):
        local = (self.data or {}).get("local") or {}
        return {
            "identifiers": {(DOMAIN, self.entry_id)},
            "name": "Panasonic AC (Local)",
            "manufacturer": "Panasonic",
            "model": local.get("model") or "MirAIe AC",
            "sw_version": local.get("firmware"),
        }

    @property
    def device_available(self):
        data = self.data or {}
        local = data.get("local") or {}
        return (
            self.last_update_success
            and bool(data.get("ac"))
            and (not local.get("enabled") or local.get("available", False))
        )

"""A heartbeat for each AC: when it last answered, to the minute.

An idle AC's other entities never change, and Home Assistant doesn't show an unchanged write, so
nothing else can tell an AC that's polled and idle from one that's no longer polled. This sensor
changes once a minute while the AC answers. It keeps its last value while the AC is unavailable (or
if polling stopped altogether), so its age says how long the AC has been quiet. To the minute, so
the recorder gets a row a minute rather than one per poll."""

from __future__ import annotations

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.const import EntityCategory
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .health import minute


async def async_setup_entry(hass, entry, async_add_entities):
    data = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([AcLastAnswer(data["coordinator"], entry.entry_id)])


class AcLastAnswer(CoordinatorEntity, SensorEntity):
    _attr_has_entity_name = True
    _attr_name = "Last answer"
    _attr_device_class = SensorDeviceClass.TIMESTAMP
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_icon = "mdi:heart-pulse"

    def __init__(self, coordinator, entry_id):
        super().__init__(coordinator)
        self._attr_unique_id = entry_id + "_last_answer"

    @property
    def device_info(self):
        return self.coordinator.device_info

    @property
    def available(self):
        # Unlike the AC's other entities, it stays available while the AC is quiet: that's its job
        return self.coordinator.health.answered_at is not None

    @property
    def native_value(self):
        return minute(self.coordinator.health.answered_at)

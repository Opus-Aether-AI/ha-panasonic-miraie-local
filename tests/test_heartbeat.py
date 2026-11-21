"""The heartbeat sensor: when the AC last answered, to the minute, kept while it's quiet."""

import asyncio
import sys
import types
from datetime import datetime, timezone
from enum import Enum


def _module(name, **attrs):
    module = sys.modules.setdefault(name, types.ModuleType(name))
    for key, value in attrs.items():
        if not hasattr(module, key):
            setattr(module, key, value)
    return module


class SensorDeviceClass(str, Enum):
    TIMESTAMP = "timestamp"


class EntityCategory(str, Enum):
    DIAGNOSTIC = "diagnostic"


class SensorEntity:
    pass


class CoordinatorEntity:
    def __init__(self, coordinator=None, *args, **kwargs):
        self.coordinator = coordinator


for _name in ("homeassistant", "homeassistant.components", "homeassistant.helpers"):
    _module(_name)
_module("homeassistant.components.sensor", SensorDeviceClass=SensorDeviceClass, SensorEntity=SensorEntity)
_module("homeassistant.const", EntityCategory=EntityCategory)
_module("homeassistant.helpers.update_coordinator", CoordinatorEntity=CoordinatorEntity)

from custom_components.ac_mitm import sensor  # noqa: E402
from custom_components.ac_mitm.health import Health, minute  # noqa: E402

STATUS = {"ps": "off", "acmd": "cool", "actmp": "23.0"}


def entity(health):
    coordinator = types.SimpleNamespace(health=health, device_info={})
    hass = types.SimpleNamespace(data={"ac_mitm": {"e": {"coordinator": coordinator}}})
    added = []
    asyncio.run(sensor.async_setup_entry(hass, types.SimpleNamespace(entry_id="e"), added.extend))
    return added[0]


def test_to_the_minute():
    assert minute(None) is None
    assert minute(125.5) == datetime(1970, 1, 1, 0, 2, tzinfo=timezone.utc)


def test_unknown_until_the_ac_first_answers_then_kept_while_it_is_quiet():
    h = Health(0)
    s = entity(h)
    assert s._attr_unique_id == "e_last_answer" and s._attr_name == "Last answer"
    assert not s.available and s.native_value is None
    h.answered(STATUS, 1000)
    assert s.available and s.native_value == datetime(1970, 1, 1, 0, 16, tzinfo=timezone.utc)
    h.answered(STATUS, 1010)                       # the same minute: the same value, no new row
    assert s.native_value == datetime(1970, 1, 1, 0, 16, tzinfo=timezone.utc)
    for t in range(1020, 1400, 10):                # quiet for minutes: the value stays, so its age grows
        h.missed_poll(t)
    assert s.available and s.native_value == datetime(1970, 1, 1, 0, 16, tzinfo=timezone.utc)

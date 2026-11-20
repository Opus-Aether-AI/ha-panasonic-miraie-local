"""The select, switch and diagnostics entities, run against small stand-ins for Home Assistant."""

import asyncio
import sys
import types

import pytest


class _CoordinatorEntity:
    def __init__(self, coordinator=None, *args, **kwargs):
        self.coordinator = coordinator


class _SelectEntity:
    pass


class _SwitchEntity:
    pass


def _stub(name, **attrs):
    module = sys.modules.get(name) or types.ModuleType(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    sys.modules[name] = module
    return module


class HomeAssistantError(Exception):
    pass


for name in (
    "homeassistant",
    "homeassistant.components",
    "homeassistant.helpers",
    "homeassistant.config_entries",
    "homeassistant.core",
):
    _stub(name)
_stub("homeassistant.components.select", SelectEntity=_SelectEntity)
_stub("homeassistant.components.switch", SwitchEntity=_SwitchEntity)
_stub("homeassistant.exceptions", HomeAssistantError=HomeAssistantError)
_stub("homeassistant.helpers.update_coordinator", CoordinatorEntity=_CoordinatorEntity)
_stub("homeassistant.config_entries", ConfigEntry=object)
_stub("homeassistant.core", HomeAssistant=object)

from custom_components.ac_mitm import diagnostics, select, switch  # noqa: E402
from custom_components.ac_mitm.api import AcMitmApiError  # noqa: E402


class FakeCoordinator:
    def __init__(self, status, fail=False):
        self.data = {"ac": dict(status), "local": {"enabled": True, "available": True}}
        self.device_available = True
        self.device_info = {}
        self.last_update_success = True
        self.sent = []
        self.fail = fail

    async def async_command(self, action, value, **kwargs):
        if self.fail:
            raise AcMitmApiError("AC acknowledged the packet but did not apply all requested settings")
        self.sent.append((action, value, kwargs.get("extra")))
        self.data["ac"][action] = value
        for key, extra_value in (kwargs.get("extra") or {}).items():
            self.data["ac"][key] = extra_value


def entities(platform, coordinator):
    hass = types.SimpleNamespace(
        data={"ac_mitm": {"entry": {"coordinator": coordinator, "api": None}}}
    )
    entry = types.SimpleNamespace(entry_id="entry", data={})
    added = []
    asyncio.run(platform.async_setup_entry(hass, entry, added.extend))
    return {getattr(e, "_attr_name", None): e for e in added}


def test_each_vane_shows_its_position_and_unique_id():
    found = entities(select, FakeCoordinator({"acvs": "0", "achs": "4", "cnv": 40}))
    assert found["Vertical vane"].current_option == "Swing"
    assert found["Horizontal vane"].current_option == "4"
    assert found["Capacity"].current_option == "40%"
    assert found["Vertical vane"]._attr_unique_id == "entry_acvs"
    assert found["Horizontal vane"]._attr_unique_id == "entry_achs"
    assert found["Capacity"]._attr_unique_id == "entry_cnv", "existing entity ids must not move"


def test_choosing_a_vane_position_sends_only_that_vane():
    coordinator = FakeCoordinator({"acvs": "0", "achs": "3"})
    vertical = entities(select, coordinator)["Vertical vane"]
    asyncio.run(vertical.async_select_option("2"))
    assert coordinator.sent == [("acvs", 2, None)]
    assert vertical.current_option == "2"
    assert coordinator.data["ac"]["achs"] == "3"


def test_capacity_still_turns_economy_and_powerful_off():
    coordinator = FakeCoordinator({"cnv": 0})
    asyncio.run(entities(select, coordinator)["Capacity"].async_select_option("70%"))
    assert coordinator.sent == [("cnv", 70, {"acem": "off", "acpm": "off"})]


def test_a_vane_the_ac_does_not_report_is_unavailable():
    found = entities(select, FakeCoordinator({"acvs": "1"}))
    assert found["Vertical vane"].available
    assert not found["Horizontal vane"].available


def test_a_refused_command_reaches_home_assistant_as_an_error():
    vertical = entities(select, FakeCoordinator({"acvs": "0"}, fail=True))["Vertical vane"]
    with pytest.raises(HomeAssistantError):
        asyncio.run(vertical.async_select_option("5"))


def test_nanoe_switch_exists_and_is_available_only_when_reported():
    with_nanoe = entities(switch, FakeCoordinator({"acng": "on"}))
    assert with_nanoe["nanoe"].is_on and with_nanoe["nanoe"].available
    without = entities(switch, FakeCoordinator({"ps": "on"}))
    assert not without["nanoe"].available


def test_turning_nanoe_on_does_not_touch_the_exclusive_modes():
    coordinator = FakeCoordinator({"acng": "off", "acpm": "on", "cnv": 70})
    asyncio.run(entities(switch, coordinator)["nanoe"].async_turn_on())
    assert coordinator.sent == [("acng", "on", None)]
    assert coordinator.data["ac"]["acpm"] == "on" and coordinator.data["ac"]["cnv"] == 70


def test_diagnostics_show_the_raw_status_without_secrets():
    coordinator = FakeCoordinator({"rmtmp": "128.25", "acec": "on", "mac": "AA:BB"})
    hass = types.SimpleNamespace(data={"ac_mitm": {"entry": {"coordinator": coordinator}}})
    entry = types.SimpleNamespace(
        entry_id="entry", data={"device_id": "x", "key": "aa", "iv": "bb", "port": 5001}
    )
    out = asyncio.run(diagnostics.async_get_config_entry_diagnostics(hass, entry))
    assert out["status"]["rmtmp"] == "128.25" and out["status"]["acec"] == "on"
    assert out["status"]["mac"] == "**REDACTED**"
    assert out["entry"] == {
        "device_id": "**REDACTED**",
        "key": "**REDACTED**",
        "iv": "**REDACTED**",
        "port": 5001,
    }

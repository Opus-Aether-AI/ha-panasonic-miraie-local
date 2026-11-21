"""Polling keeps running: every exchange is bounded, a short gap keeps the last state, a long one
makes the entities unavailable, and the log says so."""

import asyncio
import logging
import sys
import types

import pytest


def _module(name, **attrs):
    module = sys.modules.setdefault(name, types.ModuleType(name))
    for key, value in attrs.items():
        if not hasattr(module, key):
            setattr(module, key, value)
    return module


class UpdateFailed(Exception):
    pass


class DataUpdateCoordinator:
    def __init__(self, hass, logger, *, name, config_entry=None, update_interval=None):
        self.hass, self.logger, self.name = hass, logger, name
        self.data = None
        self.last_update_success = True

    def async_set_updated_data(self, data):
        self.data = data
        self.last_update_success = True

    async def async_request_refresh(self):
        pass

    async def refresh(self):
        """What Home Assistant's own refresh does with the result."""
        try:
            self.data = await self._async_update_data()
            self.last_update_success = True
        except sys.modules["homeassistant.helpers.update_coordinator"].UpdateFailed:
            self.last_update_success = False


for _name in ("homeassistant", "homeassistant.helpers"):
    _module(_name)
_module(
    "homeassistant.helpers.update_coordinator",
    DataUpdateCoordinator=DataUpdateCoordinator,
    UpdateFailed=UpdateFailed,
)

from custom_components.ac_mitm import coordinator as coordinator_module  # noqa: E402
from custom_components.ac_mitm import native  # noqa: E402
from custom_components.ac_mitm.api import AcMitmApiError  # noqa: E402
from custom_components.ac_mitm.health import STALE_AFTER  # noqa: E402

STATUS = {"ps": "on", "acmd": "cool", "actmp": "23.0", "rmtmp": "05.25"}


class Api:
    def __init__(self):
        self.answers = []

    async def async_get_state(self):
        answer = self.answers.pop(0)
        if answer == "hang":
            await asyncio.sleep(3600)
        if isinstance(answer, Exception):
            raise answer
        return {"ac": dict(answer), "local": {"enabled": True, "available": True}}

    async def async_command(self, action, value, **kwargs):
        return {"ok": True, "ac": {**STATUS, action: value}}


class Clock:
    def __init__(self):
        self.now = 1000.0

    def time(self):
        return self.now


@pytest.fixture
def setup(monkeypatch):
    clock = Clock()
    monkeypatch.setattr(coordinator_module.time, "time", clock.time)
    monkeypatch.setattr(coordinator_module, "POLL_TIMEOUT", 0.05)
    api = Api()
    entry = types.SimpleNamespace(entry_id="e", data={"host": "192.0.2.18"}, title="AC")
    coord = coordinator_module.AcMitmCoordinator(None, api, entry)
    return coord, api, clock


@pytest.mark.asyncio
async def test_a_hung_poll_is_bounded_and_the_next_poll_still_runs(setup, caplog):
    coord, api, clock = setup
    api.answers = [STATUS, "hang", STATUS]
    await coord.refresh()
    clock.now += 10
    with caplog.at_level(logging.INFO):
        await asyncio.wait_for(coord.refresh(), 1)   # returns: the hang is cut short
    assert coord.last_update_success and coord.data["ac"] == STATUS
    assert "missed a poll" in caplog.text and "192.0.2.18" in caplog.text
    clock.now += 10
    with caplog.at_level(logging.INFO):
        await coord.refresh()
    assert "answered again after 1 missed polls" in caplog.text
    assert coord.health.missed == 0


@pytest.mark.asyncio
async def test_a_long_gap_makes_the_ac_unavailable_until_it_answers(setup):
    coord, api, clock = setup
    failed = AcMitmApiError("No valid local status reply")
    api.answers = [STATUS] + [failed] * 8 + [STATUS]
    await coord.refresh()
    for _ in range(STALE_AFTER // 10):
        clock.now += 10
        await coord.refresh()
        assert coord.last_update_success
        assert coord.health.attributes()["last_answer"]
    clock.now += 10
    await coord.refresh()
    assert not coord.last_update_success
    clock.now += 10
    await coord.refresh()
    clock.now += 10
    await coord.refresh()
    assert coord.last_update_success and coord.health.attributes() == {}


@pytest.mark.asyncio
async def test_the_first_poll_failing_is_not_hidden(setup):
    coord, api, _ = setup
    api.answers = [AcMitmApiError("no reply")]
    await coord.refresh()
    assert not coord.last_update_success


@pytest.mark.asyncio
async def test_a_command_readback_is_not_the_unit_moving(setup):
    coord, api, clock = setup
    api.answers = [STATUS, {**STATUS, "actmp": "25.0"}]
    await coord.refresh()
    await coord.async_command("actmp", "25.0")
    clock.now += 10
    await coord.refresh()
    assert coord.health.moved_at == 1000.0


@pytest.mark.asyncio
async def test_a_status_stuck_while_running_is_logged_once(setup, caplog):
    coord, api, clock = setup
    api.answers = [STATUS] * 200
    with caplog.at_level(logging.WARNING):
        for _ in range(190):
            await coord.refresh()
            clock.now += 10
    assert caplog.text.count("isn't following the unit") == 1
    assert not coord.health.following


@pytest.mark.asyncio
async def test_an_exchange_that_never_returns_is_cut_short(monkeypatch):
    class Hanging:
        async def exchange(self, wire, *, expected=None):
            await asyncio.sleep(3600)

    monkeypatch.setattr(native, "EXCHANGE_TIMEOUT", 0.05)
    api = native.NativeApi({"device_id": "fixture-ac", "key": "01" * 32, "iv": "02" * 16}, Hanging())
    with pytest.raises(AcMitmApiError):
        await asyncio.wait_for(api.async_get_state(), 1)
    assert not api.lock.locked()

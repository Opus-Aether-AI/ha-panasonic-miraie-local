"""The apply service: several settings as one command, so the AC beeps once."""

import pytest

from custom_components.ac_mitm.native import NativeApi
from custom_components.ac_mitm.protocol import ProtocolError, apply_settings

from test_local import CONFIG, Device


def test_a_whole_default_is_one_command_with_power_first():
    settings = apply_settings(
        {
            "hvac_mode": "cool",
            "temperature": 24,
            "fan_mode": "Auto",
            "vertical_vane": 2,
            "horizontal_vane": 0,
            "powerful": False,
            "economy": False,
            "display": False,
            "capacity": None,
        }
    )
    assert list(settings)[:2] == ["ps", "acmd"]
    assert settings == {
        "ps": "on",
        "acmd": "cool",
        "actmp": "24.0",
        "acfs": "auto",
        "acvs": 2,
        "achs": 0,
        "acpm": "off",
        "acem": "off",
        "acdc": "off",
    }


def test_fan_only_is_the_acs_fan():
    assert apply_settings({"hvac_mode": "fan_only"}) == {"ps": "on", "acmd": "fan"}


def test_off_takes_nothing_else():
    assert apply_settings({"hvac_mode": "off"}) == {"ps": "off"}
    with pytest.raises(ProtocolError):
        apply_settings({"hvac_mode": "off", "temperature": 24})


def test_powerful_turns_the_others_off_and_capacity_to_auto():
    assert apply_settings({"powerful": True}) == {"acpm": "on", "acem": "off", "acec": "off", "cnv": 0}
    with pytest.raises(ProtocolError):
        apply_settings({"powerful": True, "economy": True})
    with pytest.raises(ProtocolError):
        apply_settings({"economy": True, "capacity": 40})


@pytest.mark.parametrize(
    "fields",
    [{}, {"temperature": 31}, {"vertical_vane": 6}, {"capacity": 45}, {"hvac_mode": "boost"}, {"beep": True}],
)
def test_what_the_ac_would_refuse_is_refused(fields):
    with pytest.raises(ProtocolError):
        apply_settings(fields)


@pytest.mark.asyncio
async def test_it_goes_as_one_packet_and_waits_for_the_readback():
    device = Device()
    api = NativeApi(CONFIG, device)
    settings = apply_settings({"hvac_mode": "cool", "temperature": 25, "fan_mode": "low"})
    action, value = next(iter(settings.items()))
    await api.async_command(action, value, extra={k: v for k, v in settings.items() if k != action})
    sent = [r for r in device.requests if set(r) - {"ki", "cnt", "sid"}]
    assert len(sent) == 1
    assert {k: sent[0][k] for k in ("ps", "acmd", "actmp", "acfs")} == {
        "ps": "on",
        "acmd": "cool",
        "actmp": "25.0",
        "acfs": "low",
    }
    assert device.state["actmp"] == "25.0"

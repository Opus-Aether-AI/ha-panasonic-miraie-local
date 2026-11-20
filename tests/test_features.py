import pytest

from custom_components.ac_mitm.features import (
    REDACT,
    VANE_OPTIONS,
    redact,
    vane_option,
    vane_value,
)
from custom_components.ac_mitm.protocol import ProtocolError, command_settings


@pytest.mark.parametrize(
    "value, option",
    [(0, "Swing"), ("0", "Swing"), (1, "1"), ("3", "3"), (5.0, "5"), ("5", "5")],
)
def test_vane_option_reads_every_position_the_ac_reports(value, option):
    assert vane_option(value) == option


@pytest.mark.parametrize("value", [None, "", "x", -1, 6, "2.5", float("nan")])
def test_vane_option_is_none_for_anything_else(value):
    assert vane_option(value) is None


def test_vane_value_round_trips_every_option():
    for option in VANE_OPTIONS:
        assert vane_option(vane_value(option)) == option


def test_vane_value_rejects_unknown_options():
    with pytest.raises(ValueError):
        vane_value("up")


@pytest.mark.parametrize("key", ["acvs", "achs"])
@pytest.mark.parametrize("option", VANE_OPTIONS)
def test_every_vane_option_makes_a_valid_command(key, option):
    assert command_settings(key, vane_value(option)) == {key: vane_value(option)}


def test_setting_one_vane_leaves_the_other_alone():
    assert command_settings("acvs", 2) == {"acvs": 2}
    assert command_settings("achs", 4) == {"achs": 4}


@pytest.mark.parametrize("value", ["on", "off"])
def test_nanoe_is_a_command(value):
    assert command_settings("acng", value) == {"acng": value}


@pytest.mark.parametrize("key", ["acpm", "acem", "acec", "acdc", "acng"])
@pytest.mark.parametrize("value", ["yes", "1", 1, True, ""])
def test_feature_switches_take_only_on_or_off(key, value):
    with pytest.raises(ProtocolError):
        command_settings(key, value)


def test_redact_hides_secrets_at_any_depth_and_keeps_the_status():
    status = {
        "ps": "on",
        "rmtmp": "25.0",
        "acec": "on",
        "key": "aa" * 32,
        "nested": {"iv": "bb" * 16, "mac": "AA:BB", "acvs": 0},
        "list": [{"token": "t"}, {"cnv": 40}],
    }
    out = redact(status)
    assert out["ps"] == "on" and out["rmtmp"] == "25.0" and out["acec"] == "on"
    assert out["key"] == out["nested"]["iv"] == out["nested"]["mac"] == "**REDACTED**"
    assert out["nested"]["acvs"] == 0
    assert out["list"] == [{"token": "**REDACTED**"}, {"cnv": 40}]
    assert status["key"] == "aa" * 32, "the original is untouched"


def test_redact_covers_what_an_entry_stores():
    for key in ("key", "iv", "device_id", "mac", "host", "password", "token"):
        assert key in REDACT

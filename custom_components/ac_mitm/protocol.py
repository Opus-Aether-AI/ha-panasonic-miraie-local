"""Panasonic native UDP framing, independent of Home Assistant."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
import json

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class ProtocolError(Exception):
    """A packet or command is invalid."""


def tlv(kind: int, value: bytes) -> bytes:
    return bytes([kind]) + len(value).to_bytes(2, "big") + value


class Protocol:
    def __init__(self, device_id: str, key: str, iv: str):
        self.device_id = device_id.encode("ascii")
        self.key = bytes.fromhex(key)
        self.iv = bytes.fromhex(iv)
        if len(self.key) != 32 or len(self.iv) != 16 or not self.device_id:
            raise ProtocolError("Invalid device identifier or AES key/IV length")

    def encode(self, settings: dict | None = None) -> bytes:
        raw = json.dumps(
            {"ki": 1, "cnt": "an", "sid": "1", **(settings or {})}, separators=(",", ":")
        ).encode()
        raw += b"\0" * (-len(raw) % 16)
        enc = Cipher(algorithms.AES(self.key), modes.CBC(self.iv)).encryptor()
        return tlv(0, self.device_id) + tlv(1, enc.update(raw) + enc.finalize())

    def decrypt(self, wire: bytes) -> bytes:
        fields = {}
        offset = 0
        while offset < len(wire):
            if offset + 3 > len(wire):
                raise ProtocolError("Truncated TLV header")
            kind, size = wire[offset], int.from_bytes(wire[offset + 1 : offset + 3], "big")
            offset += 3
            if kind in fields or offset + size > len(wire):
                raise ProtocolError("Invalid TLV field")
            fields[kind] = wire[offset : offset + size]
            offset += size
        if fields.get(0) != self.device_id or not fields.get(2) or len(fields[2]) % 16:
            raise ProtocolError("Unexpected device or ciphertext")
        dec = Cipher(algorithms.AES(self.key), modes.CBC(self.iv)).decryptor()
        return (dec.update(fields[2]) + dec.finalize()).rstrip(b"\0")

    def decode(self, wire: bytes) -> dict:
        try:
            result = json.loads(self.decrypt(wire))
        except (ValueError, UnicodeError) as err:
            raise ProtocolError("Invalid decrypted status") from err
        if not isinstance(result, dict) or "ps" not in result or "actmp" not in result:
            raise ProtocolError("Incomplete AC status")
        return result


def command_settings(action: str, value, extra: dict | None = None) -> dict:
    allowed = {"ps", "acmd", "actmp", "acfs", "acvs", "achs", "acpm", "acem", "acec", "acdc", "cnv"}
    if (
        action not in allowed
        or not isinstance(extra or {}, dict)
        or set(extra or {}) - allowed
        or action in (extra or {})
    ):
        raise ProtocolError("Unsupported command")
    settings = {action: value, **(extra or {})}
    for key in ("acvs", "achs", "cnv"):
        if key in settings:
            number = float(settings[key])
            if not number.is_integer():
                raise ProtocolError("Position/capacity must be an integer")
            settings[key] = int(number)
            if key != "cnv" and not 0 <= settings[key] <= 5:
                raise ProtocolError("Swing position must be 0–5")
    if "cnv" in settings and settings["cnv"] not in [0, 40, 55, 70, 80, 90, 100, 110]:
        raise ProtocolError("Unsupported capacity")
    if "ps" in settings and settings["ps"] not in ["on", "off"]:
        raise ProtocolError("Invalid power state")
    if "actmp" in settings and not 16 <= float(settings["actmp"]) <= 30:
        raise ProtocolError("Temperature must be 16–30°C")
    return settings


# The apply service's fields, and the AC's key for each
APPLY_KEYS = {
    "hvac_mode": "acmd",
    "temperature": "actmp",
    "fan_mode": "acfs",
    "vertical_vane": "acvs",
    "horizontal_vane": "achs",
    "powerful": "acpm",
    "economy": "acem",
    "coil_cleaning": "acec",
    "nanoe": "acng",
    "display": "acdc",
    "capacity": "cnv",
}
APPLY_MODES = {"auto": "auto", "cool": "cool", "heat": "heat", "dry": "dry", "fan_only": "fan"}
_EXCLUSIVE = ("acpm", "acem", "acec")


def apply_settings(fields: dict) -> dict:
    """Several settings as one command, so the AC beeps once: the apply service.

    `hvac_mode` "off" turns the AC off; any other mode also turns it on. On/off features take a
    boolean (or "on"/"off"). Powerful, Economy and coil cleaning exclude one another, and one of
    them on sets the capacity back to Auto, as each one's switch does. Returns the settings in the
    order they go: power first. Raises ProtocolError for anything the AC wouldn't take.
    """
    settings: dict = {}
    for name, value in fields.items():
        if value is None:
            continue
        if name not in APPLY_KEYS:
            raise ProtocolError(f"Unknown setting {name}")
        key = APPLY_KEYS[name]
        if name == "hvac_mode":
            if value == "off":
                settings["ps"] = "off"
                continue
            if value not in APPLY_MODES:
                raise ProtocolError(f"Unknown mode {value}")
            settings["ps"], settings[key] = "on", APPLY_MODES[value]
        elif name == "temperature":
            settings[key] = str(float(value))
        elif name == "fan_mode":
            settings[key] = str(value).lower()
        elif key in ("acvs", "achs", "cnv"):
            settings[key] = value
        elif isinstance(value, bool):
            settings[key] = "on" if value else "off"
        else:
            settings[key] = str(value).lower()
    if settings.get("ps") == "off" and len(settings) > 1:
        raise ProtocolError("Turning the AC off takes no other settings")
    on = [key for key in _EXCLUSIVE if settings.get(key) == "on"]
    if len(on) > 1:
        raise ProtocolError("Powerful, Economy and coil cleaning exclude one another")
    if on:
        for key in _EXCLUSIVE:
            settings.setdefault(key, "off")
        if float(settings.setdefault("cnv", 0)) != 0:
            raise ProtocolError(f"{on[0]} on needs the capacity at Auto")
    if not settings:
        raise ProtocolError("Nothing to apply")
    ordered = {"ps": settings.pop("ps")} if "ps" in settings else {}
    ordered.update(settings)
    action, value = next(iter(ordered.items()))
    return command_settings(action, value, {k: v for k, v in ordered.items() if k != action})


def room_temperature(value) -> float | None:
    """Return the room temperature in °C from an ``rmtmp`` value, or None.

    Most units report a plain value in 0.5 °C steps ("27.0", "24.5"). Some
    firmware (seen on CS-CU-NU18BKY5WX, 3.02) packs unrelated data in front and
    the whole degrees after the point: "128.25" -> 25, "01.26" -> 26. Plain
    values never have hundredths, so the fraction alone tells the formats apart.
    "0.0" means no reading yet; anything outside 0–60 °C is not a room reading.
    """
    try:
        number = Decimal(str(value).strip())
    except (InvalidOperation, ValueError):
        return None
    if not number.is_finite():
        return None
    fraction = number % 1
    if fraction not in (0, Decimal("0.5")):
        number = (fraction * 100).to_integral_value()
    return float(number) if 0 < number < 60 else None


def matches(state: dict, settings: dict) -> bool:
    for key, value in settings.items():
        if key not in state:
            return False
        try:
            if float(state[key]) == float(value):
                continue
        except (ValueError, TypeError):
            pass
        if str(state[key]).lower() != str(value).lower():
            return False
    return True

"""A stand-in for Panasonic's MirAIe MQTT broker, inside the house.

Why it exists: on a CS-CU-EU18CKY5XFM (firmware 3.02, November 2026) the status the AC serves over
local UDP follows the unit only while its Wi-Fi module holds an MQTT session with MirAIe. With
`mqtt.miraie.in`, `app.miraie.in` and `auth.miraie.in` blocked in DNS, local control kept working,
but the room reading froze and changes made on the IR remote never showed; unblocking brought both
back at once.

What it does: a DNS rewrite points `mqtt.miraie.in` at this server. It completes TLS with a
certificate of its own, accepts the AC's MQTT connection whatever its credentials, acknowledges
what MQTT requires, and hands every message the AC publishes to a callback. Nothing leaves the
house unless `relay` is given, which passes the session on to the real broker for study.

The open question is whether the AC accepts a certificate MirAIe didn't sign. The server reports
the answer either way, so one test settles it: `tls_ok`, or `tls_failed` with the AC's own alert
and a verdict.

Pure asyncio and the standard library (plus `cryptography` or the `openssl` command, only to make
the certificate); no Home Assistant imports. MQTT 3.1, 3.1.1 and 5 are understood.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
import datetime
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import tempfile
import time
from typing import Any

MIRAIE_HOSTS = ("mqtt.miraie.in", "app.miraie.in", "auth.miraie.in")
MQTT_TLS_PORT = 8883

CONNECT, CONNACK, PUBLISH, PUBACK, PUBREC, PUBREL, PUBCOMP = 1, 2, 3, 4, 5, 6, 7
SUBSCRIBE, SUBACK, UNSUBSCRIBE, UNSUBACK, PINGREQ, PINGRESP, DISCONNECT, AUTH = range(8, 16)
PACKET_NAMES = {
    CONNECT: "CONNECT", CONNACK: "CONNACK", PUBLISH: "PUBLISH", PUBACK: "PUBACK",
    PUBREC: "PUBREC", PUBREL: "PUBREL", PUBCOMP: "PUBCOMP", SUBSCRIBE: "SUBSCRIBE",
    SUBACK: "SUBACK", UNSUBSCRIBE: "UNSUBSCRIBE", UNSUBACK: "UNSUBACK", PINGREQ: "PINGREQ",
    PINGRESP: "PINGRESP", DISCONNECT: "DISCONNECT", AUTH: "AUTH",
}
MAX_PACKET = 256 * 1024
HELLO_LIMIT = 16 * 1024


class MqttError(Exception):
    """A packet is malformed, or too large to be one the AC would send."""


# ---------------------------------------------------------------------------------------------
# MQTT framing


def encode_length(size: int) -> bytes:
    """MQTT's variable-length integer."""
    if not 0 <= size <= 268_435_455:
        raise MqttError("Length out of range")
    out = bytearray()
    while True:
        size, digit = divmod(size, 128)
        out.append(digit | (0x80 if size else 0))
        if not size:
            return bytes(out)


def frame(kind: int, flags: int, body: bytes = b"") -> bytes:
    return bytes([kind << 4 | flags]) + encode_length(len(body)) + body


async def read_packet(read_exactly: Callable) -> tuple[int, int, bytes, bytes]:
    """One packet: (type, flags, body, the raw bytes as they came)."""
    head = await read_exactly(1)
    size, multiplier, raw_length = 0, 1, b""
    for _ in range(4):
        byte = await read_exactly(1)
        raw_length += byte
        size += (byte[0] & 0x7F) * multiplier
        if not byte[0] & 0x80:
            break
        multiplier *= 128
    else:
        raise MqttError("Remaining length longer than four bytes")
    if size > MAX_PACKET:
        raise MqttError(f"Packet of {size} bytes")
    body = await read_exactly(size) if size else b""
    return head[0] >> 4, head[0] & 0x0F, body, head + raw_length + body


class _Body:
    """Reads the fields of one packet body, failing on truncation instead of guessing."""

    def __init__(self, data: bytes):
        self.data, self.at = data, 0

    def take(self, size: int) -> bytes:
        if self.at + size > len(self.data):
            raise MqttError("Truncated packet")
        chunk = self.data[self.at : self.at + size]
        self.at += size
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def varint(self) -> int:
        value, multiplier = 0, 1
        for _ in range(4):
            byte = self.u8()
            value += (byte & 0x7F) * multiplier
            if not byte & 0x80:
                return value
            multiplier *= 128
        raise MqttError("Variable integer longer than four bytes")

    def binary(self) -> bytes:
        return self.take(self.u16())

    def string(self) -> str:
        try:
            return self.binary().decode("utf-8")
        except UnicodeDecodeError as err:
            raise MqttError("Invalid UTF-8 string") from err

    def skip_properties(self) -> None:
        self.take(self.varint())

    def rest(self) -> bytes:
        chunk = self.data[self.at :]
        self.at = len(self.data)
        return chunk


def _string(text: str) -> bytes:
    raw = text.encode("utf-8")
    return len(raw).to_bytes(2, "big") + raw


def parse_connect(body: bytes) -> dict[str, Any]:
    """CONNECT's fields. The password comes back as bytes: callers must never log it."""
    b = _Body(body)
    protocol = b.string()
    level = b.u8()
    if (protocol, level) not in (("MQIsdp", 3), ("MQTT", 4), ("MQTT", 5)):
        raise MqttError(f"Unknown protocol {protocol!r} level {level}")
    flags = b.u8()
    keepalive = b.u16()
    if level == 5:
        b.skip_properties()
    result: dict[str, Any] = {
        "protocol": protocol,
        "level": level,
        "keepalive": keepalive,
        "clean_session": bool(flags & 0x02),
        "client_id": b.string(),
    }
    if flags & 0x04:
        if level == 5:
            b.skip_properties()
        result["will_topic"] = b.string()
        result["will_payload"] = b.binary()
        result["will_qos"] = (flags >> 3) & 0x03
        result["will_retain"] = bool(flags & 0x20)
    if flags & 0x80:
        result["username"] = b.string()
    if flags & 0x40:
        result["password"] = b.binary()
    return result


def parse_publish(flags: int, body: bytes, level: int) -> dict[str, Any]:
    b = _Body(body)
    qos = (flags >> 1) & 0x03
    if qos == 3:
        raise MqttError("PUBLISH with QoS 3")
    topic = b.string()
    packet_id = b.u16() if qos else None
    if level == 5:
        b.skip_properties()
    return {
        "topic": topic,
        "qos": qos,
        "retain": bool(flags & 0x01),
        "dup": bool(flags & 0x08),
        "packet_id": packet_id,
        "payload": b.rest(),
    }


def parse_subscribe(body: bytes, level: int) -> tuple[int, list[tuple[str, int]]]:
    b = _Body(body)
    packet_id = b.u16()
    if level == 5:
        b.skip_properties()
    filters = []
    while b.at < len(b.data):
        filters.append((b.string(), b.u8() & 0x03))
    if not filters:
        raise MqttError("SUBSCRIBE without a topic")
    return packet_id, filters


def parse_unsubscribe(body: bytes, level: int) -> tuple[int, list[str]]:
    b = _Body(body)
    packet_id = b.u16()
    if level == 5:
        b.skip_properties()
    filters = []
    while b.at < len(b.data):
        filters.append(b.string())
    return packet_id, filters


def packet_id_of(body: bytes) -> int:
    return _Body(body).u16()


def connack(level: int, code: int = 0) -> bytes:
    return frame(CONNACK, 0, b"\x00" + bytes([code]) + (b"\x00" if level == 5 else b""))


def suback(level: int, packet_id: int, granted: list[int]) -> bytes:
    props = b"\x00" if level == 5 else b""
    return frame(SUBACK, 0, packet_id.to_bytes(2, "big") + props + bytes(granted))


def unsuback(level: int, packet_id: int, count: int) -> bytes:
    extra = b"\x00" + b"\x00" * count if level == 5 else b""
    return frame(UNSUBACK, 0, packet_id.to_bytes(2, "big") + extra)


def ack(kind: int, packet_id: int) -> bytes:
    """PUBACK, PUBREC or PUBCOMP (flags 0), or PUBREL (flags 2)."""
    return frame(kind, 2 if kind == PUBREL else 0, packet_id.to_bytes(2, "big"))


def publish_packet(
    topic: str, payload: bytes, level: int = 4, qos: int = 0, packet_id: int = 0,
    retain: bool = False,
) -> bytes:
    body = _string(topic)
    if qos:
        body += packet_id.to_bytes(2, "big")
    if level == 5:
        body += b"\x00"
    return frame(PUBLISH, qos << 1 | int(retain), body + payload)


def connect_packet(
    client_id: str, username: str | None = None, password: bytes | None = None,
    keepalive: int = 60, level: int = 4, clean: bool = True,
) -> bytes:
    """A client's CONNECT: for tests and for checking the server by hand."""
    protocol = "MQIsdp" if level == 3 else "MQTT"
    flags = (0x02 if clean else 0) | (0x80 if username is not None else 0)
    flags |= 0x40 if password is not None else 0
    body = _string(protocol) + bytes([level, flags]) + keepalive.to_bytes(2, "big")
    if level == 5:
        body += b"\x00"
    body += _string(client_id)
    if username is not None:
        body += _string(username)
    if password is not None:
        body += len(password).to_bytes(2, "big") + password
    return frame(CONNECT, 0, body)


def topic_matches(pattern: str, topic: str) -> bool:
    """MQTT filter matching with `+` and `#`."""
    want, have = pattern.split("/"), topic.split("/")
    for index, part in enumerate(want):
        if part == "#":
            return True
        if index >= len(have) or (part != "+" and part != have[index]):
            return False
    return len(want) == len(have)


# ---------------------------------------------------------------------------------------------
# What the AC says before TLS: its ClientHello

TLS_VERSIONS = {
    0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
}


def _grease(value: int) -> bool:
    return value & 0x0F0F == 0x0A0A and value >> 8 == value & 0xFF


def hello_complete(data: bytes) -> bool:
    """Whether `data` holds the whole first TLS record (or is clearly not TLS)."""
    if not data or data[0] != 0x16:
        return bool(data)
    return len(data) >= 5 and len(data) >= 5 + int.from_bytes(data[3:5], "big")


def parse_client_hello(data: bytes) -> dict[str, Any] | None:
    """The parts of a TLS ClientHello that say what the client can do. None if it isn't one."""
    if len(data) < 9 or data[0] != 0x16 or data[5] != 0x01:
        return None
    body = data[5 : 5 + int.from_bytes(data[3:5], "big")]
    b = _Body(body)
    try:
        b.take(4)
        client_version = b.u16()
        b.take(32)
        b.take(b.u8())
        cipher_bytes = b.take(b.u16())
        b.take(b.u8())
        ciphers = [
            int.from_bytes(cipher_bytes[i : i + 2], "big") for i in range(0, len(cipher_bytes), 2)
        ]
        result: dict[str, Any] = {
            "record_version": TLS_VERSIONS.get(int.from_bytes(data[1:3], "big"), "unknown"),
            "client_version": TLS_VERSIONS.get(client_version, f"0x{client_version:04x}"),
            "ciphers": [f"0x{c:04x}" for c in ciphers if not _grease(c)],
            "sni": None,
            "alpn": [],
            "versions": [],
            "extensions": [],
        }
        if b.at + 2 <= len(body):
            ext = _Body(b.take(b.u16()))
            while ext.at + 4 <= len(ext.data):
                kind, payload = ext.u16(), ext.binary()
                if _grease(kind):
                    continue
                result["extensions"].append(kind)
                inner = _Body(payload)
                if kind == 0:  # server_name
                    inner.u16()
                    if inner.u8() == 0:
                        result["sni"] = inner.string()
                elif kind == 1:  # max_fragment_length
                    result["max_fragment_length"] = {1: 512, 2: 1024, 3: 2048, 4: 4096}.get(
                        inner.u8()
                    )
                elif kind == 16:  # ALPN
                    names = _Body(inner.binary())
                    while names.at < len(names.data):
                        result["alpn"].append(names.take(names.u8()).decode("ascii", "replace"))
                elif kind == 43:  # supported_versions
                    listed = inner.take(inner.u8())
                    for i in range(0, len(listed), 2):
                        value = int.from_bytes(listed[i : i + 2], "big")
                        if not _grease(value):
                            result["versions"].append(TLS_VERSIONS.get(value, f"0x{value:04x}"))
        if not result["versions"]:
            result["versions"] = [result["client_version"]]
        return result
    except (MqttError, UnicodeDecodeError):
        return {"truncated": True}


# ---------------------------------------------------------------------------------------------
# Streams: TLS run by hand over memory BIOs, so the ClientHello can be read first


class StreamClosed(Exception):
    """The other end closed the connection."""


class PlainStream:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, first=b""):
        self.reader, self.writer, self.buffer = reader, writer, bytearray(first)

    async def read_exactly(self, size: int) -> bytes:
        while len(self.buffer) < size:
            chunk = await self.reader.read(65536)
            if not chunk:
                raise StreamClosed
            self.buffer += chunk
        out = bytes(self.buffer[:size])
        del self.buffer[:size]
        return out

    async def write(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()

    def close(self) -> None:
        self.writer.close()


class TlsStream(PlainStream):
    """Server-side TLS over memory BIOs."""

    def __init__(self, reader, writer, tls: ssl.SSLObject, incoming, outgoing):
        super().__init__(reader, writer)
        self.tls, self.incoming, self.outgoing = tls, incoming, outgoing
        self.server_flight_sent = False

    @classmethod
    def server(cls, reader, writer, context: ssl.SSLContext) -> TlsStream:
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        return cls(reader, writer, context.wrap_bio(incoming, outgoing, server_side=True),
                   incoming, outgoing)

    async def handshake(self, first: bytes) -> None:
        """Completes the server side of the handshake, `first` being what already arrived."""
        self.incoming.write(first)
        while True:
            try:
                self.tls.do_handshake()
                await self._flush()
                return
            except ssl.SSLWantReadError:
                await self._flush()
                await self._fill()
            except ssl.SSLError:
                await self._flush()
                raise

    async def _flush(self) -> None:
        data = self.outgoing.read()
        if data:
            self.server_flight_sent = True
            self.writer.write(data)
            await self.writer.drain()

    async def _fill(self) -> None:
        chunk = await self.reader.read(65536)
        if not chunk:
            raise StreamClosed
        self.incoming.write(chunk)

    async def read_exactly(self, size: int) -> bytes:
        while len(self.buffer) < size:
            try:
                chunk = self.tls.read(65536)
            except ssl.SSLWantReadError:  # a record without data, or none yet: wait for more
                await self._flush()
                await self._fill()
                continue
            except ssl.SSLZeroReturnError as err:
                raise StreamClosed from err
            if not chunk:  # what read() returns once the client's close_notify arrives
                raise StreamClosed
            self.buffer += chunk
        out = bytes(self.buffer[:size])
        del self.buffer[:size]
        return out

    async def write(self, data: bytes) -> None:
        self.tls.write(data)
        await self._flush()

    def close(self) -> None:
        """Sends close_notify where TLS still stands, so a polite client isn't left waiting."""
        try:
            self.tls.unwrap()
        except (ssl.SSLError, ValueError):
            pass
        try:
            data = self.outgoing.read()
            if data and not self.writer.is_closing():
                self.writer.write(data)
        except OSError:
            pass
        self.writer.close()

    @property
    def version(self) -> str | None:
        return self.tls.version()

    @property
    def cipher(self) -> str | None:
        cipher = self.tls.cipher()
        return cipher[0] if cipher else None


CHECKS_CERTIFICATE = "checks_certificate"
VERDICTS = {
    "TLSV1_ALERT_UNKNOWN_CA": CHECKS_CERTIFICATE,
    "SSLV3_ALERT_BAD_CERTIFICATE": CHECKS_CERTIFICATE,
    "SSLV3_ALERT_CERTIFICATE_UNKNOWN": CHECKS_CERTIFICATE,
    "TLSV1_ALERT_ACCESS_DENIED": CHECKS_CERTIFICATE,
    "TLSV1_ALERT_DECRYPT_ERROR": CHECKS_CERTIFICATE,
    "SSLV3_ALERT_UNSUPPORTED_CERTIFICATE": "certificate_type",
    "TLSV1_ALERT_INTERNAL_ERROR": "client_internal_error",
    "NO_SHARED_CIPHER": "no_shared_cipher",
    "UNSUPPORTED_PROTOCOL": "no_shared_version",
    "WRONG_VERSION_NUMBER": "no_shared_version",
    "VERSION_TOO_LOW": "no_shared_version",
    "TLSV1_ALERT_PROTOCOL_VERSION": "no_shared_version",
    "SSLV3_ALERT_HANDSHAKE_FAILURE": "handshake_failure",
}
VERDICT_TEXT = {
    CHECKS_CERTIFICATE: "the AC checks the certificate: a stand-in can't answer for MirAIe",
    "closed_after_certificate": (
        "the AC hung up after seeing our certificate: it almost certainly checks it"
    ),
    "certificate_type": "the AC refused this kind of certificate: try another key type",
    "no_shared_cipher": "no cipher in common: the server's cipher list needs widening",
    "no_shared_version": "no TLS version in common",
    "handshake_failure": "the AC aborted the handshake: cipher or certificate (try another key)",
    "client_internal_error": "the AC failed inside its own TLS code",
    "closed_before_certificate": "the AC hung up before our certificate went out",
    "timeout": "the AC stopped answering during the handshake",
    "other": "the handshake failed for another reason (see `reason`)",
}


def tls_verdict(reason: str | None, server_flight_sent: bool) -> str:
    if reason in VERDICTS:
        return VERDICTS[reason]
    if reason == "closed":
        return "closed_after_certificate" if server_flight_sent else "closed_before_certificate"
    return reason if reason in VERDICT_TEXT else "other"


# ---------------------------------------------------------------------------------------------
# Certificates


def server_context(certfile: str | os.PathLike, keyfile: str | os.PathLike) -> ssl.SSLContext:
    """TLS as permissive as the server side allows, for an embedded client's sake."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    except (ValueError, AttributeError):
        pass
    try:
        context.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        context.set_ciphers("ALL")
    context.load_cert_chain(certfile, keyfile)
    return context


def make_certificate(directory: str | os.PathLike, names=MIRAIE_HOSTS) -> tuple[Path, Path]:
    """A self-signed RSA-2048 certificate for MirAIe's names, made once and kept.

    It is valid from 2020 to 2049, so an AC whose clock isn't set yet still finds it current.
    The key is written owner-only. Uses `cryptography` when installed, else the openssl command.
    """
    folder = Path(directory)
    folder.mkdir(parents=True, exist_ok=True)
    cert, key = folder / "standin-cert.pem", folder / "standin-key.pem"
    if cert.exists() and key.exists():
        return cert, key
    try:
        _make_with_cryptography(cert, key, names)
    except ImportError:
        _make_with_openssl(cert, key, names)
    os.chmod(key, 0o600)
    return cert, key


def _make_with_cryptography(cert: Path, key: Path, names) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    built = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2049, 12, 31, tzinfo=datetime.UTC))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .sign(private, hashes.SHA256())
    )
    fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    cert.write_bytes(built.public_bytes(serialization.Encoding.PEM))


def _make_with_openssl(cert: Path, key: Path, names) -> None:
    openssl = shutil.which("openssl")
    if not openssl:
        raise RuntimeError("Making the certificate needs the cryptography package or openssl")
    with tempfile.NamedTemporaryFile("w", suffix=".cnf", delete=False) as conf:
        conf.write(
            "[req]\ndistinguished_name=dn\nprompt=no\nx509_extensions=ext\n"
            f"[dn]\nCN={names[0]}\n[ext]\nbasicConstraints=critical,CA:FALSE\n"
            "subjectAltName=" + ",".join(f"DNS:{n}" for n in names) + "\n"
        )
    base = [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
            "-keyout", str(key), "-out", str(cert), "-config", conf.name]
    try:
        try:  # OpenSSL 3.4+ can date it from 2020
            subprocess.run(base + ["-not_before", "20200101000000Z", "-not_after",
                                   "20491231235959Z"], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            subprocess.run(base + ["-days", "8400"], check=True, capture_output=True)
    finally:
        os.unlink(conf.name)


# ---------------------------------------------------------------------------------------------
# Logging without leaking

SECRET_KEY = re.compile(r"pass|pwd|token|secret|cred|^key$|^iv$|auth|sign", re.IGNORECASE)


def redact(value: Any) -> Any:
    """Masks values under keys that look secret, at any depth."""
    if isinstance(value, dict):
        return {
            k: ("**REDACTED**" if SECRET_KEY.search(str(k)) else redact(v)) for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def decode_payload(payload: bytes) -> Any:
    """JSON where it is JSON (redacted), else a short printable preview."""
    try:
        return redact(json.loads(payload))
    except (ValueError, UnicodeDecodeError):
        text = payload[:200].decode("utf-8", "replace")
        return {"text": text, "bytes": len(payload)}


# ---------------------------------------------------------------------------------------------
# The server


@dataclass
class Session:
    peer: str
    stream: PlainStream
    level: int = 4
    client_id: str = ""
    subscriptions: dict[str, int] = field(default_factory=dict)
    connected_at: float = field(default_factory=time.time)
    next_id: int = 0

    def packet_id(self) -> int:
        self.next_id = self.next_id % 65535 + 1
        return self.next_id


Event = Callable[[str, dict], None]


class StandIn:
    """Answers the AC's MirAIe MQTT session inside the house.

    `on_event(kind, data)` hears everything worth knowing, as plain dicts: `refused`, `tcp_open`,
    `client_hello`, `plaintext`, `tls_ok`, `tls_failed`, `mqtt_connect`, `mqtt_subscribe`,
    `mqtt_unsubscribe`, `mqtt_publish`, `status`, `ping`, `mqtt_disconnect`, `mqtt_error`,
    `closed`, and in relay mode `relay_open`, `relay_failed` and `relay_packet`. A CONNECT's
    password is reported by length only. `on_status(session, topic, status)` gets each status the
    AC publishes (a topic ending `/status`), decoded.
    """

    def __init__(
        self,
        context: ssl.SSLContext,
        on_event: Event,
        *,
        allow: set[str] | None = None,
        on_status: Callable | None = None,
        relay: tuple[str, int] | None = None,
        relay_context: ssl.SSLContext | None = None,
        relay_hostname: str = MIRAIE_HOSTS[0],
        handshake_timeout: float = 20.0,
    ):
        self.context, self.on_event, self.allow = context, on_event, allow
        self.on_status, self.relay = on_status, relay
        self.relay_context = relay_context or ssl.create_default_context()
        self.relay_hostname = relay_hostname
        self.handshake_timeout = handshake_timeout
        self.sessions: list[Session] = []
        self.server: asyncio.Server | None = None
        self._writers: set[asyncio.StreamWriter] = set()

    def emit(self, kind: str, **data) -> None:
        try:
            self.on_event(kind, {"time": time.time(), **data})
        except Exception:  # noqa: BLE001 - a logging fault must not drop the AC's session
            pass

    async def start(self, host: str = "0.0.0.0", port: int = MQTT_TLS_PORT) -> asyncio.Server:
        self.server = await asyncio.start_server(self._handle, host, port)
        return self.server

    async def close(self) -> None:
        """Stops listening and drops every connection, finished or not."""
        if self.server:
            self.server.close()
        for writer in list(self._writers):
            writer.close()
        if self.server:
            try:
                async with asyncio.timeout(5):
                    await self.server.wait_closed()
            except TimeoutError:
                pass

    async def publish(self, topic: str, payload: bytes | str | dict, qos: int = 0) -> int:
        """Sends a message to every session subscribed to `topic`; returns how many got it."""
        if isinstance(payload, dict):
            payload = json.dumps(payload, separators=(",", ":"))
        if isinstance(payload, str):
            payload = payload.encode()
        sent = 0
        for session in list(self.sessions):
            granted = [q for f, q in session.subscriptions.items() if topic_matches(f, topic)]
            if not granted:
                continue
            level_qos = min(qos, max(granted))
            packet_id = session.packet_id() if level_qos else 0
            try:
                await session.stream.write(
                    publish_packet(topic, payload, session.level, level_qos, packet_id)
                )
                sent += 1
            except (OSError, ssl.SSLError, StreamClosed):
                pass
        return sent

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = (writer.get_extra_info("peername") or ("?",))[0]
        if self.allow is not None and peer not in self.allow:
            self.emit("refused", peer=peer)
            writer.close()
            return
        opened, reason = time.time(), "closed"
        self.emit("tcp_open", peer=peer)
        stream: PlainStream | None = None
        self._writers.add(writer)
        try:
            first = b""
            async with asyncio.timeout(self.handshake_timeout):
                while not hello_complete(first) and len(first) < HELLO_LIMIT:
                    chunk = await reader.read(HELLO_LIMIT)
                    if not chunk:
                        raise StreamClosed
                    first += chunk
            hello = parse_client_hello(first)
            if hello is None:
                self.emit("plaintext", peer=peer, first_byte=f"0x{first[0]:02x}")
                stream = PlainStream(reader, writer, first)
            else:
                self.emit("client_hello", peer=peer, **hello)
                stream = await self._tls(reader, writer, first, peer)
                if stream is None:
                    reason = "tls_failed"
                    return
            if self.relay:
                reason = await self._relay(stream, peer)
            else:
                reason = await self._serve(stream, peer)
        except StreamClosed:
            reason = "closed"
        except TimeoutError:
            reason = "timeout"
        except MqttError as err:
            reason = "mqtt_error"
            self.emit("mqtt_error", peer=peer, error=str(err))
        except (OSError, ssl.SSLError) as err:
            reason = f"error: {type(err).__name__}"
        finally:
            self._writers.discard(writer)
            if stream is not None:
                stream.close()
            writer.close()
            self.emit("closed", peer=peer, reason=reason, seconds=round(time.time() - opened, 1))

    async def _tls(self, reader, writer, first: bytes, peer: str) -> TlsStream | None:
        stream = TlsStream.server(reader, writer, self.context)
        try:
            async with asyncio.timeout(self.handshake_timeout):
                await stream.handshake(first)
        except ssl.SSLError as err:
            reason = err.reason or type(err).__name__
        except StreamClosed:
            reason = "closed"
        except TimeoutError:
            reason = "timeout"
        else:
            self.emit("tls_ok", peer=peer, version=stream.version, cipher=stream.cipher)
            return stream
        verdict = tls_verdict(reason, stream.server_flight_sent)
        self.emit("tls_failed", peer=peer, reason=reason, verdict=verdict,
                  certificate_sent=stream.server_flight_sent,
                  meaning=VERDICT_TEXT.get(verdict, VERDICT_TEXT["other"]))
        return None

    async def _serve(self, stream: PlainStream, peer: str) -> str:
        kind, _, body, _ = await asyncio.wait_for(
            read_packet(stream.read_exactly), self.handshake_timeout
        )
        if kind != CONNECT:
            raise MqttError(f"First packet was {PACKET_NAMES.get(kind, kind)}, not CONNECT")
        connect = parse_connect(body)
        session = Session(peer, stream, connect["level"], connect["client_id"])
        self.emit("mqtt_connect", peer=peer, **_connect_report(connect))
        await stream.write(connack(session.level))
        self.sessions.append(session)
        keepalive = connect["keepalive"]
        try:
            while True:
                timeout = keepalive * 1.5 if keepalive else None
                try:
                    kind, flags, body, _ = await asyncio.wait_for(
                        read_packet(stream.read_exactly), timeout
                    )
                except TimeoutError:
                    return "keepalive"
                if kind == PUBLISH:
                    await self._incoming_publish(session, flags, body)
                elif kind == PUBREL:
                    await stream.write(ack(PUBCOMP, packet_id_of(body)))
                elif kind in (PUBACK, PUBCOMP):
                    pass
                elif kind == PUBREC:
                    await stream.write(ack(PUBREL, packet_id_of(body)))
                elif kind == SUBSCRIBE:
                    packet_id, filters = parse_subscribe(body, session.level)
                    granted = [min(qos, 1) for _, qos in filters]
                    for (topic, _), qos in zip(filters, granted):
                        session.subscriptions[topic] = qos
                    self.emit("mqtt_subscribe", peer=peer, topics=[t for t, _ in filters],
                              qos=granted)
                    await stream.write(suback(session.level, packet_id, granted))
                elif kind == UNSUBSCRIBE:
                    packet_id, filters = parse_unsubscribe(body, session.level)
                    for topic in filters:
                        session.subscriptions.pop(topic, None)
                    self.emit("mqtt_unsubscribe", peer=peer, topics=filters)
                    await stream.write(unsuback(session.level, packet_id, len(filters)))
                elif kind == PINGREQ:
                    self.emit("ping", peer=peer)
                    await stream.write(frame(PINGRESP, 0))
                elif kind == DISCONNECT:
                    self.emit("mqtt_disconnect", peer=peer)
                    return "disconnect"
                else:
                    self.emit("mqtt_error", peer=peer,
                              error=f"Unexpected {PACKET_NAMES.get(kind, kind)}")
        finally:
            self.sessions.remove(session)

    async def _incoming_publish(self, session: Session, flags: int, body: bytes) -> None:
        message = parse_publish(flags, body, session.level)
        payload = decode_payload(message["payload"])
        self.emit("mqtt_publish", peer=session.peer, topic=message["topic"], qos=message["qos"],
                  retain=message["retain"], payload=payload, bytes=len(message["payload"]))
        if message["qos"] == 1:
            await session.stream.write(ack(PUBACK, message["packet_id"]))
        elif message["qos"] == 2:
            await session.stream.write(ack(PUBREC, message["packet_id"]))
        if message["topic"].endswith("/status") and isinstance(payload, dict):
            self.emit("status", peer=session.peer, topic=message["topic"], status=payload)
            if self.on_status:
                try:
                    self.on_status(session, message["topic"], payload)
                except Exception:  # noqa: BLE001 - the session matters more than a listener
                    pass
        for other in list(self.sessions):
            if other is not session:
                granted = [
                    q for f, q in other.subscriptions.items() if topic_matches(f, message["topic"])
                ]
                if granted:
                    try:
                        await other.stream.write(
                            publish_packet(message["topic"], message["payload"], other.level)
                        )
                    except (OSError, ssl.SSLError, StreamClosed):
                        pass

    async def _relay(self, stream: PlainStream, peer: str) -> str:
        """Pass the AC's session on to the real broker, reporting each packet both ways."""
        kind, _, body, raw = await asyncio.wait_for(
            read_packet(stream.read_exactly), self.handshake_timeout
        )
        if kind != CONNECT:
            raise MqttError("First packet was not CONNECT")
        connect = parse_connect(body)
        level = connect["level"]
        self.emit("mqtt_connect", peer=peer, **_connect_report(connect))
        host, port = self.relay
        try:
            cloud_reader, cloud_writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host, port, ssl=self.relay_context, server_hostname=self.relay_hostname
                ),
                self.handshake_timeout,
            )
        except (OSError, ssl.SSLError, TimeoutError) as err:
            self.emit("relay_failed", peer=peer, error=f"{type(err).__name__}: {err}")
            return "relay_failed"
        cloud = PlainStream(cloud_reader, cloud_writer)
        self.emit("relay_open", peer=peer, host=host, port=port)
        await cloud.write(raw)

        async def pump(source: PlainStream, sink: PlainStream, direction: str):
            while True:
                kind, flags, body, raw = await read_packet(source.read_exactly)
                report: dict[str, Any] = {"packet": PACKET_NAMES.get(kind, str(kind))}
                if kind == PUBLISH:
                    message = parse_publish(flags, body, level)
                    report |= {"topic": message["topic"], "qos": message["qos"],
                               "payload": decode_payload(message["payload"])}
                elif kind == CONNACK and len(body) >= 2:
                    report["code"] = body[1]
                elif kind == SUBSCRIBE:
                    report["topics"] = [t for t, _ in parse_subscribe(body, level)[1]]
                self.emit("relay_packet", peer=peer, direction=direction, **report)
                await sink.write(raw)

        tasks = [
            asyncio.create_task(pump(stream, cloud, "ac_to_cloud")),
            asyncio.create_task(pump(cloud, stream, "cloud_to_ac")),
        ]
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                error = task.exception()
                if error and not isinstance(error, StreamClosed):
                    raise error
            return "relay_closed"
        finally:
            for task in tasks:
                task.cancel()
            cloud.close()


def _connect_report(connect: dict) -> dict:
    """CONNECT's fields fit to log: the password by length, the will's payload decoded."""
    report = {k: v for k, v in connect.items() if k not in ("password", "will_payload")}
    report["password_bytes"] = len(connect["password"]) if "password" in connect else None
    if "will_payload" in connect:
        report["will_payload"] = decode_payload(connect["will_payload"])
    return report

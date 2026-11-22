"""The MirAIe stand-in broker, end to end over real TLS sockets on loopback."""

import asyncio
import json
import os
import socket
import ssl

import pytest

from custom_components.ac_mitm import standin as s

STATUS = {"ps": "on", "acmd": "cool", "actmp": "24.0", "rmtmp": "134.23", "ki": 1, "token": "x"}
TOPIC = "user0000000001/home0000000001/device000000001"
PASSWORD = b"the-ac-device-password-never-logged"


@pytest.fixture(scope="module")
def certificate(tmp_path_factory):
    return s.make_certificate(tmp_path_factory.mktemp("cert"))


def insecure():
    """A client that takes any certificate: what the AC must be for the stand-in to work."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


class Recorder:
    def __init__(self):
        self.events, self.statuses = [], []

    def __call__(self, kind, data):
        self.events.append((kind, data))

    def kinds(self):
        return [k for k, _ in self.events]

    def first(self, kind):
        return next(d for k, d in self.events if k == kind)

    async def wait_for(self, kind, timeout=5):
        async with asyncio.timeout(timeout):
            while kind not in self.kinds():
                await asyncio.sleep(0.01)
        return self.first(kind)


async def serve(certificate, **kwargs):
    events = Recorder()
    server = s.StandIn(s.server_context(*certificate), events, **kwargs)
    listener = await server.start("127.0.0.1", 0)
    return server, events, listener.sockets[0].getsockname()[1]


class Client:
    """A minimal MQTT client over our own framing, as the AC would speak it."""

    def __init__(self, reader, writer, level=4):
        self.reader, self.writer, self.level = reader, writer, level

    @classmethod
    async def open(cls, port, context=None, level=4, hostname="mqtt.miraie.in", tls=True):
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=(context or insecure()) if tls else None,
            server_hostname=hostname if tls else None,
        )
        return cls(reader, writer, level)

    async def send(self, data):
        self.writer.write(data)
        await self.writer.drain()

    async def packet(self):
        return await asyncio.wait_for(s.read_packet(self.reader.readexactly), 5)

    async def connect(self, keepalive=60, **kwargs):
        await self.send(s.connect_packet("an0001", "dev0001", PASSWORD, keepalive, self.level,
                                         **kwargs))
        return await self.packet()

    def close(self):
        self.writer.close()


def subscribe(level, packet_id, *topics):
    body = packet_id.to_bytes(2, "big") + (b"\x00" if level == 5 else b"")
    for topic in topics:
        body += s._string(topic) + b"\x01"
    return s.frame(s.SUBSCRIBE, 2, body)


def reader_of(data: bytes):
    buffer = bytearray(data)

    async def read_exactly(size):
        if size > len(buffer):
            raise s.StreamClosed
        chunk = bytes(buffer[:size])
        del buffer[:size]
        return chunk
    return read_exactly


@pytest.mark.parametrize(("size", "length_bytes"),
                         [(0, 1), (127, 1), (128, 2), (16383, 2), (16384, 3), (200_000, 3)])
async def test_remaining_length_round_trips(size, length_bytes):
    assert len(s.encode_length(size)) == length_bytes
    kind, _, body, raw = await s.read_packet(reader_of(s.frame(s.PUBLISH, 0, b"\x01" * size)))
    assert (kind, len(body), len(raw)) == (s.PUBLISH, size, 1 + length_bytes + size)


@pytest.mark.parametrize("size", [s.MAX_PACKET + 1, 268_435_455])
async def test_oversized_packets_are_refused_before_reading(size):
    with pytest.raises(s.MqttError):
        await s.read_packet(reader_of(bytes([0x30]) + s.encode_length(size)))


def test_length_out_of_range():
    with pytest.raises(s.MqttError):
        s.encode_length(268435456)


@pytest.mark.parametrize(("pattern", "topic", "matches"), [
    ("a/b/status", "a/b/status", True),
    ("a/+/status", "a/b/status", True),
    ("a/#", "a/b/c/status", True),
    ("#", "a", True),
    ("a/+", "a/b/c", False),
    ("a/b", "a/b/c", False),
    ("a/b/c", "a/b", False),
])
def test_topic_matching(pattern, topic, matches):
    assert s.topic_matches(pattern, topic) is matches


@pytest.mark.parametrize("level", [3, 4, 5])
def test_connect_fields_every_level(level):
    parsed = s.parse_connect(s.connect_packet("an42", "user", b"secret", 30, level)[2:])
    assert parsed["level"] == level
    assert parsed["protocol"] == ("MQIsdp" if level == 3 else "MQTT")
    assert (parsed["client_id"], parsed["username"], parsed["password"]) == ("an42", "user",
                                                                            b"secret")
    assert parsed["keepalive"] == 30


def test_connect_rejects_unknown_protocol():
    body = s._string("HTTP") + bytes([4, 2]) + b"\x00\x3c" + s._string("x")
    with pytest.raises(s.MqttError):
        s.parse_connect(body)


def test_truncated_publish_is_an_error():
    with pytest.raises(s.MqttError):
        s.parse_publish(0, b"\x00\x10ab", 4)


def test_redaction_masks_secret_keys_at_any_depth():
    masked = s.redact({"token": "t", "nested": [{"password": "p", "ps": "on"}], "ki": 1})
    assert masked == {"token": "**REDACTED**", "nested": [{"password": "**REDACTED**",
                                                            "ps": "on"}], "ki": 1}


def test_certificate_names_dates_and_key_mode(certificate):
    from cryptography import x509
    cert_path, key_path = certificate
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert set(names.get_values_for_type(x509.DNSName)) == set(s.MIRAIE_HOSTS)
    assert cert.not_valid_before_utc.year == 2020
    assert cert.not_valid_after_utc.year == 2049
    assert cert.public_key().key_size == 2048
    assert os.stat(key_path).st_mode & 0o777 == 0o600


def test_certificate_is_made_once(tmp_path):
    first = s.make_certificate(tmp_path)
    stamp = first[0].read_bytes()
    assert s.make_certificate(tmp_path)[0].read_bytes() == stamp


def test_client_hello_from_openssl():
    """OpenSSL's own ClientHello, parsed independently of the server."""
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = insecure().wrap_bio(incoming, outgoing, server_hostname="mqtt.miraie.in")
    with pytest.raises(ssl.SSLWantReadError):
        client.do_handshake()
    hello = s.parse_client_hello(outgoing.read())
    assert hello["sni"] == "mqtt.miraie.in"
    assert "TLS 1.2" in hello["versions"] or "TLS 1.3" in hello["versions"]
    assert hello["ciphers"] and 0 in hello["extensions"]


def test_not_a_client_hello():
    assert s.parse_client_hello(s.connect_packet("x")) is None


async def test_session_end_to_end(certificate):
    statuses = []
    server, events, port = await serve(certificate,
                                       on_status=lambda _, t, st: statuses.append((t, st)))
    try:
        client = await Client.open(port)
        kind, _, body, _ = await client.connect()
        assert (kind, body) == (s.CONNACK, b"\x00\x00")

        await client.send(subscribe(4, 7, TOPIC + "/control"))
        kind, _, body, _ = await client.packet()
        assert (kind, body) == (s.SUBACK, b"\x00\x07\x01")

        payload = json.dumps(STATUS).encode()
        await client.send(s.publish_packet(TOPIC + "/status", payload, qos=1, packet_id=9))
        kind, _, body, _ = await client.packet()
        assert (kind, body) == (s.PUBACK, b"\x00\x09")

        await client.send(s.frame(s.PINGREQ, 0))
        assert (await client.packet())[0] == s.PINGRESP

        assert await server.publish(TOPIC + "/control", {"ps": "off"}) == 1
        kind, flags, body, _ = await client.packet()
        message = s.parse_publish(flags, body, 4)
        assert (message["topic"], json.loads(message["payload"])) == (TOPIC + "/control",
                                                                      {"ps": "off"})
        assert await server.publish("elsewhere/control", {"ps": "off"}) == 0

        await client.send(s.frame(s.DISCONNECT, 0))
        closed = await events.wait_for("closed")
        assert closed["reason"] == "disconnect"
    finally:
        await server.close()

    assert events.kinds()[:4] == ["tcp_open", "client_hello", "tls_ok", "mqtt_connect"]
    assert events.first("client_hello")["sni"] == "mqtt.miraie.in"
    connect = events.first("mqtt_connect")
    assert connect["password_bytes"] == len(PASSWORD) and "password" not in connect
    assert events.first("status")["status"]["rmtmp"] == "134.23"
    assert events.first("status")["status"]["token"] == "**REDACTED**"
    assert statuses and statuses[0][0] == TOPIC + "/status"
    assert PASSWORD.decode() not in json.dumps([d for _, d in events.events], default=str)


async def test_verifying_client_is_reported_as_checking(certificate):
    """A client that checks certificates, as the AC might: the verdict must say so."""
    def verifying_client(port):
        # A blocking OpenSSL client sends its alert before giving up; asyncio's drops the line
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with pytest.raises(ssl.SSLCertVerificationError):
                ssl.create_default_context().wrap_socket(raw, server_hostname="mqtt.miraie.in")

    server, events, port = await serve(certificate)
    try:
        await asyncio.to_thread(verifying_client, port)
        failed = await events.wait_for("tls_failed")
    finally:
        await server.close()
    assert failed["reason"] in ("TLSV1_ALERT_UNKNOWN_CA", "SSLV3_ALERT_BAD_CERTIFICATE")
    assert failed["verdict"] == s.CHECKS_CERTIFICATE
    assert failed["certificate_sent"] is True
    assert "mqtt_connect" not in events.kinds()


async def test_client_trusting_our_certificate_passes(certificate):
    """Hostname and chain checked against our own certificate: proves the names are right."""
    server, events, port = await serve(certificate)
    try:
        client = await Client.open(port, context=ssl.create_default_context(
            cafile=str(certificate[0])))
        assert (await client.connect())[0] == s.CONNACK
        client.close()
        await events.wait_for("closed")
    finally:
        await server.close()
    assert "tls_ok" in events.kinds()


@pytest.mark.parametrize("ciphers", [
    "AES128-SHA",  # RSA key exchange, CBC: what an ESP8266's axTLS offers
    "AES256-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",  # what the real broker chose with OpenSSL
])
async def test_embedded_tls_12_cipher_suites(certificate, ciphers):
    """The small TLS stacks in Wi-Fi modules offer TLS 1.2 and older ciphers only."""
    context = insecure()
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    try:
        context.set_ciphers(f"{ciphers}:@SECLEVEL=0")
    except ssl.SSLError:
        pytest.skip(f"this OpenSSL has no {ciphers}")
    server, events, port = await serve(certificate)
    try:
        client = await Client.open(port, context=context)
        assert (await client.connect())[0] == s.CONNACK
        client.close()
        await events.wait_for("closed")
    finally:
        await server.close()
    ok = events.first("tls_ok")
    assert (ok["version"], ok["cipher"]) == ("TLSv1.2", ciphers)
    assert events.first("client_hello")["versions"] == ["TLS 1.2"]


async def test_hang_up_after_certificate(certificate):
    server, events, port = await serve(certificate)
    try:
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        tls = insecure().wrap_bio(incoming, outgoing, server_hostname="mqtt.miraie.in")
        with pytest.raises(ssl.SSLWantReadError):
            tls.do_handshake()
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(outgoing.read())
        await writer.drain()
        await reader.read(1)  # the server's flight has started
        writer.close()
        failed = await events.wait_for("tls_failed")
    finally:
        await server.close()
    assert failed["verdict"] == "closed_after_certificate"


async def test_refuses_addresses_not_allowed(certificate):
    server, events, port = await serve(certificate, allow={"192.0.2.19"})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        assert await asyncio.wait_for(reader.read(1), 5) == b""
        writer.close()
    finally:
        await server.close()
    assert events.kinds() == ["refused"]


async def test_plain_mqtt_on_the_port(certificate):
    server, events, port = await serve(certificate)
    try:
        client = await Client.open(port, tls=False)
        assert (await client.connect())[0] == s.CONNACK
        client.close()
        await events.wait_for("closed")
    finally:
        await server.close()
    assert events.kinds()[:3] == ["tcp_open", "plaintext", "mqtt_connect"]


@pytest.mark.parametrize("level", [3, 5])
async def test_other_mqtt_levels(certificate, level):
    server, events, port = await serve(certificate)
    try:
        client = await Client.open(port, level=level)
        kind, _, body, _ = await client.connect()
        assert kind == s.CONNACK and body == (b"\x00\x00\x00" if level == 5 else b"\x00\x00")
        await client.send(subscribe(level, 3, TOPIC + "/control"))
        kind, _, body, _ = await client.packet()
        assert kind == s.SUBACK and body.endswith(b"\x01")
        payload = json.dumps(STATUS).encode()
        await client.send(s.publish_packet(TOPIC + "/status", payload, level, 1, 4))
        assert (await client.packet())[0] == s.PUBACK
        await events.wait_for("status")
        client.close()
    finally:
        await server.close()


async def test_qos2_publish(certificate):
    server, events, port = await serve(certificate)
    try:
        client = await Client.open(port)
        await client.connect()
        await client.send(s.publish_packet(TOPIC + "/status", b"{}", qos=2, packet_id=5))
        kind, _, body, _ = await client.packet()
        assert (kind, body) == (s.PUBREC, b"\x00\x05")
        await client.send(s.ack(s.PUBREL, 5))
        kind, _, body, _ = await client.packet()
        assert (kind, body) == (s.PUBCOMP, b"\x00\x05")
        client.close()
    finally:
        await server.close()


async def test_keepalive_expiry_closes(certificate):
    server, events, port = await serve(certificate)
    try:
        client = await Client.open(port)
        await client.connect(keepalive=1)
        closed = await events.wait_for("closed", timeout=5)
    finally:
        await server.close()
    assert closed["reason"] == "keepalive"


async def test_first_packet_must_be_connect(certificate):
    server, events, port = await serve(certificate)
    try:
        client = await Client.open(port)
        await client.send(s.frame(s.PINGREQ, 0))
        closed = await events.wait_for("closed")
    finally:
        await server.close()
    assert closed["reason"] == "mqtt_error"


async def test_messages_route_between_sessions(certificate):
    server, events, port = await serve(certificate)
    try:
        ac, watcher = await Client.open(port), await Client.open(port)
        await ac.connect()
        await watcher.connect()
        await watcher.send(subscribe(4, 1, "+/+/+/status"))
        await watcher.packet()
        await ac.send(s.publish_packet(TOPIC + "/status", b'{"ps":"on"}'))
        kind, flags, body, _ = await watcher.packet()
        assert s.parse_publish(flags, body, 4)["payload"] == b'{"ps":"on"}'
        ac.close()
        watcher.close()
    finally:
        await server.close()


async def test_relay_passes_both_ways_and_reports(certificate, tmp_path):
    """The AC's session relayed to a broker that stands for the real one."""
    cloud_cert = s.make_certificate(tmp_path / "cloud")
    cloud, cloud_events, cloud_port = await serve(cloud_cert)
    relay, events, port = await serve(
        certificate, relay=("127.0.0.1", cloud_port),
        relay_context=ssl.create_default_context(cafile=str(cloud_cert[0])),
    )
    try:
        ac = await Client.open(port)
        assert (await ac.connect())[0] == s.CONNACK
        await ac.send(subscribe(4, 2, TOPIC + "/control"))
        assert (await ac.packet())[0] == s.SUBACK
        await ac.send(s.publish_packet(TOPIC + "/status", json.dumps(STATUS).encode()))
        await cloud_events.wait_for("status")
        assert await cloud.publish(TOPIC + "/control", {"actmp": "25.0"}) == 1
        kind, flags, body, _ = await ac.packet()
        assert json.loads(s.parse_publish(flags, body, 4)["payload"]) == {"actmp": "25.0"}
        ac.close()
        await events.wait_for("closed")
    finally:
        await relay.close()
        await cloud.close()
    directions = {(d["direction"], d["packet"]) for k, d in events.events if k == "relay_packet"}
    assert ("cloud_to_ac", "CONNACK") in directions
    assert ("ac_to_cloud", "PUBLISH") in directions
    assert ("cloud_to_ac", "PUBLISH") in directions
    assert cloud_events.first("mqtt_connect")["password_bytes"] == len(PASSWORD)
    assert PASSWORD.decode() not in json.dumps([d for _, d in events.events], default=str)


async def test_relay_failure_is_reported(certificate):
    relay, events, port = await serve(certificate, relay=("127.0.0.1", 1),
                                      handshake_timeout=3)
    try:
        ac = await Client.open(port)
        await ac.send(s.connect_packet("an0001", "dev", PASSWORD))
        failed = await events.wait_for("relay_failed")
    finally:
        await relay.close()
    assert failed["error"]


@pytest.mark.parametrize("protocol", ["MQTTv31", "MQTTv311", "MQTTv5"])
async def test_independent_paho_client(certificate, protocol):
    """paho, the client MirAIe's app-side libraries use, against the stand-in."""
    mqtt = pytest.importorskip("paho.mqtt.client")

    def run(port):
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="an123",
                             protocol=getattr(mqtt, protocol))
        client.username_pw_set("dev0001", PASSWORD.decode())
        client.tls_set_context(insecure())
        client.connect("127.0.0.1", port, keepalive=30)
        client.loop_start()
        try:
            client.subscribe(TOPIC + "/control", qos=1)
            info = client.publish(TOPIC + "/status", json.dumps(STATUS), qos=1)
            info.wait_for_publish(5)
            return info.is_published()
        finally:
            client.disconnect()
            client.loop_stop()

    server, events, port = await serve(certificate)
    try:
        assert await asyncio.to_thread(run, port)
        await events.wait_for("closed")
    finally:
        await server.close()
    assert {"tls_ok", "mqtt_subscribe", "status"} <= set(events.kinds())
    assert events.first("mqtt_connect")["level"] == {"MQTTv31": 3, "MQTTv311": 4,
                                                     "MQTTv5": 5}[protocol]


def test_tls_verdicts():
    assert s.tls_verdict("TLSV1_ALERT_UNKNOWN_CA", True) == s.CHECKS_CERTIFICATE
    assert s.tls_verdict("closed", True) == "closed_after_certificate"
    assert s.tls_verdict("closed", False) == "closed_before_certificate"
    assert s.tls_verdict("NO_SHARED_CIPHER", False) == "no_shared_cipher"
    assert s.tls_verdict("SOMETHING_NEW", True) == "other"

#!/usr/bin/env python3
"""Run the MirAIe stand-in broker on any machine in the house, outside Home Assistant.

    python3 tools/miraie_standin.py --allow 192.168.1.19

It listens on TCP 8883, answers only the addresses given with --allow, and writes every event as
one JSON line (default `~/.local/state/miraie-standin/events.jsonl`) and a short line to the
terminal. Its certificate is made on the first run and kept beside the log. A CONNECT's password is
never written, only its length; identifiers are shortened on the terminal but kept whole in the
file, which is private to this machine. Stop it with Ctrl-C.

--relay passes the AC's session on to the real mqtt.miraie.in and reports both directions. That
sends the AC's traffic to Panasonic, as an unblocked AC does anyway: use it only to learn what the
broker says to the AC, and only when the owner has agreed.

Standard library only; `cryptography` is used for the certificate when present, else `openssl`.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib.util
import json
from pathlib import Path
import re
import signal
import socket
import sys
import time

HERE = Path(__file__).resolve().parent
MODULE = HERE.parent / "custom_components" / "ac_mitm" / "standin.py"
spec = importlib.util.spec_from_file_location("miraie_standin_core", MODULE)
standin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = standin
spec.loader.exec_module(standin)

# userId, homeId and deviceId sit in topics and client ids: show their ends only
LONG_ID = re.compile(r"[0-9A-Za-z_-]{12,}")


def shorten(text: str) -> str:
    return LONG_ID.sub(lambda m: f"{m.group()[:4]}…{m.group()[-2:]}", text)


def summary(kind: str, data: dict) -> str:
    peer = data.get("peer", "")
    if kind == "client_hello":
        return (f"{peer} hello: SNI {data.get('sni')}, offers {', '.join(data.get('versions', []))}"
                f", {len(data.get('ciphers', []))} ciphers"
                + (f", max fragment {data['max_fragment_length']}"
                   if data.get("max_fragment_length") else ""))
    if kind == "tls_ok":
        return f"{peer} TLS OK ({data['version']}, {data['cipher']}): it took our certificate"
    if kind == "tls_failed":
        return f"{peer} TLS FAILED: {data['reason']}. {data['meaning']}"
    if kind == "mqtt_connect":
        return shorten(
            f"{peer} CONNECT {data['protocol']} {data['level']}, client {data['client_id']!r}, "
            f"user {data.get('username')!r}, password {data['password_bytes']} bytes, "
            f"keepalive {data['keepalive']} s, will {data.get('will_topic')!r}"
        )
    if kind in ("mqtt_subscribe", "mqtt_unsubscribe"):
        return shorten(f"{peer} {kind[5:]} {', '.join(data['topics'])}")
    if kind == "mqtt_publish":
        return shorten(f"{peer} publish {data['topic']} (QoS {data['qos']}): "
                       + json.dumps(data["payload"])[:300])
    if kind == "relay_packet":
        detail = data.get("topic") or data.get("topics") or data.get("code", "")
        payload = json.dumps(data["payload"])[:200] if "payload" in data else ""
        return shorten(f"{peer} {data['direction']} {data['packet']} {detail} {payload}")
    if kind == "status":
        status = data["status"]
        keys = ("ps", "acmd", "actmp", "rmtmp", "acfs", "acdc")
        return f"{peer} STATUS " + " ".join(f"{k}={status.get(k)}" for k in keys if k in status)
    rest = {k: v for k, v in data.items() if k not in ("time", "peer")}
    return f"{peer} {kind} " + (shorten(json.dumps(rest)) if rest else "")


def local_addresses() -> set[str]:
    found = {"127.0.0.1"}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            found.add(info[4][0])
    except OSError:
        pass
    return found


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--allow", action="append", required=True,
                        help="the AC's IPv4 address (repeat for more)")
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=standin.MQTT_TLS_PORT)
    parser.add_argument("--state", type=Path,
                        default=Path.home() / ".local" / "state" / "miraie-standin",
                        help="where the certificate and the event log are kept")
    parser.add_argument("--cert", type=Path, help="use this certificate instead of our own")
    parser.add_argument("--key", type=Path)
    parser.add_argument("--relay", action="store_true",
                        help="pass the session on to the real broker (sends data to Panasonic)")
    parser.add_argument("--relay-host", default="mqtt.miraie.in")
    args = parser.parse_args()

    if args.cert:
        cert, key = args.cert, args.key or args.cert
    else:
        cert, key = standin.make_certificate(args.state)
    log_path = args.state / "events.jsonl"
    args.state.mkdir(parents=True, exist_ok=True)
    log = log_path.open("a", buffering=1)

    relay = None
    if args.relay:
        addresses = {i[4][0] for i in socket.getaddrinfo(args.relay_host, args.port,
                                                         socket.AF_INET)}
        if addresses & (local_addresses() | {args.listen}):
            print(f"{args.relay_host} resolves to this machine here: refusing to relay to itself")
            return 2
        relay = (args.relay_host, args.port)
        print(f"RELAY: the AC's session goes on to {args.relay_host} ({', '.join(addresses)})")

    def on_event(kind: str, data: dict) -> None:
        log.write(json.dumps({"kind": kind, **data}, default=str) + "\n")
        stamp = time.strftime("%H:%M:%S", time.localtime(data["time"]))
        print(f"{stamp} {summary(kind, data)}", flush=True)

    server = standin.StandIn(standin.server_context(cert, key), on_event,
                             allow=set(args.allow), relay=relay)
    await server.start(args.listen, args.port)
    print(f"Listening on {args.listen}:{args.port} for {', '.join(args.allow)}; "
          f"log {log_path}")

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()
    await server.close()
    log.close()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

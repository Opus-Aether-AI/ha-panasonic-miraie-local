# A stand-in for MirAIe's broker

## Why

On a CS-CU-EU18CKY5XFM (firmware 3.02, November 2026), blocking the AC's internet had a cost that
local control hides. With `mqtt.miraie.in`, `app.miraie.in` and `auth.miraie.in` blocked in DNS:

- commands from Home Assistant still worked, and their readback was right;
- the status the AC serves over UDP stopped following the unit: the room reading (`rmtmp`) froze,
  and changes made on the IR remote never showed;
- unblocking the names brought both back at once.

So the AC refreshes its local status only while its Wi-Fi module holds an MQTT session with MirAIe.
The live checks in [testing](testing.md) ran with the internet blocked, but every change in them
came from Home Assistant, and the AC updates its status for a command it receives itself. They
couldn't show this.

## The idea

Give the AC a broker inside the house. A DNS rewrite points `mqtt.miraie.in` at
[`standin.py`](../custom_components/ac_mitm/standin.py). It:

- completes TLS with a certificate of its own;
- accepts the AC's MQTT connection whatever its credentials;
- acknowledges what MQTT requires (CONNACK, SUBACK, PUBACK, PINGRESP);
- hands each message the AC publishes to a callback.

Nothing leaves the house. Control stays on local UDP, as now.

## What is known about MirAIe's side

- **The broker** is `mqtt.miraie.in:8883`: MQTT over TLS 1.2, behind an AWS load balancer in
  ap-south-1. On 22 November 2026 it presented an Amazon-issued RSA-2048 certificate for
  `app.miraie.in.panasonic.com`, which also names `mqtt`, `app` and `auth.miraie.in` and chains to
  Amazon Root CA 1. It was issued on 18 November 2026, and the ACs reconnected to it, so they don't
  pin the earlier certificate.
- **It asks no client certificate,** so the AC signs in with an MQTT username and password. A
  stand-in doesn't need to know them.
- **The topics**, from the app-side libraries (for example
  [py-miraie-ac](https://github.com/milothomas/py-miraie-ac)), are
  `<userId>/<homeId>/<deviceId>/status`, `/control` and `/connectionStatus`. The status is plain
  JSON with the same keys as the UDP status (`ps`, `acmd`, `actmp`, `rmtmp`, ...).
- **Onboarding** gives the AC its home, space and user ids, the Wi-Fi details and a registration
  token over its setup access point. It doesn't give a broker address, which is built into the
  firmware ([kholia/Panasonic-Smart-AC-Research](https://github.com/kholia/Panasonic-Smart-AC-Research)).
- **The local key and IV** encrypt UDP only. They play no part in the MQTT session.

## The open question, and the test that settles it

Whether the AC checks the server's certificate against a CA it carries is unknown. Nothing public
records a MirAIe AC talking to another broker. If it checks, no stand-in can answer for MirAIe
without changing the module's firmware.

The stand-in reports the answer as the first thing it learns:

| What it logs | What it means |
|---|---|
| `tls_ok` then `mqtt_connect` | The AC took our certificate: the stand-in works |
| `tls_failed`, verdict `checks_certificate` (alert `unknown_ca` or `bad_certificate`) | It checks: give up on this route |
| `tls_failed`, verdict `closed_after_certificate` | It hung up after our certificate went out: almost certainly checks |
| `tls_failed`, verdict `no_shared_cipher` or `no_shared_version` | TLS settings, not trust: widen the server's settings and try again |
| `plaintext` | It spoke MQTT without TLS |
| nothing | The AC never asked: check the DNS rewrite and the listening machine's firewall |

The certificate is self-signed RSA-2048 for the three MirAIe names. It is valid from 2020 to 2049,
so an AC whose clock isn't set yet still finds it current. The server accepts TLS 1.0 to 1.3 and
any cipher OpenSSL has, including plain-RSA suites such as `AES128-SHA` that small TLS stacks offer.

### Running it

Run it on any machine in the house (Python 3.11 or newer, standard library). It makes its
certificate on the first run, with `cryptography` if installed, else `openssl`:

```sh
python3 tools/miraie_standin.py --allow <AC address>
```

- It answers only the addresses given with `--allow`.
- It writes every event as one JSON line in `~/.local/state/miraie-standin/events.jsonl`, and a
  short line to the terminal.
- A CONNECT's password is never written, only its length. Values under secret-looking keys in a
  payload are masked.
- Identifiers are shortened on the terminal but kept whole in the file.

Then point `mqtt.miraie.in` at that machine for that AC only. In AdGuard Home that is one custom
filtering rule:

```text
||mqtt.miraie.in^$dnsrewrite=NOERROR;A;<machine address>,client=<AC address>
```

A `dnsrewrite` rule outranks a blocking rule such as `||miraie.in^`. The AC holds its current
session until it reconnects, so switch it off at the wall for 30 seconds. To go back, delete the
rule and switch the AC off and on again.

`--relay` passes the session on to the real broker and reports both directions. It's for learning
what the broker says to the AC, if the AC connects but publishes nothing. It sends the AC's
traffic to Panasonic, as an unblocked AC does anyway.

## After the test

If the AC takes the certificate:

1. Block `app.miraie.in` and `auth.miraie.in` for the same AC, and check it still connects and
   publishes. It may need them only at onboarding.
2. Run the stand-in inside Home Assistant (planned, not built):
   - an option on the entry, off by default;
   - one server for all entries, on port 8883;
   - each session matched to its entry by the `deviceId` in its topic, or by address;
   - each status the AC publishes goes straight to the coordinator as an instant update.
3. Point the rewrite at Home Assistant for every AC.

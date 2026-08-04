## CTF Writeup — "Towel on the Sunbed" Race Condition (TryHackMe)
### TryHackMe · Hacker Holidays Day 8 · Web · Medium (90 pts) · Business-logic TOCTOU race → double-spend

**Flag:** `THM{REDACTED}`

---

## TL;DR

The app gives **+50 PONZI once every 24 hours** and unlocks the **Whale Vault at
150 PONZI** — exactly 3 claims, but the timer only allows 1. The daily-claim
check is a **race condition**: the server checks "has 24h passed?" and *then*
records the claim, with no lock in between. Fire many claim requests at the exact
same instant and they *all* pass the check before any of them saves the "already
claimed" timestamp — each one adds 50. Three simultaneous claims → 150 → vault.

---

## The attack chain

```
Register a guest account
        │
        ▼
Read dashboard: +50 PONZI / 24h, Whale Vault at 150  →  need 3 claims, allowed 1
        │
        ▼
Find the reward endpoint:  POST /claim  →  +50, returns newBalance
        │
        ▼
Naive parallel curl burst  →  only 1 succeeds (requests too spread out)
        │
        ▼
FIX 1: fresh account (eligibility window is open)
FIX 2: thread barrier — fire all requests at the SAME instant
        │
        ▼
Multiple claims pass the 24h check before any commits  →  balance jumps past 150
        │
        ▼
Whale Vault unlocks  →  FLAG
```

Maps onto the briefing: "claimed three times over," "a gap wide enough to walk a
whale through" (the check-to-update gap), and Mia's "the clock isn't the only
thing checking him" (the timer is real but bypassable by *concurrency*).

---

## Background: what is a race condition?

Skip this if you're comfortable with the concept.

Imagine a bank ATM that lets you withdraw once per day. Internally it does:

1. **Check:** "has this card withdrawn today?" → no.
2. **Give** the cash.
3. **Record:** "this card withdrew today."

Now imagine you insert **ten cloned cards into ten ATMs and hit withdraw at the
exact same millisecond.** All ten machines run step 1 *before* any of them
reaches step 3 — so all ten see "no, hasn't withdrawn today," all ten give cash,
and only *then* do they each write "withdrew today." You withdrew ten times from
a once-a-day account.

That gap — between **checking** a condition and **acting** on it — is a
**TOCTOU** flaw: **T**ime **O**f **C**heck to **T**ime **O**f **U**se. The check
was true when you looked, but nothing stopped ten actions from slipping through
before the record caught up.

This room is exactly that, with a crypto-rewards app instead of an ATM. The
"once per 24h" claim is the once-a-day withdrawal, and we're the ten cloned
cards.

---

## Step 1 — Understand the mechanic

Register a guest account (the itinerary tells you to) and land on `/dashboard`.
The rules are stated right in the page HTML:

```html
<p class="staking-desc">Earn <strong>50 PONZI</strong> every 24 hours by claiming
   your staking reward.</p>
...
<p class="vault-desc">Reach <strong>150 PONZI</strong> to unlock the Whale Vault
   and claim your exclusive reward.</p>
```

Do the arithmetic:
- One claim = **+50 PONZI**, once per 24h.
- Vault unlocks at **150 PONZI**.
- 150 ÷ 50 = **3 claims needed**, but only **1 allowed** per day.

The whole challenge lives in that gap: *legitimately* it takes 3 days; we need to
collapse it into one burst.

---

## Step 2 — Find the claim endpoint

The dashboard is driven by JavaScript, so the real API routes aren't in the HTML.
We probe likely endpoint names directly with `curl`. Only one answered:

```bash
IP=10.146.147.180
C='connect.sid=<your session cookie>'      # from registering / logging in

curl -s -b "$C" -X POST "http://$IP:3000/claim"
```

**What the flags mean:**
- `-s` — silent (no progress bar).
- `-b "$C"` — send our session cookie, so the server knows who we are. (`connect.sid`
  is the default cookie name for Node's `express-session`.)
- `-X POST` — this action *changes* something, so it's a POST, not a GET.

Response:

```json
{"message":"Staking reward claimed successfully.","reward":50,
 "newBalance":50,"tier":"Shrimp","priceSnapshot":4.2}
```

`POST /claim` grants 50 and returns our new balance. We're at 50, tier "Shrimp,"
and we need 150 for the vault. Two more claims — normally blocked by the 24h
timer.

---

## Step 3 — First attempt (and why it fails)

The obvious idea: fire a burst of claims in parallel using shell backgrounding.

```bash
for i in $(seq 1 30); do
  curl -s -b "$C" -X POST "http://$IP:3000/claim" >> race.txt &
done
wait
grep -c 'successfully' race.txt      # → 1
```

- `for i in $(seq 1 30)` — loop 30 times.
- `... &` — the `&` runs each curl **in the background**, so they launch without
  waiting for the previous one to finish.
- `wait` — pause until all 30 background jobs are done.

**Result: only 1 claim succeeded.** Why?

Two reasons, both about timing:
1. **Node.js is single-threaded.** Its event loop handles requests one at a time,
   so even "parallel" requests get lined up and processed in sequence.
2. **Each curl pays its own network cost.** Every `curl` opens a fresh TCP
   connection (a handshake that takes a few milliseconds). So the 30 requests
   don't arrive together — they trickle in over tens of milliseconds, spread out.

By the time request #2 arrives, request #1 has already finished and written
"claimed" to the database. So #2 (and the rest) correctly see "already claimed
today" and get rejected. The race window — the gap between check and update — is
maybe a millisecond wide, and backgrounded curls are far too loose to land inside
it.

To win, we need the requests to hit the server **within microseconds of each
other**, so several land inside that tiny window at once.

---

## Step 4 — Win the race

Two fixes were needed.

### Fix 1 — race a *fresh* account

A race exploits the **first** claim window. Every request has to hit "eligible =
true" simultaneously. But we already claimed once on our first account, so it's
now on the 24h cooldown — there's no open window left to race. Requests would
*correctly* be rejected.

So: **register a brand-new guest account and race it before ever claiming
normally.** A never-claimed account has an open eligibility window that all our
requests can hit at once.

### Fix 2 — synchronize the requests with a thread barrier

Instead of backgrounded curls (loose timing), use a Python script where all
threads prepare their request and then fire at the *same instant*, coordinated by
a **barrier**:

```python
import requests, threading

IP="http://10.146.147.180:3000"
C={"connect.sid":"<fresh-account-cookie>"}   # the NEW account
N=30

barrier=threading.Barrier(N)                 # a gate that opens only when N threads reach it
results=[]
lock=threading.Lock()

def claim():
    barrier.wait()                           # (1) wait here until all 30 threads are ready
    r=requests.post(f"{IP}/claim",cookies=C) # (2) then ALL fire at once
    with lock: results.append(r.text)

ts=[threading.Thread(target=claim) for _ in range(N)]
for t in ts: t.start()                        # start all 30 threads
for t in ts: t.join()                         # wait for them to finish
for r in sorted(set(results)): print(r)       # print the distinct responses
```

**The key line is `barrier.wait()`.** A `threading.Barrier(30)` is a gate that
stays shut until all 30 threads have arrived at it. Each thread does its slow
setup (creating the connection object, etc.), then parks at the barrier. When the
30th thread arrives, the gate flies open and **all 30 send their request in the
same instant** — no trickle, no spread. That collapses the arrival window from
tens of milliseconds down to microseconds, tight enough that several requests
pass the "24h elapsed?" check before any of them writes the timestamp.

Run it:

```bash
python3 race.py
```

Multiple responses come back with `newBalance` climbing — 100, 150, 200 — instead
of the cooldown error. Each claim that squeezed into the window added its 50. We
sail past 150.

> **Burp Suite alternative** (the room's tags mention it): Burp Repeater has
> **"Send group in parallel (single-packet attack),"** which fires a group of
> requests inside a single TCP frame — the same "all at once" idea, done in the
> GUI. The Python barrier achieves the same result and is quicker to script. Both
> beat the naive curl loop.

---

## Step 5 — Open the vault

With balance ≥ 150, the Whale Vault unlocks and returns the flag:

```
THM{REDACTED}
```

The flag names the vulnerability perfectly: a **double-spend**. The same
once-per-day reward was "spent" several times over by exploiting the window
before the ledger updated — the crypto-world term for exactly this class of race.

---

## Root cause

The claim handler did, in effect:

```
1. read the user's last_claim timestamp
2. check: (now − last_claim) ≥ 24h ?        ← TIME OF CHECK
3. …some processing…
4. balance = balance + 50                   ← TIME OF USE
5. last_claim = now
```

There is no lock between steps 2 and 5. Concurrent requests all run step 2
against the *same* stale `last_claim`, all pass, and all continue to step 4. The
"once per 24h" rule is guarded by a check that isn't **atomic** with the update it
depends on — textbook TOCTOU.

---

## Defensive takeaways

- **Make check-and-update atomic.** Do it in one database operation with a
  conditional, e.g. `UPDATE users SET last_claim = now(), balance = balance + 50
  WHERE (now() − last_claim) ≥ interval '24h'` and act on rows-affected. Only the
  first concurrent request matches; the rest change nothing.
- **Lock the row** for the duration of the read-check-write
  (`SELECT … FOR UPDATE` inside a transaction), so concurrent claims serialize
  instead of overlapping.
- **Idempotency keys** on state-changing endpoints, so duplicate/parallel
  submissions of the "same" claim collapse into one.
- **Rate-limit** the endpoint as defence-in-depth — it won't fix the logic but
  blunts the burst.
- **Never trust the client.** The UI disabled the "Claim" button between claims;
  that enforced nothing. All limits must live server-side.

## Detection opportunities

- **Burst of identical state-changing requests** from one session within a few
  milliseconds — a strong race-attempt signature. Alert on N+ `POST /claim` per
  session per second.
- **Balance deltas exceeding the per-window maximum** — a "+50 per 24h" reward
  producing +100/+150 in one second violates the invariant. Check it server-side,
  log and flag it.
- **Many requests on one session arriving in a single TCP window** (the
  single-packet-attack pattern) — visible at the proxy / load-balancer layer even
  without app changes.

---

## Command cheat-sheet

```
# find the claim endpoint
curl -s -b "$C" -X POST "http://$IP:3000/claim"

# naive parallel burst (usually TOO SLOW — proves the point, then fails)
for i in $(seq 1 30); do curl -s -b "$C" -X POST "http://$IP:3000/claim" & done; wait

# winning method: synchronized barrier race from a FRESH account — see race.py
python3 race.py
```

---

## Two things worth remembering

1. **To win a race, synchronize — don't just parallelize.** Backgrounded curls
   fire "at roughly the same time," which isn't good enough against a
   millisecond-wide window. A thread barrier (or Burp's single-packet attack)
   fires them at *the same instant*. That difference is the whole exploit.
2. **Race the fresh state.** A race exploits the *first* time a condition is true.
   Our already-claimed account was on cooldown, so its window was shut — a new
   account had it wide open. Always attack the state where the check is still
   passable.

*Target and data are fictional TryHackMe challenge material; all actions performed
against the room's provisioned machine.*

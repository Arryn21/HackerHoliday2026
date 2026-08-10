## CTF Writeup — "Management Wants a Word" Windows Triage + DPAPI + VeraCrypt (TryHackMe)
### TryHackMe · Hacker Holidays Day 14 (finale) · Forensics · Hard (120 pts) · Chrome-saved password → DPAPI → VeraCrypt container → invoice image flag

**Flag:** `THM{REDACTED}`

---

## TL;DR

Housekeeping left behind Vera's laptop. We got a KAPE triage folder: the Windows registry hives (SAM/SYSTEM/SECURITY), her Chrome profile, and a suspicious 100 MB file called `backup`. That `backup` is a VeraCrypt encrypted container, and the password to open it is sitting in Chrome's saved passwords. But Chrome passwords are locked with Windows DPAPI, so to read them we first recover Vera's Windows login password from the registry (`minivera`), use it to unlock her DPAPI key, decrypt the Chrome password (`Wh4t1sV3raD0inG0nTh1sH0st`), then use that to decrypt the VeraCrypt volume. Inside is a fake invoice PDF — and the flag is written as a line item on the invoice.

---

## The attack chain

```
KAPE triage folder
   │
   ├── SAM + SYSTEM + SECURITY hives ── secretsdump ──► Vera login password:  minivera
   │
   ├── DPAPI masterkey + SID + "minivera" ──────────► unlocks DPAPI user key
   │
   ├── Chrome "Local State" (DPAPI-wrapped AES key) ─► Chrome master AES key
   │        + Chrome "Login Data" (v10 AES-GCM blob)
   │                                   └────────────► saved password:
   │                                        Wh4t1sV3raD0inG0nTh1sH0st
   │
   └── Documents\backup (VeraCrypt container)
            + password above ─────────────────────► decrypt volume (AES-XTS)
                                                        │
                                                  FAT filesystem
                                                        │
                                       secret_financial_documents\
                                          important_invoice_byte_lotus.pdf
                                                        │
                                              embedded invoice image
                                                        │
                                                     FLAG
```

The story hints map straight onto the steps:
- *"a browser will remember things for you that you never told anyone else"* → the password is in Chrome's saved logins.
- *"not every hidden file needs a password cracker, some of them just need a really good memory"* → we don't brute-force anything; we recover the password Chrome remembered.
- *"version number 1.26.29"* → that's a **VeraCrypt** version number, telling us the `backup` file is a VeraCrypt container.

---

## Background: the three concepts in plain language

**1. Registry hives and password hashes.** Windows stores account info in files called "hives" (`SAM`, `SYSTEM`, `SECURITY`). Combined, they contain each user's password hash. A tool called `secretsdump` reads them offline (no need for the live machine) and prints the hashes. It also prints a bonus: any "LSA secret" like an auto-login password stored in clear-ish form.

**2. DPAPI (Data Protection API).** When Chrome saves a password, it doesn't store it in plain text — it encrypts it with a key that is itself locked to the Windows user account. That lock is DPAPI. The important part: DPAPI's "master key" can only be unlocked with the **user's actual Windows login password** (plus their account SID). So to read Chrome's saved passwords offline, you need Vera's Windows password first. Think of it as: Chrome password is in a box, the box key is in a safe, and the safe combination is Vera's Windows login.

**3. VeraCrypt container.** A VeraCrypt "container" is just a normal-looking file that is actually an encrypted disk. Mount it with the right password and it appears as a drive with files inside. It has no file magic bytes — it looks like random noise — which is exactly what a 100 MB file called `backup` looked like here.

## Scope note

THM-provisioned challenge material — a KAPE forensic triage archive of a fictional guest's laptop. All analysis done offline on the provided files; no live target.

---

## Step 1 — Look at what she left behind

Unzip the task file. Inside is a `KAPE\C\...` tree (KAPE is a common forensic collection tool). The interesting bits:

- `C\Windows\System32\config\` → `SAM`, `SYSTEM`, `SECURITY`, `SOFTWARE` (the registry hives)
- `C\Users\vera\AppData\Local\Google\Chrome For Testing\User Data\` → a full Chrome profile (`Local State`, `Default\Login Data`)
- `C\Users\vera\AppData\Roaming\Microsoft\Protect\S-1-5-21-...\` → the DPAPI master key files
- `C\Users\vera\Documents\backup` → one 100 MB file, no extension

Checking the first bytes of `backup` shows high-entropy random-looking data (no recognizable header). Big round size + random bytes + the "1.26.29" VeraCrypt hint = **VeraCrypt container**.

## Step 2 — Recover Vera's Windows password

Use impacket's `secretsdump` on the offline hives:

```
secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL
```

Output includes Vera's NT hash and, crucially, an LSA secret:

```
[*] DefaultPassword
(Unknown User):minivera
```

`DefaultPassword` is the auto-login password Windows stored. To confirm it's really Vera's password, hash `minivera` the Windows way (NT hash = MD4 of the password in UTF-16):

```
MD4("minivera".encode("utf-16-le")) = 1241186a4aac4f34f4bf7ace71b396a8
```

That matches Vera's NT hash from the SAM dump exactly. So her Windows login password is **`minivera`**. No cracking needed — the machine handed it to us.

## Step 3 — Unlock the DPAPI master key

With her password and her account SID (the folder name under `Protect\`), decrypt the DPAPI master key file:

```
dpapi.py masterkey -file <masterkey-guid> -sid S-1-5-21-2529683458-431225740-1723070931-1000 -password minivera
```

Result: `Decrypted key with User Key (SHA1)` and a 64-byte decrypted master key. This is the key that unlocks anything Vera's account DPAPI-encrypted — including Chrome's password key.

## Step 4 — Decrypt the Chrome saved password

Chrome stores its password-encryption key inside `Local State`, in `os_crypt.encrypted_key`, wrapped with DPAPI (it starts with the text `DPAPI`). Strip that 5-byte prefix, decrypt the rest with the DPAPI master key from Step 3 → you get Chrome's 32-byte AES key.

Then open `Default\Login Data` (a SQLite database). Each saved password is a "v10" blob = `v10` + 12-byte IV + ciphertext + 16-byte GCM tag, encrypted with AES-256-GCM using that key. Decrypting the one saved entry:

```
URL:      http://bytelotus.thm:8080/
Username: VeraSecretVault
Password: Wh4t1sV3raD0inG0nTh1sH0st
```

The username `VeraSecretVault` is a big wink — this is the password to her secret vault (the `backup` container).

## Step 5 — Decrypt the VeraCrypt container

Normally you'd just mount it in the VeraCrypt app, but mounting needs a driver and admin rights. It's decryptable purely from the file with the password, so here it's done in Python with AES-XTS:

1. First 64 bytes of the file = salt.
2. Derive the header key with PBKDF2-HMAC-**SHA-512**, 500000 iterations (VeraCrypt's default for non-system volumes).
3. Decrypt header bytes 64–512 with AES-XTS → the plaintext starts with `VERA` (confirms right password + settings).
4. The volume's master keys sit at offset 256 of the decrypted header.
5. The actual data starts at file offset 131072. Decrypt each 512-byte sector with AES-XTS. **Gotcha:** the data-unit counter starts at **256** (131072 ÷ 512), not 0 — with the wrong start number every sector comes out as garbage. With 256, the first sector decodes to a `MSDOS5.0` boot record = a FAT filesystem. That's the "aha" moment.

## Step 6 — Read the files and find the flag

Parse the decrypted FAT image (here with `pyfatfs`). Contents:

```
/secret_financial_documents/important_invoice_byte_lotus.pdf   (26747 bytes)
/secret_financial_documents/transactions_q3.csv
/$RECYCLE.BIN/DESKTOP.INI
/System Volume Information/WPSettings.dat
```

**One small trap:** on the first read the PDF came out as only 1024 bytes (the tool grabbed a single cluster). FAT files are stored as a *chain* of clusters — you have to follow the whole chain to get all 26747 bytes. After reading the full chain, the PDF is complete.

The PDF has no selectable text — it's a single embedded image (`/XObject /Image`, FlateDecode, 636×724). Extract that image and open it: it's a fake "Byte Lotus Resorts" invoice, and the first line item reads:

```
Flag: THM{REDACTED}
```

Done — that's the flag.

---

## Root cause

Vera's operational security fell apart at one link: she saved the vault password *in her browser*. Everything else (a strong VeraCrypt container, hiding the vault as `backup`) was undone because the browser quietly stored the password, and the browser's protection (DPAPI) is only as strong as her weak, auto-login Windows password (`minivera`), which the machine itself stored in plain sight.

## Defensive takeaways

- Don't save the password of an encrypted vault in your browser — it defeats the whole point of the vault.
- Browser DPAPI protection is tied to your Windows login. A weak login password (and auto-login `DefaultPassword`) makes every saved secret trivially recoverable from an offline image.
- Disable auto-login / clear `DefaultPassword`; it's stored as an LSA secret that any registry dump reveals.
- Full-disk encryption on the whole laptop would have protected the triage artifacts too — here everything except the one container was in the clear.

## Detection opportunities

- KAPE/triage collections that include both registry hives and a browser profile are enough to reconstruct this whole chain — treat those artifacts as highly sensitive.
- A large, extension-less, high-entropy file in a user's Documents is a classic encrypted-container indicator worth flagging.

## Command cheat-sheet

```
# 1. Windows password from offline hives
secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL
#    -> DefaultPassword: minivera (confirm via MD4 NT-hash match)

# 2. Unlock DPAPI master key
dpapi.py masterkey -file <guid> -sid <SID> -password minivera

# 3. (script) DPAPI-decrypt Chrome Local State key, then AES-GCM decrypt Login Data
#    -> Wh4t1sV3raD0inG0nTh1sH0st

# 4. (script) VeraCrypt: PBKDF2-SHA512 x500000 -> header key -> AES-XTS
#    header check "VERA"; master keys at offset 256; data at 131072; unit base 256

# 5. Read FAT image (follow full cluster chain!), extract PDF, pull embedded image
```

## Two things worth remembering

- **The secret was in content, not in clever crypto.** Same lesson as the OSINT rooms in this series: the password wasn't hidden in bytes to be cracked — it was *remembered* by a tool (Chrome) and *stored* by the OS (DefaultPassword). When crypto looks unbreakable, look for where a human or a program already wrote the secret down.
- **Small format details decide success.** Two tiny things made or broke this: the VeraCrypt data-unit counter starting at 256 (not 0), and following the full FAT cluster chain (not just the first cluster). Get the format right and the "hard" crypto falls open; get it wrong and correct keys still produce garbage.

*Target/users/credentials are fictional challenge material; all actions performed offline against the THM-provided triage archive.*

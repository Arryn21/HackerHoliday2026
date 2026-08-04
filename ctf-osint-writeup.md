## CTF Writeup — "VERA" Image OSINT (TryHackMe)
### TryHackMe · Hacker Holidays · OSINT · finding a hidden social account from a brochure image

**Flag:** `THM{REDACTED}`

---

## TL;DR

A brochure image (`thebrochure.png`) looks like a steganography puzzle and isn't.
Every byte-level technique — metadata, chunk analysis, carving, LSB stego — comes
back empty. The clue is **printed text on the brochure itself**, too small and
stylised to read at a glance, which names "VERA" and points to an Instagram
account holding a base64-encoded flag. The lesson: OSINT clues live *in the
content*, not hidden in the bytes.

---

## The attack chain

```
thebrochure.png
        │
        ▼
Byte-level analysis (exiftool, pngcheck, binwalk, zsteg)  →  ALL empty
        │  (this is itself a clue: the payload isn't hidden in bytes)
        ▼
OCR the image (tesseract)  →  readable text: "VERA", "Find us on ___"
        │
        ▼
OSINT pivot  →  Instagram account  veratheconcierge
        │
        ▼
Profile bio holds a base64 string (split into 3 chunks)
        │
        ▼
Concatenate + base64-decode  →  FLAG
```

---

## Background: forensics vs OSINT clues

Two challenge categories look similar but hide their secrets in opposite places:

- **Forensics / steganography** hides data *in the bytes* of a file — in metadata
  fields, appended after the image, or in the least-significant bits of pixels.
  You attack it with tools that inspect the file's internals.
- **OSINT** (Open-Source INTelligence) hides the clue *in the visible content* and
  points you *off the file* — to a website, a social account, a person. You attack
  it by reading what's there and searching the open web.

This room is filed under **OSINT**, and that label is the biggest hint: the answer
is something printed on the brochure that leads to an online account. The trap is
that it *looks* like a forensics puzzle, so you waste time on stego tooling.

---

## Step 1 — Archive triage (before extracting)

The image arrives inside a zip. Never extract an unknown archive carelessly.

```bash
sha256sum archive.zip           # record a hash for reference
file archive.zip                # confirm it's really a zip
unzip -l archive.zip            # LIST contents without extracting
```

- `unzip -l` lists what's inside *without* writing anything to disk — so you can
  spot a zip-bomb (huge uncompressed size) or path-traversal entries (names with
  `../`) before they can do harm.

Extract into a contained, dated directory (not your home folder, never as root):

```bash
mkdir -p ~/analysis/$(date +%Y%m%d-%H%M) && cd $_
unzip ~/archive.zip -d extracted
```

Contents: a single PNG, `thebrochure.png`.

## Step 2 — Metadata

```bash
exiftool -a -u -g1 thebrochure.png
```

- `exiftool` reads a file's metadata (camera, software, comments, GPS, etc.).
- `-a` shows duplicate tags, `-u` shows unknown ones, `-g1` groups by category.
  Challenge authors love hiding text in obscure or duplicate tags, so these flags
  matter. **Result: nothing planted.**

## Step 3 — PNG structure

```bash
pngcheck -vtp7 thebrochure.png
```

`pngcheck` walks every internal "chunk" of a PNG and reports its structure. It
flags unusual chunks, embedded text comments, and — most importantly — **data
appended after the `IEND` marker** (the official end of a PNG), a classic hiding
spot. **Result: clean.**

## Step 4 — Appended / embedded files

```bash
binwalk thebrochure.png
strings -n 8 thebrochure.png | grep -iE 'flag|pass|http|BEGIN|PK'
```

- `binwalk` scans for other file types smuggled inside (a zip riding along, etc.).
- `strings` prints readable text runs; the `grep` filters for interesting keywords.
  A `PK` signature would mean a hidden zip. **Result: nothing.**

## Step 5 — LSB steganography (the dead end)

```bash
zsteg -a thebrochure.png
```

`zsteg` looks for data hidden in the **least-significant bits** of pixels (LSB
stego). `-a` tries every possible channel/bit combination.

**It returned hundreds of "hits" — all false positives.** This is the trap. Here's
how to read `zsteg -a` output so you don't chase ghosts:

- The **same "finding" appearing across dozens of unrelated settings** is noise —
  real hidden data lives in exactly *one* configuration, not everywhere.
- Text hits that are smooth gradients (`"NOOPPQQQRQR..."`) are just the photo's
  pixels rendered as ASCII.
- Exotic `file`-type matches (*MPEG*, *AIX core file*, etc.) are the `file` tool
  matching 4–8 coincidental bytes.
- **Real** stego is usually a *single* clean hit containing readable English,
  base64, or a recognisable file header.

Also worth knowing: **`steghide` does not support PNG** (JPEG/BMP only) — a common
time-waster on PNG challenges.

Empty metadata + clean pngcheck + clean binwalk + zsteg noise is itself
information: it rules out the byte-level hiding places and should redirect you to
the *content*.

## Step 6 — OCR (the breakthrough)

```bash
tesseract thebrochure.png -
```

`tesseract` is OCR — Optical Character Recognition. It reads printed text out of
an image and prints it as plain, searchable text. The raw output was garbled but
decisive:

```
MON JUL 27
Some things aren't posted. Some clues are.
VERA can assist you with further information.
Find us on ___ or not.
... SIGNALS ...
```

Two capitalised leads jump out: **VERA** and a mangled platform name after
**"Find us on."** For cleaner OCR on stylised brochure text, upscale and use
sparse-text mode:

```bash
convert thebrochure.png -colorspace gray -resize 400% -sharpen 0x1 /tmp/ocr.png
tesseract /tmp/ocr.png - --psm 11
```

- `convert` (ImageMagick) greyscales and enlarges the image 4× — tesseract wants
  ~300 DPI and struggles below it.
- `--psm 11` treats the page as "sparse scattered text," which suits a designed
  brochure far better than the default's assumption of a solid paragraph.

## Step 7 — OSINT pivot

"VERA" + "Find us on…" points to the Instagram account **`veratheconcierge`**. To
find an account name across platforms from a username, you can enumerate it:

```bash
maigret <username>       # checks hundreds of sites, reports profile content
# or: sherlock <username>
```

## Step 8 — Decode the flag

The profile bio held the flag as base64, deliberately **split into three chunks**
to slow you down:

```bash
echo 'CHUNK1CHUNK2CHUNK3' | base64 -d
```

- `base64 -d` decodes base64 back to plain text. Each chunk fails to decode
  alone — you must **concatenate them first**, then decode the whole string.

Result:

```
THM{REDACTED}
```

---

## Root cause / what this teaches

- The challenge deliberately *looks* like stego (so you burn time on zsteg/binwalk)
  but the payload was legible print pointing off-platform. **Match your technique
  to the category:** OSINT → read the content and search; forensics → inspect the
  bytes.
- Empty byte-level results are a signal, not a failure — they eliminate the
  hiding places and redirect you.

## Defensive / privacy takeaways

- **Anything printed on published media is discoverable.** Handles, QR codes,
  emails, and "hidden" hints on brochures/flyers are OSINT gold — treat public
  design assets as public forever.
- **Splitting/encoding a secret is obfuscation, not protection.** Base64 is
  trivially reversible; splitting it only adds seconds.

## Detection opportunities

Less applicable to a pure-OSINT puzzle, but for an org: monitor for brand/handle
mentions and for company assets (logos, staff names, internal tool names) leaking
into public creative material — the same recon an attacker runs.

## Command cheat-sheet

```
# archive triage
sha256sum archive.zip ; file archive.zip ; unzip -l archive.zip

# metadata + structure + carving
exiftool -a -u -g1 img.png
pngcheck -vtp7 img.png
binwalk img.png

# LSB stego (PNG/BMP only; expect false positives with -a)
zsteg -a img.png

# OCR (upscale + greyscale first for stylised text)
convert img.png -colorspace gray -resize 400% -sharpen 0x1 /tmp/o.png
tesseract /tmp/o.png - --psm 11

# handle enumeration + decode
maigret <username>
echo '<base64>' | base64 -d
```

## Two things worth remembering

1. **Run OCR early on any image with visible design.** "Nothing to see" almost
   always means small or stylised print, not absent print — one `tesseract` call
   skips the entire stego detour.
2. **The challenge category is a hint.** OSINT clues are in the content and point
   off-platform; forensics clues are in the bytes. Reading the label first saves
   the most time.

*Analysis ran on a disposable cloud VM, not the host laptop; carved files were
inspected, never executed. Target and account are fictional challenge material.*

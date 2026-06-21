---
title: "Template: AV/EDR Bypass Post"
date: 2040-06-17 00:00:00 +0000
categories: [AV/EDR Bypass, AMSI]
tags: [amsi, etw, evasion, windows, powershell, csharp]
toc: true
---

## Overview

What's being bypassed, product/version tested against, and the core primitive used.

## How the Defence Works

Explain what the target detection mechanism does before explaining how to bypass it.
This makes the post useful for both red and blue readers.

## Bypass Technique

```csharp
// Example: AMSI context field patch (context-specific, lab use only)
var amsi = typeof(System.Management.Automation.AmsiUtils);
var field = amsi.GetField("amsiContext",
    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
// ...
```

## Limitations & Gotchas

- Works against X but not Y because...
- Patched in build XXXXX

## Blue Team Perspective

How would you detect this if you were defending?

- ETW provider: `Microsoft-Antimalware-Scan-Interface`
- Look for memory writes to `amsi.dll` outside of `amsi.dll` itself

## References

- [MITRE ATT&CK T1562.001 — Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)

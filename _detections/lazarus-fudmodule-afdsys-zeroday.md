---
title: "Lazarus Group - AFD.sys Zero-Day (CVE-2026-68820) & FudModule Deployment (Threat Brief)"
layout: default
---

## Overview

On 2026-08-11, Microsoft patched **CVE-2026-68820** as part of that month's Patch Tuesday - a use-after-free race condition in `AFD.sys` (the Ancillary Function Driver for Winsock) that had already been under active exploitation by North Korea's **Lazarus Group** since at least early July 2026. Check Point Research, which reported the flaw to Microsoft on 2026-07-28, documented the exploitation chain as part of the group's long-running "Operation Dream Job" campaign: fake recruiters impersonating **Enveil**, a real privacy-enhancing-technology firm, targeted employees at defense, aerospace, and aviation organizations in Europe and India, delivering **SecurityPDF** - a modified PDF viewer that opens attacker-crafted documents and executes a previously undocumented backdoor named **Troy**. Troy then exploits CVE-2026-68820 to escalate from limited user access to SYSTEM and deploys **FudModule v3.1**, Lazarus' kernel-mode rootkit, to blind endpoint defenses.

## Why this matters for detection

This was a genuine zero-day, not a misconfiguration - unpatched hosts had no preventive control against the privilege-escalation step itself, which makes the delivery and post-exploitation stages the only place defenders had leverage before 2026-08-11 (and they remain useful signal afterward, for any host that hasn't updated yet). FudModule v3.1's specific contribution to the intrusion is disabling telemetry rather than stealing data directly - it kills roughly 94 ETW providers and suppresses crash dumps - which means the most reliable detection opportunity is often the *absence* of expected telemetry (a host that abruptly stops producing security events) combined with the crash-dump-suppression registry change itself, something that's unusual in normal endpoint operation and rarely legitimate outside managed deployment tooling.

## Detection Guidance

```yaml
title: Lazarus Operation Dream Job - Crash Dump Suppression Following Trojanized PDF Viewer Execution
status: experimental
description: >-
  Detects Windows crash-dump suppression shortly after execution of a
  non-standard PDF viewer process, consistent with Lazarus Group's
  Operation Dream Job post-exploitation pattern (SecurityPDF -> Troy
  backdoor -> CVE-2026-68820 AFD.sys zero-day -> FudModule v3.1 EDR
  blinding).
references:
  - https://research.checkpoint.com/2026/shattering-the-dream-when-a-job-offer-becomes-a-zero-day-attack/
  - https://thehackernews.com/2026/08/lazarus-exploits-windows-zero-day-to.html
  - https://www.bleepingcomputer.com/news/security/lazarus-hackers-exploited-windows-zero-day-to-target-defense-firms/
author: Aryan
date: 2026-09-01T00:00:00.000Z
tags:
  - attack.initial_access
  - attack.t1566.001
  - attack.privilege_escalation
  - attack.t1068
  - attack.defense_evasion
  - attack.t1562.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_trojanized_pdf_viewer:
    Image|endswith: '\SecurityPDF.exe'
  selection_crashdump_disabled:
    EventID: 13
    TargetObject|endswith: '\CrashControl\CrashDumpEnabled'
    Details: 'DWORD (0x00000000)'
  condition: selection_trojanized_pdf_viewer and selection_crashdump_disabled
  timeframe: 20m
  # Also alert independently on any host where 20+ distinct ETW providers
  # are disabled within a short window - FudModule v3.1's ~94-provider
  # shutdown is an outlier against normal endpoint behavior regardless of
  # what triggered it
falsepositives:
  - IT-managed imaging/deployment scripts that disable crash dumps as fleet policy (should be limited to known maintenance windows/hosts)
level: high
```

## Prevention

- Confirm the 2026-08-11 Patch Tuesday update (which fixes CVE-2026-68820) is deployed across all Windows 11 24H2/25H2 endpoints - this closes the specific privilege-escalation path this campaign relies on.
- Treat unsolicited recruiter contact referencing a real company (Enveil, in this case) as something to verify, not a trust signal on its own - confirm outreach independently through the named company's official channels before opening any attachment or installer.
- Restrict PDF viewer installation to IT-approved sources, and alert on PDF-reader-branded executables running from user-writable paths (Downloads, AppData, Temp) rather than Program Files.
- Alert on crash-dump suppression and mass ETW provider shutdowns as high-severity events in their own right, independent of what process triggered them - both are rare in legitimate operation and are exactly what FudModule-class rootkits rely on to operate undetected.

*See also: [Lazarus Group / Operation Dream Job - DPRK Zero-Day Recruitment-Lure Intrusions](/actors/lazarus-group/) for the actor's broader behavioral pattern.*

---
title: "UTA0565 - CLEANGULP Backdoor via Cloned-Website BlueMoon Zero-Day Delivery (Threat Brief)"
layout: default
---

## Overview

On 2026-09-21, Volexity published a follow-up to its original BlueMoon exploit-chain disclosure, detailing a second, distinct China-linked cluster it tracks as **UTA0565** exploiting the same three-stage zero-day chain - **CVE-2026-85046** (Chrome V8 type confusion), **CVE-2026-87491** (WebAssembly compiled-function metadata corruption to escape the V8 sandbox), and **CVE-2026-85880** (a Windows ALPC heap overflow escalating to SYSTEM) - between 2026-09-03 and 2026-09-04, before either vendor had shipped a fix.

UTA0565's delivery method differs from the original UTA0560 campaign: rather than a reflected-XSS redirect planted on a single compromised, legitimate university site, UTA0565 stood up multiple cloned/fake websites impersonating media outlets, an NGO, the Center for American Progress, China Digital Times, a halal-restaurant search site, and a corporate training portal, then drove traffic to them with Chinese- and English-language phishing emails - including lures invoking Hong Kong activist Chow Hang-tung - targeting Asian government entities. The payload is also new: a previously undocumented, heavily obfuscated C-based implant Volexity named **CLEANGULP**, distinct from UTA0560's JScript-based GRIMWEDGE backdoor. CLEANGULP installs itself at `%LOCALAPPDATA%\Microsoft\IME\MicrosoftIME.exe` and creates a scheduled task named `MicrosoftIME` for persistence - masquerading as a legitimate Windows Input Method Editor component. It supports shell-command execution, process listing, file upload/download, and execution of Beacon Object Files, communicating over HTTP with request/response bodies encrypted with AES-256-GCM and encoded with a custom Base64 alphabet.

## Why this matters for detection

This confirms the BlueMoon exploit chain is being shared or brokered across multiple, independently operating China-nexus clusters - UTA0565 is at least the fourth distinct group observed using it, each swapping in its own payload and delivery infrastructure. That means detections keyed to any single cluster's tooling (a specific domain set, a specific payload) will miss the others. CLEANGULP is also the first payload in this exploit-chain family to use disk-based persistence instead of staying memory-resident like GRIMWEDGE, which gives defenders a durable, host-based artifact - the `MicrosoftIME` scheduled task and file path - that survives a reboot and doesn't depend on catching the initial exploitation in the act.

## Detection Guidance

```yaml
title: CLEANGULP Persistence - MicrosoftIME Scheduled Task Masquerade
status: experimental
description: >-
  Detects creation of a scheduled task named MicrosoftIME or execution of
  MicrosoftIME.exe from the Microsoft\IME AppData path, consistent with
  CLEANGULP backdoor persistence used by UTA0565 following BlueMoon
  Chrome/Windows zero-day exploitation (CVE-2026-85046, CVE-2026-87491,
  CVE-2026-85880).
references:
  - https://www.volexity.com/blog/2026/09/21/mind-the-patch-gap-part-2-fake-websites-used-to-deploy-chrome-windows-0-day-exploits/
  - https://thehackernews.com/2026/09/chinese-hackers-exploit-chrome-windows.html
  - https://cyberscoop.com/volexity-uta0565-china-exploit-chain-chrome-microsoft/
author: Aryan
date: 2026-09-24T00:00:00.000Z
tags:
  - attack.persistence
  - attack.t1053.005
  - attack.defense_evasion
  - attack.t1036.005
  - attack.command_and_control
  - attack.t1071.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_scheduled_task:
    EventID: 4698
    TaskName|contains: 'MicrosoftIME'
  selection_process_path:
    Image|endswith: '\Microsoft\IME\MicrosoftIME.exe'
  condition: selection_scheduled_task or selection_process_path
falsepositives:
  - None expected - genuine Windows IME components do not live under this AppData path or register a scheduled task with this name
level: critical
```

## Prevention

- Patch Chrome/Chromium to the version addressing CVE-2026-85046/CVE-2026-87491 and apply the Windows update for CVE-2026-85880 (ALPC heap overflow) - the same chain now confirmed in use by at least four separate clusters.
- Alert on scheduled task creation (Event ID 4698) where the task name or binary path imitates a built-in Windows component (IME, print spooler, update services) but resolves to a user-writable AppData location rather than `System32`.
- Apply domain/brand-impersonation monitoring for organizations frequently cloned as phishing lures in this campaign family (policy think tanks, human-rights/activist causes, NGOs, media outlets) rather than relying on reputation filtering alone, since UTA0565's cloned sites are new infrastructure with no prior negative reputation.
- Treat any Chromium-based browser process spawning unexpected child processes, or any new disk-resident implant appearing shortly after a browsing session, as equally suspicious - this exploit-chain family has now been observed with both memory-resident (GRIMWEDGE) and disk-persistent (CLEANGULP) payloads.

*See also: [UTA0560 - China-Linked Espionage Actor Behind the BlueMoon Chrome/Windows Zero-Day Chain](/actors/uta0560/) for the broader BlueMoon exploit-chain economy this cluster is part of.*

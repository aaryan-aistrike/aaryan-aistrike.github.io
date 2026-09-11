---
title: "UTA0560 - GRIMWEDGE Backdoor via Chained Chrome/Windows Zero-Days (Threat Brief)"
layout: default
---

## Overview

On 2026-09-01, Volexity's network monitoring detected a spear-phishing campaign from a China-linked actor it tracks as **UTA0560**, targeting customers at multiple NGOs, including US-based international policy research organizations. The emails linked to a legitimate, compromised US university website carrying a reflected XSS flaw, which redirected victims into a three-stage zero-day exploit chain - since referred to by other researchers as "BlueMoon" - built from **CVE-2026-85046** (a Chrome V8 type-confusion bug giving arbitrary read/write inside the V8 sandbox), **CVE-2026-87491** (a WebAssembly-metadata-corruption bug that escapes the V8 sandbox by overwriting compiled function bodies with shellcode), and **CVE-2026-85880** (a heap-based buffer overflow in Windows ALPC that escalates from Chrome's AppContainer renderer sandbox to SYSTEM with no further user interaction).

The final payload, **GRIMWEDGE**, is a lightweight JScript backdoor - under 250 lines - that runs entirely in memory as an eval()'d string inside `msiexec.exe`. It supports around ten commands covering host reconnaissance, process listing, command execution, and file upload/download, with no built-in persistence, lateral-movement, or exfiltration mechanism of its own - it exists purely to give UTA0560 an initial foothold to survey the host and stage follow-on tooling. CVE-2026-85046 had already been fixed in the public Chromium source tree before Google shipped the fix to Chrome's stable channel; UTA0560 is assessed to have weaponized that public "patch gap" to build working exploit code while ordinary Chrome users still had no update available. Google shipped an emergency fix (Chrome 152.0.7977.82/.83) on 2026-09-03/04. Within days, at least three other China-nexus clusters - including APT31/JungleBamboo - were observed using the identical exploit chain to deliver different payloads (SUPERSTOMP, the GemStone and LONGTALE malicious Chrome extensions, and ShadowPad), indicating the exploit chain is shared across multiple, otherwise separate operations.

## Why this matters for detection

This is a fully patched Chrome + fully patched Windows combination getting compromised from a single clicked link - there is no patch-based defense during the window before the fix ships, and the delivery mechanism (a reflected XSS redirect on a legitimate, trusted domain) defeats reputation- and domain-based email filtering. That means the durable detection point isn't the phishing lure or the vulnerable site - it's the browser process's behavior immediately after exploitation. A Chrome or Edge renderer spawning `msiexec.exe`, or any similar living-off-the-land binary, is not something any legitimate browser update, extension install, or normal user workflow does, which makes it a strong, exploit-chain-agnostic signal regardless of which specific CVE combination was used to get there.

## Detection Guidance

```yaml
title: Chromium-Based Browser Spawning LOLBin Process - Post-Exploitation Sandbox Escape
status: experimental
description: >-
  Detects a Chrome or Edge renderer process spawning msiexec.exe or another
  common living-off-the-land binary, consistent with post-exploitation code
  execution following a browser sandbox escape - as seen in the UTA0560
  GRIMWEDGE campaign chaining CVE-2026-85046, CVE-2026-87491, and
  CVE-2026-85880.
references:
  - https://www.volexity.com/blog/2026/09/09/mind-the-patch-gap-multiple-chinese-threat-actors-chain-0-day-exploits-in-chrome-windows/
  - https://www.proofpoint.com/us/blog/threat-insight/once-bluemoon-multiple-state-aligned-threat-actors-rapidly-adopt-novel-exploit
  - https://www.bleepingcomputer.com/news/security/new-bluemoon-kit-exploited-windows-and-chrome-zero-day-flaws/
author: Aryan
date: 2026-09-11T00:00:00.000Z
tags:
  - attack.initial_access
  - attack.t1189
  - attack.privilege_escalation
  - attack.t1068
  - attack.defense_evasion
  - attack.t1218.007
  - attack.execution
  - attack.t1059.007
logsource:
  category: process_creation
  product: windows
detection:
  selection_browser_parent:
    ParentImage|endswith:
      - '\chrome.exe'
      - '\msedge.exe'
  selection_lolbin_child:
    Image|endswith:
      - '\msiexec.exe'
      - '\rundll32.exe'
      - '\mshta.exe'
      - '\powershell.exe'
      - '\cmd.exe'
  filter_known_updater:
    Image|endswith:
      - '\GoogleUpdate.exe'
      - '\setup.exe'
  condition: selection_browser_parent and selection_lolbin_child and not filter_known_updater
falsepositives:
  - Enterprise-managed browser deployments that legitimately shell out to an installer helper during extension/update flows (rare - verify against known update channels and signed binaries)
  - Accessibility or kiosk-mode browser configurations that intentionally launch helper processes
level: critical
```

## Prevention

- Patch Chrome/Chromium to 152.0.7977.82 or later immediately, and treat any Chromium-based browser (Edge, Brave, etc.) as in-scope until its own vendor ships the equivalent fix.
- Apply the Windows update addressing CVE-2026-85880 (ALPC heap overflow) - it's the step that actually escapes the browser sandbox and matters even if the initial V8 bug can't be exploited in your environment.
- Alert on any browser process (Chrome, Edge) spawning a LOLBin child process as a standing detection - this parent-child relationship is not the normal footprint of routine browsing or updates.
- Treat "already fixed in the public Chromium source but not yet in stable" as an active exploitation window, not a resolved issue - attackers monitor public open-source fixes specifically to weaponize this gap before general availability.

*See also: [UTA0560 - China-Linked Espionage Actor Behind the BlueMoon Chrome/Windows Zero-Day Chain](/actors/uta0560/) for the actor's broader behavioral pattern.*

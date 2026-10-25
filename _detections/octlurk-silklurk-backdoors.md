---
title: "OctLurk & SilkLurk - Victim-Tailored Backdoors Targeting Central Asian Governments (Threat Brief)"
layout: default
---

## Overview

**OctLurk** and **SilkLurk** are two related Windows backdoor families that Kaspersky's Global Research and Analysis Team (GReAT) disclosed on 2026-07-30, tied to a cyber-espionage campaign active since at least January 2025. Victims span government ministries, law enforcement agencies, healthcare and research organizations, and logistics and urban-planning bodies in Afghanistan, Kazakhstan, Kyrgyzstan, Tajikistan, Uzbekistan, and the Syrian Arab Republic. Kaspersky assesses with **medium confidence** that a single Chinese-speaking actor operates both families, but could not tie the campaign to any previously tracked, named APT group - the operators remain formally unattributed. The campaign also deployed the well-known **PlugX** backdoor alongside the two new families, and uses a companion tunneling utility, **LurkProxy**, that shares OctLurk's code architecture.

The defining engineering trait of both backdoors is **victim-specific payload decryption**: rather than shipping a generically-decryptable payload that any sandbox could detonate, each loader derives part of its decryption key from data unique to the intended target machine. OctLurk keys its payload decryption to the **volume serial number of the system drive**; SilkLurk instead hashes the **victim's computer name**. A copy of either sample run on any machine other than its intended target simply fails to decrypt and never reveals its second-stage payload - a deliberate anti-sandbox, anti-analysis measure that goes well beyond typical environment checks. Persistence differs between the two: OctLurk is installed via scheduled tasks and malicious Windows services after the operator has already obtained administrative credentials, while SilkLurk side-loads a malicious DLL through legitimate, signed NVIDIA and Realtek utilities and then registers a service configured to auto-restart on failure. Both keep their main component resident only in memory, leaving a minimal loader on disk. Post-infection, both support a modular, downloadable plugin architecture covering command execution, filesystem manipulation, synthetic keyboard/mouse input, network and host scanning, credential dumping, keylogging, browser-stored password theft, and email collection - with at least one documented plugin disguising itself as AnyDesk to blend into remote-access tooling IT staff already expect to see in these environments.

## Why this matters for detection

Victim-specific keying defeats the sandbox-detonation and hash-matching workflows that most malware triage pipelines depend on - there's no universal "defanged" sample to study, because the payload simply won't decrypt off the intended host. That pushes detection toward the parts of the chain that *can't* be victim-tailored: the side-loading mechanic (a legitimate, signed NVIDIA/Realtek binary loading a DLL from an unexpected path), the persistence footprint (new scheduled tasks or auto-restarting services appearing shortly after administrative-credential use), and plugin-masquerade naming (a process named after AnyDesk that doesn't match the real binary's signing certificate or install path). Each of these is detectable from endpoint telemetry alone, without ever needing to see - let alone decrypt - the actual payload.

## Detection Guidance

```yaml
title: Signed Utility Side-Loading DLL from Non-Standard Path with Auto-Restarting Service
status: experimental
description: >-
  Detects a legitimate, signed NVIDIA or Realtek executable loading a DLL
  from a non-standard or user-writable path, followed by registration of a
  service configured to restart on failure - consistent with the SilkLurk
  side-loading and persistence mechanism observed in the OctLurk/SilkLurk
  Central Asian espionage campaign (Kaspersky GReAT, 2026-07-30).
references:
  - https://www.kaspersky.com/about/press-releases/kaspersky-uncovers-victim-tailored-backdoors-in-central-asia-targeting-government-healthcare-and-research
  - https://thehackernews.com/2026/08/suspected-chinese-speaking-hackers.html
  - https://blog.polyswarm.io/octlurk-and-silklurk-analysis-of-a-modular-cyber-espionage-framework
  - https://hackread.com/octlurk-silklurk-backdoors-target-6-countries/
author: Aryan
date: 2026-10-25T00:00:00.000Z
tags:
  - attack.defense_evasion
  - attack.t1574.002
  - attack.persistence
  - attack.t1543.003
  - attack.t1053.005
  - attack.command_and_control
  - attack.t1090
logsource:
  category: image_load
  product: windows
detection:
  selection_signed_loader:
    Image|contains:
      - 'nvidia'
      - 'realtek'
    Image|endswith: '.exe'
  selection_nonstandard_dll_path:
    ImageLoaded|contains:
      - '\AppData\'
      - '\Temp\'
      - '\ProgramData\'
  selection_service_autorestart:
    EventID: 7045
    ServiceFileName|contains:
      - 'AppData'
      - 'ProgramData'
  condition: (selection_signed_loader and selection_nonstandard_dll_path) or selection_service_autorestart
  timeframe: 15m
  # Escalate to critical if a process named "AnyDesk" or "anydesk.exe" is
  # observed without a matching Authenticode signature from AnyDesk
  # Software GmbH, or outbound traffic to an unexpected proxy/relay
  # follows within the same session (LurkProxy-style tunneling)
falsepositives:
  - Legitimate NVIDIA/Realtek driver or utility updates that temporarily stage DLLs in a user or ProgramData path during install
  - Third-party software that intentionally registers auto-restarting Windows services (monitoring agents, update services)
level: high
```

## Prevention

- Verify Authenticode signatures on any process named after remote-access tools (AnyDesk, TeamViewer, etc.) rather than trusting the filename - plugin-masquerade naming is specifically designed to pass a quick visual check.
- Alert on DLL loads by signed vendor executables (NVIDIA, Realtek, and similar OEM utilities) from AppData, Temp, or ProgramData paths - legitimate vendor DLLs almost always ship alongside the executable in Program Files, not in user-writable directories.
- Monitor Windows service creation events (Event ID 7045) for services pointing at binaries in user-writable paths, especially when configured to auto-restart on failure.
- Because both backdoors key their decryption to machine-specific data, static signature or hash-based detection will miss new victims entirely - prioritize the behavioral indicators above (side-loading, persistence footprint, masquerade naming) over any published IOC list, which will already be stale for the next target.
- Restrict and audit administrative credential use, since OctLurk's scheduled-task/service installation path assumes the operator already has admin rights on the target host.

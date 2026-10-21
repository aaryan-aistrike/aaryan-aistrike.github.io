---
title: "XWorm - Leaked-Builder RAT Evolves Into a Browser-Session-Hijacking Surveillance Kit (Threat Brief)"
layout: default
---

## Overview

**XWorm** is a commodity .NET remote access trojan that has circulated since at least 2022, but new research from Netskope Threat Labs (published 2026-09, widely covered through October 2026) shows it evolving well past a basic RAT. A publicly leaked builder - first cracked and circulated in mid-2025, then followed by a full leak of the version 6.4 source code - triggered an explosion of concurrent forks: versions 6.4, 6.5 ("XWorm Reborn"), 7.2, and 7.4 are all active in the wild at once, maintained by different, unrelated operators rather than a single group. Netskope recorded 1,236 detection events across more than 100 customer organizations in Q3 2026 - roughly four times the volume seen in the same quarter of 2025.

The leaked builder's extensibility has turned XWorm into a surveillance platform: its plugin ecosystem grew from 35 modules in July 2025 to 46 by October 2026, adding a Maps plugin for device geolocation, a Microphone plugin for live audio capture, and - most notably - **HBrowser**, which lets an operator remotely drive a victim's already-authenticated browser session. HBrowser doesn't break MFA cryptography; instead it sends an OpenBrowser command over XWorm's AES-encrypted C2 channel to take over a browser tab the victim has already signed into, then relays base64-encoded keyboard, mouse, and clipboard actions into it - giving the operator whatever the victim's existing session already grants, regardless of how strong the original login was. Financial-services organizations make up roughly 35% of affected customers, with detections concentrated in India, Brazil, Italy, Panama, and the US.

Delivery stays consistent with XWorm's long-documented infection chain: phishing lures (fake invoices, FedEx delivery notices, bank payment receipts) carry a malicious attachment or script that runs a fileless PowerShell loader, which process-hollows the actual XWorm payload into a trusted .NET utility - MSBuild.exe, CasPol.exe, InstallUtil.exe, or RegAsm.exe - to run in memory and dodge on-disk AV scanning.

## Why this matters for detection

Because the builder is leaked and the plugin system is modular, no single IOC set, hash, or C2 domain list will keep pace - different operators run different forks against different infrastructure. What's stable across nearly every documented wave is the *loader mechanic*: a script host spawning PowerShell, which in turn launches a signed .NET utility that is never normally invoked that way, to host injected code purely in memory. That parent-child process pattern is far more durable than any indicator tied to a specific build, and it's detectable from process-creation telemetry alone, without needing to see the payload. HBrowser is also a reminder that MFA is not by itself a session-security boundary - once an endpoint is compromised, every "already authenticated" browser tab on it is exposed no matter how strong the original login was.

## Detection Guidance

```yaml
title: XWorm-Style Fileless Loader - Script Host Spawning Trusted .NET Utility for Process Hollowing
status: experimental
description: >-
  Detects a PowerShell or script-host process spawning a trusted .NET
  utility (MSBuild, CasPol, InstallUtil, RegAsm, RegSvcs) without the
  command-line arguments that utility's legitimate use normally requires,
  consistent with the fileless process-hollowing loader chain used to run
  XWorm and its "XWorm Reborn" forks entirely in memory.
references:
  - https://threatlabs.netskope.com/blog/2026/09/xworm-reborn
  - https://securityaffairs.com/200910/malware/how-a-leaked-builder-of-xworm-turned-a-remote-access-trojan-into-a-surveillance-kit.html
  - https://gbhackers.com/xworm-hbrowser-plugin/
  - https://www.securityweek.com/xworm-rat-evolves-into-surveillance-platform/
author: Aryan
date: 2026-10-21T00:00:00.000Z
tags:
  - attack.execution
  - attack.t1127.001
  - attack.defense_evasion
  - attack.t1055.012
  - attack.collection
  - attack.t1185
  - attack.t1123
logsource:
  category: process_creation
  product: windows
detection:
  selection_loader_parent:
    ParentImage|endswith:
      - '\powershell.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
  selection_hollowed_target:
    Image|endswith:
      - '\msbuild.exe'
      - '\caspol.exe'
      - '\installutil.exe'
      - '\regasm.exe'
      - '\regsvcs.exe'
  filter_legit_project_args:
    CommandLine|contains:
      - '.csproj'
      - '.sln'
      - '.proj'
  condition: selection_loader_parent and selection_hollowed_target and not filter_legit_project_args
  # Escalate to critical if the hollowed process subsequently opens an
  # outbound connection or accesses another process's memory (Sysmon
  # Event ID 10) shortly after spawning
falsepositives:
  - Legitimate CI/CD pipelines invoking MSBuild from a build or deploy script
  - Signed installers or update scripts chaining through InstallUtil/RegAsm/RegSvcs for .NET component registration
  - Administrative automation scripts using PowerShell to launch build tooling
level: high
```

## Prevention

- Treat a PowerShell or script-host child spawning MSBuild.exe, CasPol.exe, InstallUtil.exe, or RegAsm.exe/RegSvcs.exe without the command-line arguments that tool's legitimate use normally requires as a high-confidence injection indicator, not just an oddity.
- Constrain execution of these trusted .NET utilities outside known build/deployment contexts via WDAC or AppLocker - legitimate end-user invocation of them is rare.
- Don't rely on MFA alone as a session-security boundary; pair it with device-compliance checks and short session/token lifetimes so a compromised endpoint can't silently ride an already-authenticated session indefinitely.
- Audit microphone and location-permission grants on business endpoints, not just mobile devices - desktop RATs are increasingly bundling the same surveillance capability mobile malware has had for years.

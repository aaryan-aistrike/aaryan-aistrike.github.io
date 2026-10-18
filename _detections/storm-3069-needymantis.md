---
title: "NeedyMantis - DLL Sideloading Loader Chain and WebSockets C2 (Threat Brief)"
layout: default
---

## Overview

On 2026-09-28, Microsoft published research on **NeedyMantis**, a modular post-compromise malware family it ties to an actor it tracks as **Storm-3069**, assessed with medium confidence to originate from China. Microsoft found the cluster while pivoting off indicators tied to Kaspersky's reporting on the May 2026 DAEMON Tools supply-chain compromise; NeedyMantis itself has not been observed spreading via a supply chain, but is instead deployed manually once an operator already has a foothold, to maintain long-term access and stage follow-on operations. Observed activity dates back to at least October 2025. Confirmed victims span telecommunications providers, universities, intergovernmental organizations, medical nonprofits, and government contractors - a limited, selective set of targets Microsoft says is consistent with Chinese strategic interests.

The infection chain packages a malicious loader DLL alongside a legitimate application and launches it via **DLL sideloading** - observed abusing Poedit (`WinSparkle.dll`), curl (`libcurl.dll`), Vim (`vim64.dll`), TightVNC, Microsoft Office and Broadcom software (`dbghelp.dll`), Intel software (`jli.dll`), and NVIDIA software (`nvml.dll`). The sideloaded first-stage DLL only extracts and runs a second stage from a bundled custom-encrypted archive; that second stage, despite carrying a `.ps1` extension, is actually x64 shellcode that unpacks a main component communicating over HTTPS before upgrading the connection to a binary WebSockets protocol for ongoing command-and-control.

## Why this matters for detection

Because the malware's job is specifically to hide inside trusted software, hash- and filename-based detection ages out the moment Storm-3069 (or another NeedyMantis operator) swaps carrier applications. What holds constant is the **sideloading pattern**: a DLL with a name matching a legitimate update/library component (`WinSparkle.dll`, `libcurl.dll`, `dbghelp.dll`, `jli.dll`, `nvml.dll`, `vim64.dll`) loading from a path that vendor never installs to - `ProgramData\USOShared`, `ProgramData\broadcom`, `ProgramData\Intel`, `ProgramData\VIM`, or `ProgramData\office` rather than each application's real Program Files directory. The protocol's HTTPS-to-WebSockets upgrade, paired with a hard-coded `firefox/21.0` user-agent on the initial beacon, is a second, carrier-independent signal that survives changes to the sideloaded application entirely.

## Detection Guidance

```yaml
title: Known-Vendor DLL Name Loaded From a Non-Standard ProgramData Path
status: experimental
description: >-
  Detects a DLL matching the name of a legitimate vendor update or library
  component (WinSparkle.dll, libcurl.dll, dbghelp.dll, jli.dll, nvml.dll,
  vim64.dll) being loaded from a ProgramData subdirectory rather than that
  vendor's standard Program Files installation path, consistent with the
  DLL-sideloading loader chain used to deploy the NeedyMantis malware
  family (Storm-3069).
references:
  - https://microsoft.com/en-us/security/blog/2026/09/28/needymantis-unpacking-a-post-compromise-malware-family-used-in-targeted-operations
  - https://thehackernews.com/2026/09/hackers-use-needymantis-to-maintain.html
  - https://www.scworld.com/brief/needymantis-malware-used-for-long-term-network-access
author: Aryan
date: 2026-10-18
tags:
  - attack.defense_evasion
  - attack.t1574.002
  - attack.command_and_control
  - attack.t1071.001
  - attack.t1573
  - attack.persistence
  - attack.t1547
logsource:
  category: image_load
  product: windows
detection:
  selection_sideload_candidate:
    ImageLoaded|endswith:
      - '\WinSparkle.dll'
      - '\libcurl.dll'
      - '\dbghelp.dll'
      - '\jli.dll'
      - '\nvml.dll'
      - '\vim64.dll'
  selection_nonstandard_path:
    ImageLoaded|contains:
      - '\ProgramData\USOShared\'
      - '\ProgramData\broadcom\'
      - '\ProgramData\Intel\'
      - '\ProgramData\VIM\'
      - '\ProgramData\office\'
      - '\ProgramData\ics\'
  condition: selection_sideload_candidate and selection_nonstandard_path
  # Correlate: the loading process (Image) should also be checked against
  # an outbound HTTPS connection that later upgrades to a WebSockets
  # protocol, or a request carrying the User-Agent "firefox/21.0" - either
  # is a strong secondary signal of the NeedyMantis C2 channel
falsepositives:
  - Legitimate third-party packaging tools that stage vendor update components under ProgramData during custom deployment workflows
  - Endpoint management or imaging software that intentionally relocates these DLLs as part of a golden-image build process
level: high
```

## Prevention

- Hunt for the listed DLL names loading from any path outside each vendor's documented installation directory - the sideloading pattern itself is more durable than any single sample hash.
- Baseline and alert on the HTTPS-to-WebSockets protocol upgrade pattern at the network egress layer, and specifically flag the `firefox/21.0` user-agent string, which is unusual for 2026-era legitimate traffic.
- Restrict and audit lateral-movement tooling such as Impacket, which Microsoft observed being used to manually copy the carrier application, loader DLL, and payload archive onto new hosts from a network share.
- Enable attack surface reduction rules that block execution of potentially obfuscated scripts and restrict unsigned or low-prevalence executables, and run EDR in block mode even where third-party antivirus is also deployed.

*See also: [Storm-3069 - China-Based Actor Behind the NeedyMantis Long-Term Access Toolkit](/actors/storm-3069-needymantis/) for the actor's broader behavioral pattern.*

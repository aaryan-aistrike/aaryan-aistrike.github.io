---
title: "SparroWocky - FamousSparrow's DLL Side-Load Backdoor Targeting Latin American Governments (Threat Brief)"
layout: default
---

## Overview

On 2026-09-17, ESET disclosed **SparroWocky**, a new modular C++ backdoor that the China-aligned espionage group **FamousSparrow** has used since at least August 2025 to progressively replace its longstanding **SparrowDoor** implant. The name comes from the first stanza of Lewis Carroll's "Jabberwocky," found in early build strings. ESET's telemetry shows roughly 90% of FamousSparrow's observed targets from mid-2025 into 2026 were government entities in Latin America - Argentina, Ecuador, Guatemala, Honduras, Panama, Peru, Puerto Rico, and Venezuela - a pivot ESET links to US-China geopolitical competition over the region, with one targeted Panamanian organization directly tied to the CK Hutchison Panama Canal ports dispute.

Execution follows a DLL side-loading chain consistent with FamousSparrow's prior campaigns: a legitimate executable loads a malicious DLL side by side with it, which then RC4-decrypts and reflectively maps an encrypted payload directly into process memory - the backdoor never exists on disk as a standalone executable. ESET's own IOC set names two SparroWocky loader DLLs, `winfsp-x64.dll` and `DukeQt.dll`. The backdoor supports arbitrary command/executable execution, TCP proxying, file theft, host reconnaissance, session enumeration, screenshot capture, and loading Beacon Object Files compatible with Cobalt Strike or Sliver. ESET identified at least 18 distinct C2 IP addresses, communicating over TLS with RC4-encrypted command data inside the tunnel. Persistence techniques documented for this campaign include Windows service creation, registry Run-key/startup-folder placement, scheduled tasks, masquerading of the created task or service, and clearing of persistence artifacts after use.

## Why this matters for detection

SparroWocky's final payload is fileless by design - it is decrypted and mapped into memory by the loader DLL, so endpoint tooling that only inspects on-disk executables or relies on static signatures will miss the backdoor itself. The detectable surface is the **loader DLL's filename and load context**: `winfsp-x64.dll` and `DukeQt.dll` are not standard Windows system components, so either name loading into a process - particularly from outside an application's own installation directory, or alongside an unrelated host executable - is a strong, low-noise signal regardless of what the in-memory payload later does. This also illustrates why filename allowlisting alone is insufficient against this actor: FamousSparrow has repeatedly reused the side-load-a-trusted-binary technique across multiple implant generations (SparrowDoor, ShadowPad, and now SparroWocky) with different DLL names each time, so the durable detection is the *behavior pattern* - an unexpected DLL load immediately followed by outbound TLS traffic from that process - not any single filename.

## Detection Guidance

```yaml
title: SparroWocky Loader DLL Image Load Followed by Anomalous Persistence
status: experimental
description: >-
  Detects the SparroWocky loader DLLs (winfsp-x64.dll, DukeQt.dll) loading
  into a process, or a Windows service/scheduled task/registry Run key
  created shortly afterward, consistent with FamousSparrow's DLL
  side-loading and reflective-payload-mapping execution chain.
references:
  - https://github.com/eset/malware-ioc/blob/master/famoussparrow/README.adoc
  - https://thehackernews.com/2026/09/china-aligned-famoussparrow-deploys.html
  - https://www.bleepingcomputer.com/news/security/chinese-hackers-use-sparrowocky-malware-in-govt-espionage-attacks/
author: Aryan
date: 2026-10-26T00:00:00.000Z
tags:
  - attack.defense_evasion
  - attack.t1574.001
  - attack.t1027
  - attack.t1140
  - attack.persistence
  - attack.t1543.003
  - attack.t1547.001
  - attack.t1053.005
  - attack.t1036.004
  - attack.t1070.009
  - attack.command_and_control
  - attack.t1071.001
logsource:
  category: image_load
  product: windows
detection:
  selection_loader_dll_load:
    ImageLoaded|endswith:
      - '\winfsp-x64.dll'
      - '\DukeQt.dll'
  filter_known_legitimate_path:
    ImageLoaded|contains:
      - '\Program Files\WinFsp\'
      - '\Windows\System32\'
      - '\Windows\SysWOW64\'
  selection_new_service:
    EventID: 4697
  selection_scheduled_task:
    EventID: 4698
  condition: (selection_loader_dll_load and not filter_known_legitimate_path) or (selection_loader_dll_load and (selection_new_service or selection_scheduled_task))
  timeframe: 15m
  # Correlate: outbound TLS connection on 443/8080 from the host process
  # shortly after the loader DLL load, to infrastructure outside known
  # business SaaS/CDN ranges
falsepositives:
  - Legitimate WinFsp (Windows File System Proxy) driver installations, which ship an unrelated winfsp-x64.dll from Program Files - verify install path and digital signature before alerting
  - Software packaging that happens to reuse the DukeQt.dll filename in an unrelated, legitimately signed product (verify publisher/signature if this fires)
level: high
```

## Prevention

- Treat `winfsp-x64.dll` or `DukeQt.dll` loading from any path other than a verified legitimate WinFsp installation as a confirmed compromise indicator, not a tuning exception - both names are specific enough that collision with unrelated software is uncommon.
- Apply Windows Defender Application Control or equivalent allowlisting to block unsigned or hash-mismatched DLLs from loading under trusted process names, closing the side-loading vector FamousSparrow has reused across SparrowDoor, ShadowPad, and SparroWocky.
- Monitor for new Windows services, scheduled tasks, or Run-key entries created within minutes of an unrecognized DLL load - the correlation is far more actionable than either event alone.
- Government and public-sector organizations in Latin America should treat this campaign's geographic focus as an active, elevated-priority threat given ESET's explicit geopolitical attribution, independent of any organization's own prior targeting history.
- Inspect outbound TLS traffic on 443/8080 for destination infrastructure matching ESET's published C2 IOC list, and rotate blocklists as vendors publish updates.

*See also: [FamousSparrow - China-Aligned Espionage Actor Behind the SparroWocky Backdoor](/actors/famoussparrow/) for the actor's broader behavioral pattern.*

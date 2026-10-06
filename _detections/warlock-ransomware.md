---
title: "Warlock Ransomware - SYSVOL-Staged Deployment via Active Directory Replication (Threat Brief)"
layout: default
---

## Overview

**Warlock** is the ransomware payload deployed by a China-nexus intrusion set that Symantec tracks as **Longlegs** and Microsoft tracks as **Storm-2603**. The group first gained attention exploiting the Microsoft SharePoint "ToolShell" vulnerability chain (CVE-2025-49704, CVE-2025-49706, CVE-2025-53770, CVE-2025-53771) for broad opportunistic access in 2025. Reporting from late September/early October 2026 shows a pivot toward fewer, higher-value targets - a water utility, a telecommunications provider, a regional government body, and a university, concentrated in Spanish- and Portuguese-speaking countries across Europe, Africa, and Latin America.

Technically, two things stand out. First, the group abuses a vulnerable, signed driver (**K7RKScan**) in a BYOVD (Bring Your Own Vulnerable Driver) attack to disable security tooling at scale - one documented intrusion pushed the EDR-killing driver to at least 40 hosts within roughly two hours. Second, and more unusual, the group stages the Warlock binary directly inside the target domain's **SYSVOL** share, so ordinary Distributed File System Replication (DFSR) carries the ransomware to every domain controller and from there to member hosts - the same intrusion deployed Warlock on at least 33 hosts purely through this replication path, alongside DLL sideloading for execution and abuse of Visual Studio Code's remote tunneling feature for covert remote access.

## Why this matters for detection

Most ransomware lateral movement relies on PsExec, WMI, or RDP - all well-covered by existing detections. Warlock's SYSVOL-staging technique sidesteps that entirely: it turns a trusted, domain-wide replication mechanism that most environments don't monitor for payload delivery into the distribution channel itself. A file-integrity or EDR policy that only watches `C:\Windows\System32` or user-writable paths will miss an executable dropped into `\SYSVOL\<domain>\scripts` or `\policies`, even though that location is readable by every domain-joined host and gets pushed out automatically by AD replication. Combined with BYOVD-based EDR killing (itself invisible to the very tooling it's disabling) and covert remote access riding on legitimate VS Code tunnel traffic, the overall chain is built around abusing trusted mechanisms rather than deploying anything a signature would easily flag.

## Detection Guidance

```yaml
title: Warlock Ransomware - SYSVOL Payload Staging and Vulnerable Driver Drop
status: experimental
description: >-
  Detects an executable or DLL written into a domain's SYSVOL share, or a
  file matching the K7RKScan vulnerable driver being dropped to disk,
  consistent with Warlock/Longlegs (Storm-2603) staging ransomware for
  Active-Directory-replication-based mass distribution and BYOVD-based
  EDR killing following SharePoint ToolShell exploitation.
references:
  - https://thehackernews.com/2026/10/warlock-exploits-sharepoint-flaws-to.html
  - https://therecord.media/warlock-ransomware-used-in-critical-infrastructure-attacks
  - https://industrialcyber.co/ransomware/symantec-reports-warlock-ransomware-group-targets-water-telecom-government-organizations-through-sharepoint-flaws/
author: Aryan
date: 2026-10-06T00:00:00.000Z
tags:
  - attack.defense_evasion
  - attack.t1562.001
  - attack.persistence
  - attack.t1484.001
  - attack.lateral_movement
  - attack.t1021
  - attack.impact
  - attack.t1486
logsource:
  category: file_event
  product: windows
detection:
  selection_sysvol_payload:
    TargetFilename|contains: '\SYSVOL\'
    TargetFilename|endswith:
      - '.exe'
      - '.dll'
  selection_vulnerable_driver_drop:
    TargetFilename|endswith: '.sys'
    TargetFilename|contains: 'k7rkscan'
  condition: selection_sysvol_payload or selection_vulnerable_driver_drop
  timeframe: 2h
  # Escalate to critical if the SYSVOL-staged file is then observed executing
  # from the local NETLOGON/SYSVOL replica cache on 3+ distinct domain-joined
  # hosts within the timeframe - the signature of replication-driven mass
  # deployment rather than a routine GPO/logon-script update
falsepositives:
  - Legitimate GPO logon-script or software-deployment packages pushed through SYSVOL by IT/systems management tooling
  - Third-party security products that coincidentally share naming with the abused driver (verify file hash/signer before dismissing)
level: critical
```

## Prevention

- Patch on-premises SharePoint against the ToolShell chain (CVE-2025-49704, CVE-2025-49706, CVE-2025-53770, CVE-2025-53771) - every observed Warlock intrusion starts there.
- Monitor SYSVOL for unexpected executable/DLL writes and treat it as a payload-delivery surface, not just a policy store - this is the group's signature distribution mechanism and goes unmonitored in most environments.
- Deploy and keep current Microsoft's vulnerable driver blocklist policy (or an equivalent allowlist) to stop K7RKScan-style BYOVD EDR killing before it executes.
- Alert on `code tunnel` / VS Code remote-tunneling activity originating from servers and infrastructure hosts that have no legitimate reason to run developer tooling.

*See also: [Warlock / Longlegs / Storm-2603 - China-Nexus Ransomware Exploiting SharePoint ToolShell Flaws](/actors/warlock/) for the actor's broader behavioral pattern.*

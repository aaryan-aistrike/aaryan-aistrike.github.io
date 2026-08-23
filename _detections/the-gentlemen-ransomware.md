---
title: "The Gentlemen - Fast-Scaling Cross-Platform RaaS (Threat Brief)"
layout: default
---

## Overview

**The Gentlemen** is a ransomware-as-a-service operation that emerged around mid-2025 and became the most active ransomware threat actor in Q2 2026, scaling faster than any previously tracked group. It claimed more than 328 victims in the first five months of 2026 alone - roughly 10% of all global ransomware claims in that period - and by 2026-07-07 its leak site listed 580 victims across 77 countries. Monthly activity nearly doubled between January (48 attacks) and February (91 attacks) 2026.

Technically, the group's defining trait is **cross-platform reach**: it deploys separate ransomware lockers targeting Windows, Linux, NAS, BSD, and ESXi, letting a single intrusion encrypt an organization's full infrastructure footprint rather than just Windows endpoints. Affiliates gain initial access through internet-facing RDP, SSL VPN endpoints, and remote management tooling, then move laterally using legitimate administrative utilities - AnyDesk and PsExec - rather than custom malware, blending into normal admin activity. In early May 2026, a breach of the group's own backend infrastructure gave researchers an unusually detailed look at how the operation runs internally. The group is believed to operate out of Russian-speaking regions, based on an internal prohibition against targeting CIS-region organizations.

## Why this matters for detection

The Gentlemen's growth curve is a direct result of using **legitimate tooling for lateral movement** rather than custom malware - which means signature-based detection on the tools themselves (AnyDesk, PsExec) is a dead end; they're deployed everywhere for legitimate reasons. What's detectable is the *sequence*: remote access tooling arriving on a host shortly after external RDP/VPN authentication, followed by PsExec-driven execution against multiple hosts, followed by encryption activity across heterogeneous platforms in a short window. The multi-OS locker strategy also means Linux/ESXi telemetry needs equal detection investment - a Windows-only detection posture leaves the NAS/hypervisor layer, which this group specifically targets, uncovered.

## Detection Guidance

```yaml
title: Cross-Platform Ransomware Precursor - Remote Access Tool Post-External-Auth
status: experimental
description: >-
  Detects AnyDesk or PsExec execution shortly following an external
  RDP/VPN authentication event on the same host, consistent with
  RaaS-affiliate lateral movement staging prior to multi-platform
  encryption (as seen in The Gentlemen intrusions).
references:
  - https://research.checkpoint.com/2026/thus-spoke-the-gentlemen/
  - https://www.halcyon.ai/ransomware-research-reports/threat-assessment-the-gentlemen-ransomware-group
  - https://thecyberexpress.com/the-gentlemen-ransomware-group/
author: Aryan
date: 2026-08-23T00:00:00.000Z
tags:
  - attack.lateral_movement
  - attack.t1021
  - attack.impact
  - attack.t1486
  - attack.t1072
logsource:
  category: process_creation
  product: windows
detection:
  selection_external_auth:
    EventID: 4624
    LogonType:
      - 10   # RemoteInteractive (RDP)
      - 3    # Network (VPN-terminated)
  selection_remote_tooling:
    Image|endswith:
      - '\anydesk.exe'
      - '\psexec.exe'
      - '\psexesvc.exe'
  condition: selection_external_auth and selection_remote_tooling
  timeframe: 30m
  # Escalate to critical if the same source account triggers this pattern
  # against 3+ distinct destination hosts within a 1h window
falsepositives:
  - IT/helpdesk staff using AnyDesk for legitimate remote support following VPN login
  - Scheduled PsExec-based deployment or patching tooling used by the systems team
level: high
```

## Prevention

- Restrict RDP and SSL VPN exposure to the smallest possible set of source IPs, and require MFA on both - this is the group's stated primary entry vector.
- Apply the same detection and hardening standard to Linux, NAS, and ESXi hosts as to Windows endpoints - this group's cross-platform lockers specifically target the infrastructure layer that's often left with the weakest telemetry.
- Alert on AnyDesk/PsExec execution as a *sequence* following external authentication, not just on the tool's presence - both are legitimate in isolation.
- Maintain offline, immutable backups for hypervisor and NAS configuration, not just VM/file data - this group's technical profile specifically threatens that layer.

*See also: [The Gentlemen - Fast-Scaling RaaS Affiliate Tradecraft](/actors/the-gentlemen/) for the actor's broader behavioral pattern.*

---
title: "AuditTeam - OpsAgent BYOVD Defense-Evasion Chain (Threat Brief)"
layout: default
---

## Overview

**AuditTeam** is a ransomware group that Kaspersky's GReAT team publicly detailed on 2026-11-18, having tracked its activity from January through October 2026. The group compromised dozens of organizations across at least seven countries and territories, with confirmed victims in China, Finland, Hong Kong, Italy, the Philippines, Russia, and Senegal. Its core tooling is a custom, likely AI-assisted modular framework called **OpsAgent**, first observed on 2026-03-10 in a Hong Kong intrusion.

OpsAgent ships obfuscated loaders in multiple languages (C, .NET, and Rust) that inject the implant into legitimate processes such as `msiexec.exe`, then escalate privileges using built-in Windows commands and token theft rather than custom exploits. Its signature move is a BYOVD (bring-your-own-vulnerable-driver) module that drops a digitally signed driver from Beijing Jiangmin Antivirus and abuses it to terminate security, backup, and database processes ahead of encryption. The ransom note is framed as an "Audit & Consulting fee" invoice, offering a "vulnerability report" in exchange for payment - the extortion message never mentions encryption directly.

## Why this matters for detection

AuditTeam's defense-evasion chain works precisely because the driver it abuses is legitimately signed - it is not malware in the traditional sense, so signature- and reputation-based AV/EDR controls won't flag the driver file itself. What's detectable is the **behavioral sequence**: a previously-unseen signed driver loading on an endpoint, followed in short order by the termination of multiple security, backup, or database processes in a correlated burst. That sequence is abnormal regardless of which specific driver is used, which matters because BYOVD tooling rotates frequently across ransomware crews. The social-engineering angle - a ransom note worded as a business "audit" invoice - is also worth training staff on directly, since it's designed not to trigger the instinctive "this is ransomware" reaction that a traditional extortion note would.

## Detection Guidance

```yaml
title: Newly Loaded Signed Driver Followed by Correlated Security Process Termination
status: experimental
description: >-
  Detects a rarely-seen or newly-installed kernel driver loading shortly
  before multiple distinct security, backup, or database processes
  terminate in a short window, consistent with BYOVD-based defense
  evasion preceding ransomware deployment (as used by AuditTeam/OpsAgent).
references:
  - https://www.kaspersky.com/about/press-releases/kaspersky-uncovers-auditteam-ransomware-campaign-spanning-europe-asia-and-africa
  - https://securelist.com/auditteam-opsagent-forced-audit/122031/
  - https://blog.gridinsoft.com/auditteam-opsagent-ransomware-audit-fee/
author: Aryan
date: 2026-11-25T00:00:00.000Z
tags:
  - attack.defense_evasion
  - attack.t1562.001
  - attack.t1068
  - attack.privilege_escalation
  - attack.t1078
  - attack.impact
  - attack.t1486
logsource:
  category: driver_load
  product: windows
detection:
  selection_driver_load:
    TargetFilename|endswith: '.sys'
    Signed: true
  selection_mass_process_termination:
    EventType: 'process_terminated'
    Image|contains:
      - 'edr'
      - 'defender'
      - 'backup'
      - 'sql'
      - 'veeam'
  condition: selection_driver_load and selection_mass_process_termination
  timeframe: 15m
  # Escalate to critical if 5+ distinct security/backup/database processes
  # terminate within the timeframe following the driver load event
falsepositives:
  - Legitimate AV/EDR product upgrades that install a new signed driver and briefly restart their own services
  - Scheduled backup software maintenance windows that stop and restart database/backup agents
  - IT-initiated driver rollouts via approved software deployment tooling
level: high
```

## Prevention

- Maintain and enforce a Microsoft-recommended vulnerable-driver blocklist (or equivalent) rather than trusting code-signing alone - a valid signature does not mean a driver is safe to load.
- Alert on any kernel driver load that is new to the environment or rarely seen across the fleet, not just on known-malicious driver hashes, since BYOVD tooling rotates between campaigns.
- Monitor for correlated termination of security, backup, and database processes as a single behavioral signal rather than relying on any one product's self-protection tamper alerts in isolation.
- Train staff to recognize extortion attempts that are deliberately worded to avoid looking like ransomware - an unsolicited "security audit" or "consulting fee" invoice following unexplained system disruption should be treated as a security incident, not a billing question.

*See also: [AuditTeam - Ransomware Group Disguising Extortion as a Paid Security Audit](/actors/auditteam/) for the actor's broader behavioral pattern.*

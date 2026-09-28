---
title: "n0n - Shadow Copy and Backup Catalog Destruction (Threat Brief)"
layout: default
---

## Overview

**n0n** is a ransomware operation first identified by CyberXTron researchers on 2026-09-18. It quickly established a Tor-hosted leak site and claimed more than a dozen victims within four days - financial services organizations bore the brunt (23% of victims), followed by technology, retail, and education (15% each), with the US as the primary target but victims claimed globally.

The group's defining trait is going a step past standard double extortion: alongside stealing data and threatening to leak it, n0n explicitly threatens to **encrypt or destroy victim backups and shadow copies**, aiming to remove recovery as a fallback entirely rather than just slow it down. Initial access comes from credentials harvested by third-party infostealer malware rather than n0n's own tooling; operators then escalate privileges and abuse legitimate administrative access to stage and exfiltrate data ahead of extortion demands.

## Why this matters for detection

Because backup and shadow-copy destruction is n0n's stated core leverage, the highest-value detection surface is the small set of native Windows utilities capable of doing it - `vssadmin`, `wbadmin`, `wmic`, `diskshadow`, and `bcdedit` - which is exactly the MITRE ATT&CK **T1490 (Inhibit System Recovery)** technique. None of these tools are inherently malicious (backup software and IT admins use them routinely), so the signal comes from *context*: this activity firing on a host that recently saw an anomalous authentication (new geography, new device, no MFA - consistent with infostealer-sourced credential reuse) outside of a scheduled backup maintenance window is a far stronger indicator than the command alone.

## Detection Guidance

```yaml
title: Shadow Copy or Backup Catalog Deletion via Native Windows Utilities
status: experimental
description: >-
  Detects vssadmin, wbadmin, wmic, diskshadow, or bcdedit being used to
  delete shadow copies, wipe backup catalogs, or disable Windows recovery
  options - consistent with n0n's stated tactic of destroying victim
  backups to remove recovery options ahead of double-extortion demands.
references:
  - https://www.scworld.com/brief/new-ransomware-group-n0n-escalates-threats-by-targeting-backups
  - https://www.infosecurity-magazine.com/news/ransomware-gang-uses-backup/
  - https://mallory.ai/stories/01a0d404-9482-78ce-953c-062fa47c6c0b
  - https://attack.mitre.org/techniques/T1490/
author: Aryan
date: 2026-09-28T00:00:00.000Z
tags:
  - attack.impact
  - attack.t1490
  - attack.credential_access
  - attack.t1078
  - attack.privilege_escalation
logsource:
  category: process_creation
  product: windows
detection:
  selection_tools:
    Image|endswith:
      - '\vssadmin.exe'
      - '\wbadmin.exe'
      - '\wmic.exe'
      - '\diskshadow.exe'
      - '\bcdedit.exe'
  selection_commands:
    CommandLine|contains:
      - 'delete shadows'
      - 'shadowcopy delete'
      - 'delete catalog'
      - 'delete systemstatebackup'
      - 'recoveryenabled no'
      - 'bootstatuspolicy ignoreallfailures'
  condition: selection_tools and selection_commands
  # Escalate to critical if preceded within 24h by an anomalous
  # authentication event (new geo/device, no MFA) on the same account
  falsepositives:
    - Scheduled backup software performing routine shadow copy or catalog rotation
    - IT admin manually clearing old shadow copies to reclaim disk space
    - Disaster-recovery testing or backup software migrations
level: high
```

## Prevention

- Keep backups immutable, versioned, and offline or air-gapped from the production domain - this directly neutralizes n0n's stated core leverage.
- Monitor infostealer log marketplaces and credential-exposure feeds for your organization's domains, since that's this group's documented entry vector.
- Enforce MFA on all remote access and backup administration consoles, and rotate any credentials found exposed in stealer logs immediately.
- Restrict shadow-copy and backup-catalog deletion rights to a small, monitored set of accounts, and alert on `vssadmin`/`wbadmin`/`wmic`/`diskshadow`/`bcdedit` deletion activity outside of change-managed backup maintenance windows.

*See also: [n0n - Backup-Destruction Double-Extortion Ransomware Group](/actors/n0n/) for the actor's broader behavioral pattern.*

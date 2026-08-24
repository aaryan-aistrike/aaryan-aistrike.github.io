---
title: "Storm-1175 - Rapid N-Day-to-Ransomware Post-Exploitation Pattern (Threat Brief)"
layout: default
---

## Overview

**Storm-1175** is a financially motivated, China-linked ransomware actor tracked by Microsoft Threat Intelligence, known for weaponizing N-day vulnerabilities in internet-facing software within days of public disclosure and moving from initial access to ransomware deployment in as little as 24 hours. Historically a Medusa RaaS affiliate, the group debuted a self-branded payload - StormEncryptor - on 2026-08-02, the same day a critical authentication-bypass flaw in N-able's N-central RMM platform (CVE-2026-18577) was publicly disclosed. CISA added the vulnerability to its Known Exploited Vulnerabilities catalog the following day, 2026-08-03.

StormEncryptor is a C++ payload that appends `.encrypted` to affected files and drops a `!!!README_FIRST!!!.txt` ransom note in every scanned directory. Post-compromise, the group relies on legitimate remote-management tooling (AnyDesk, SimpleHelp) for persistence, Advanced IP Scanner for network discovery, and Mimikatz for LSASS credential dumping - commodity tooling rather than custom malware for the lateral-movement phase.

## Why this matters for detection

Because Storm-1175's entire operating model depends on speed - intrusion to encryption in hours, not weeks - detections tuned for slow, methodical dwell-time patterns will often fire too late to matter. The durable signal isn't any single indicator; it's the *sequence and pace* of new-admin-account creation, remote-access tooling arrival, and credential dumping all happening in rapid succession on the same host, which is unusual regardless of which specific N-day got the group in.

## Detection Guidance

```yaml
title: Rapid Post-Exploitation Sequence - New Admin, RMM Tooling, LSASS Access
status: experimental
description: >-
  Detects a rapid sequence consistent with Storm-1175-style post-exploitation:
  a new local administrator account created shortly before AnyDesk/SimpleHelp
  execution and LSASS memory access on the same host, within a short window -
  the sequence and pace are the signal, not any single indicator alone.
references:
  - https://thehackernews.com/2026/08/china-linked-hackers-deploy-new.html
  - https://www.microsoft.com/en-us/security/blog/2026/04/06/storm-1175-focuses-gaze-on-vulnerable-web-facing-assets-in-high-tempo-medusa-ransomware-operations/
  - https://www.bleepingcomputer.com/news/security/new-stormencryptor-ransomware-used-by-former-medusa-affiliate/
author: Aryan
date: 2026-08-24T00:00:00.000Z
tags:
  - attack.persistence
  - attack.t1136.001
  - attack.credential_access
  - attack.t1003.001
  - attack.impact
  - attack.t1486
logsource:
  category: process_creation
  product: windows
detection:
  selection_new_admin:
    EventID: 4720
  selection_rmm_tooling:
    Image|endswith:
      - '\anydesk.exe'
      - '\simplehelp.exe'
      - '\advancedipscanner.exe'
  selection_lsass_access:
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains: '0x1010'
  condition: selection_new_admin and selection_rmm_tooling and selection_lsass_access
  timeframe: 6h
  # The narrow timeframe is deliberate - Storm-1175 intrusions have completed
  # initial-access-to-encryption in under 24 hours in documented cases
falsepositives:
  - Legitimate IT onboarding that happens to create an admin account and use remote-support tools within the same window
  - Authorized penetration testing or red-team engagements replicating this exact chain
level: high
```

## Prevention

- Patch internet-facing RMM, file-transfer, and edge software within days of disclosure, not weeks - this group's entire model depends on that patching gap existing.
- Treat N-able N-central and similar RMM platforms as high-value, high-exposure assets requiring the same patch SLA as any public web app, not routine IT infrastructure.
- Alert on the full sequence (new admin account -> RMM tool execution -> LSASS access) as a single correlated detection rather than three separate low-priority alerts.
- Restrict which accounts can install/execute remote-access software like AnyDesk or SimpleHelp, and monitor for their use by accounts that don't normally need them.

*See also: [Storm-1175 - N-Day-to-Ransomware Speed Runner](/actors/storm-1175/) for the actor's broader behavioral pattern.*

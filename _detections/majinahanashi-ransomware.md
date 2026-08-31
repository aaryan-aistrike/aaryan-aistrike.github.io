---
title: "Majinahanashi Ransomware - WFP/QoS-Based EDR Interference (Threat Brief)"
layout: default
---

## Overview

**Majinahanashi** is a ransomware operation first tracked by researchers around 2026-08-12, with sample compile timestamps as early as 2026-07-02. It is a Windows-based, C/C++-compiled locker that encrypts files with AES-256 using a unique per-file key protected by RSA, appending the `.majin` extension. Before encrypting, it deletes volume shadow copies, removes the USN journal, disables System Restore and hibernation, modifies boot-recovery settings, and clears Windows event logs.

What sets it apart technically is its approach to defense evasion: alongside terminating a broad, named list of EDR and backup processes (CrowdStrike Falcon, SentinelOne, Carbon Black, FortiEDR, Cylance, Microsoft Defender for Endpoint, Qualys, Tanium, Veeam, Backup Exec, Acronis), it also manipulates Windows Filtering Platform (WFP) filters and QoS policies to interfere with or throttle those tools' network communications - a technique aimed at blinding cloud-connected security agents rather than just killing their local process. It runs a double-extortion leak site with countdown timers and publishes stolen PII as proof of compromise, and has claimed victims across healthcare, hospitality, e-commerce, manufacturing, agri-food, retail, and technology sectors in at least nine countries.

## Why this matters for detection

Most ransomware defense evasion relies on killing the EDR/backup agent process outright or abusing a vulnerable driver (BYOVD) to do so - both of which are increasingly well-instrumented. Majinahanashi's WFP/QoS manipulation is a different, less-monitored evasion surface: an endpoint can show the security agent's *process* still running while its *network* connectivity to the management console or cloud backend is silently degraded or blocked. Detection strategies built only around "is the EDR process alive" miss this. Combined with the reported link between roughly half of victims and prior infostealer exposure, initial access here is frequently a credential-buying problem as much as a malware-detection problem.

## Detection Guidance

```yaml
title: Majinahanashi Ransomware - Security Process Termination and Recovery Inhibition
status: experimental
description: >-
  Detects attempts to terminate named EDR/backup agent processes or delete
  shadow copies/backup catalogs shortly before file encryption, consistent
  with Majinahanashi's pre-encryption defense-evasion and anti-recovery
  behavior. Correlate with unexpected WFP filter or QoS policy changes on
  the same host for higher confidence, since this actor is also known to
  interfere with security-tool network connectivity rather than only
  killing the process.
references:
  - https://www.broadcom.com/support/security-center/protection-bulletin/majinahanashi-ransomware
  - https://theravenfile.com/2026/08/14/majinahanashi-ransomware-another-japanese-locker/
  - https://www.breachsense.com/ransomware-groups/majinahanashi/
author: Aryan
date: 2026-08-31T00:00:00.000Z
tags:
  - attack.defense_evasion
  - attack.t1562.001
  - attack.impact
  - attack.t1486
  - attack.t1490
logsource:
  category: process_creation
  product: windows
detection:
  selection_security_process_kill:
    Image|endswith:
      - '\taskkill.exe'
      - '\net.exe'
      - '\sc.exe'
    CommandLine|contains:
      - 'CSFalconService'
      - 'SentinelAgent'
      - 'FortiEDRCollector'
      - 'MsMpEng'
      - 'VeeamBackup'
      - 'BackupExecRPCService'
      - 'AcronisAgent'
  selection_recovery_inhibit:
    Image|endswith:
      - '\vssadmin.exe'
      - '\wmic.exe'
      - '\wbadmin.exe'
    CommandLine|contains:
      - 'shadowcopy'
      - 'delete'
      - 'catalog'
  condition: selection_security_process_kill or selection_recovery_inhibit
  timeframe: 20m
  # Escalate to critical if both selections fire on the same host within the
  # timeframe, or if followed by mass file rename to the .majin extension
falsepositives:
  - Legitimate security-agent reinstallation/upgrade cycles that stop and restart the service
  - IT-approved backup catalog maintenance or shadow copy pruning jobs
level: high
```

## Prevention

- Alert on stop/kill attempts against named EDR and backup agent processes issued via `taskkill`/`sc`/`net` rather than the vendor's own management console - a strong precursor signal regardless of which ransomware family is behind it.
- Monitor for unexpected WFP filter additions or QoS policy changes targeting security-tool network traffic, not just process termination - this actor specifically uses that path to blind cloud-connected agents without killing the process.
- Maintain immutable, offline backups and alert on shadow copy/USN journal deletion and backup catalog manipulation as a leading indicator that precedes encryption.
- Prioritize infostealer and credential hygiene (rotate browser-stored credentials, invalidate stale session tokens) - roughly half of confirmed victims trace back to prior infostealer exposure rather than novel exploitation.

*See also: [Majinahanashi - Emerging RaaS with WFP/QoS-Based EDR Interference](/actors/majinahanashi/) for the actor's broader behavioral pattern.*

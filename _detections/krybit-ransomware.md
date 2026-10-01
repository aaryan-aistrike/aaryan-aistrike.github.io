---
title: "KryBit - Pre-Encryption Shadow Copy Deletion and Lateral Movement (Threat Brief)"
layout: default
---

## Overview

**KryBit** is a Babuk-derived ransomware-as-a-service operation first observed in March 2026 that has posted 20+ victims to its Tor-based leak site across consumer services, business services, education, technology, and manufacturing sectors in countries including Germany, Mexico, Turkiye, Japan, Austria, Taiwan, Canada, New Zealand, Argentina, and India. The operator supplies cross-platform encryptor builders (Windows, Linux, ESXi, NAS) and 24/7 support under an 80/20 affiliate revenue split, while affiliates supply their own initial access - tracked intrusions map to Valid Accounts (T1078) and RDP/Remote Services (T1021/T1021.001) with no single CVE or exploit attributed to the group as a whole.

Affiliates stage 10GB-250GB of exfiltrated data per victim - employee records, credentials, financial data, design files - before encryption, then demand $40,000-$100,000 via a Tor-based onion chat portal and threaten publication. The encryptor appends a `.KRYBIT` extension and drops a `RECOVER-README.txt` ransom note. In a notable mid-2026 incident, a rival extortion crew ("0APT") breached and leaked KryBit's own backend infrastructure; KryBit retaliated by compromising 0APT's leak site, giving researchers an unusually public window into the operation's internals.

## Why this matters for detection

Because KryBit's RaaS model lets each affiliate bring a different initial-access method, there is no consistent upstream IOC to block - credential-based RDP logons look identical to legitimate remote access until something downstream confirms malicious intent. What *is* consistent across affiliates, because it comes from the shared Babuk-derived encryptor rather than from each affiliate's own tradecraft, is the pre-encryption defense-evasion step: deleting Volume Shadow Copies via `vssadmin.exe delete shadows /all /quiet` to block built-in recovery, typically following WMI- or PsExec-driven lateral movement to stage the encryptor across multiple hosts. Catching that sequence - lateral movement tooling followed by shadow copy deletion on the same or adjacent hosts within a short window - gives a detection surface that doesn't depend on knowing which CVE or credential set got the affiliate in the door.

## Detection Guidance

```yaml
title: Ransomware Pre-Encryption Staging - Shadow Copy Deletion Following Lateral Movement
status: experimental
description: >-
  Detects vssadmin-based shadow copy deletion occurring shortly after
  WMI or PsExec process execution on the same host, consistent with
  Babuk-derived ransomware (e.g. KryBit) staging for mass encryption
  after affiliate-driven lateral movement.
references:
  - https://www.halcyon.ai/threat-group/krybit
  - https://cyble.com/threat-actor-profiles/krybit-ransomware-threat-actor/
  - https://www.picussecurity.com/resource/blog/how-krybit-ransomware-works-and-how-to-test-your-defenses
  - https://attack.mitre.org/techniques/T1490/
author: Aryan
date: 2026-10-01T00:00:00.000Z
tags:
  - attack.lateral_movement
  - attack.t1021.001
  - attack.defense_evasion
  - attack.t1490
  - attack.impact
  - attack.t1486
logsource:
  category: process_creation
  product: windows
detection:
  selection_lateral_movement:
    Image|endswith:
      - '\wmic.exe'
      - '\psexec.exe'
      - '\psexesvc.exe'
    CommandLine|contains:
      - 'process call create'
      - 'service'
  selection_shadow_copy_deletion:
    Image|endswith: '\vssadmin.exe'
    CommandLine|contains|all:
      - 'delete'
      - 'shadows'
  condition: selection_lateral_movement and selection_shadow_copy_deletion
  timeframe: 2h
  # Escalate to critical if shadow copy deletion fires on 3+ distinct hosts
  # within the same timeframe - consistent with multi-host encryption staging
falsepositives:
  - IT staff manually clearing shadow copies to reclaim disk space (rare in production, more common on workstation images)
  - Backup software reconfiguring VSS snapshot retention
  - Legitimate WMI/PsExec-based patch or software deployment tooling coinciding by chance with unrelated VSS maintenance
level: high
```

## Prevention

- Restrict and alert on `vssadmin.exe delete shadows` (and equivalent `wmic shadowcopy delete` / `wbadmin` recovery-disabling commands) - this command has almost no legitimate reason to run outside planned storage maintenance.
- Store backups offline or in immutable/append-only storage that local shadow-copy deletion cannot reach, since affiliates reliably attempt to disable native Windows recovery before encrypting.
- Apply the same backup and monitoring rigor to ESXi and NAS targets as to Windows endpoints - KryBit's builder kit explicitly covers both, and hypervisor/storage layers are frequently the weakest-monitored part of an environment.
- Enforce MFA on RDP and other remote-access paths; since KryBit affiliates supply their own access and rely heavily on valid accounts and RDP, credential hygiene closes the most common entry point even though no single exploit chain can be blocklisted.

*See also: [KryBit - Babuk-Derived RaaS Caught in a Rival-Gang Hack-Back War](/actors/krybit/) for the actor's broader behavioral pattern.*

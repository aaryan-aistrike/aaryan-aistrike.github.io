---
title: "VantaCore - Pro-Ukraine Ransomware Rebrand Custom Toolset (Threat Brief)"
layout: default
---

## Overview

**VantaCore** is a ransomware-as-a-service operation first observed in active attacks in August 2026, assessed by Russian cybersecurity firm F6 to be a rebrand of **Thor**, a pro-Ukrainian hacktivist-ransomware group active against Russian organizations in 2025. F6 has confirmed at least seven Russian corporate victims, with ransom demands reaching into the millions of dollars.

Initial access is gained through poorly secured VPNs and remote-access tooling, vulnerabilities in internet-facing applications, and credentials stolen from business partners. Once inside, the group deploys a fully custom toolset rather than leaked or commodity builders: **VantaCoreLoader** distributes payloads at scale across the compromised network (propagation behavior resembling PsExec/WinExec and techniques associated with LockBit 3.0 Black), a Go-based **VantaCoreRAT** provides recon, command execution, reverse shell, and file transfer capability, and **SnowKiller** disables security software ahead of encryption. The ransomware payload itself is written in C++ and encrypts using ChaCha20 + X25519. Documented behavior follows an espionage-adjacent sequence: steal data, disable security tooling, destroy or sabotage backup infrastructure, encrypt, then attempt to clean up evidence - lateral movement rides on legitimate compromised accounts over SMB and RDP.

## Why this matters for detection

VantaCore's most distinctive - and most detectable - trait is the deliberate destruction of backup infrastructure *before* encryption begins, immediately preceded by security-software tampering (SnowKiller). Neither AV/EDR process termination nor shadow-copy/backup deletion is unique in isolation - both occur during legitimate maintenance - but the two occurring in sequence, on the same host, in a short window, is a strong precursor signal that recovery options are being deliberately removed ahead of a ransomware detonation. Catching this sequence buys defenders time before encryption starts, which is the only point at which backups can still be protected.

## Detection Guidance

```yaml
title: Security Software Termination Followed by Backup or Shadow Copy Deletion
status: experimental
description: >-
  Detects termination of AV/EDR processes or services shortly followed by
  shadow copy or backup deletion commands on the same host, consistent
  with VantaCore ransomware's documented sequence of disabling security
  tooling (SnowKiller) before sabotaging backup infrastructure ahead of
  encryption.
references:
  - https://therecord.media/new-pro-ukraine-hacker-group-custom-ransomware-russia
  - https://www.hendryadrian.com/new-pro-ukraine-hacker-group-targets-russian-companies-with-custom-ransomware/
author: Aryan
date: 2026-09-10T00:00:00.000Z
tags:
  - attack.defense_evasion
  - attack.t1562.001
  - attack.impact
  - attack.t1490
logsource:
  category: process_creation
  product: windows
detection:
  selection_security_tooling_kill:
    Image|endswith:
      - '\taskkill.exe'
      - '\net.exe'
      - '\sc.exe'
    CommandLine|contains:
      - '/f /im'
      - 'stop'
  selection_backup_destruction:
    Image|endswith:
      - '\vssadmin.exe'
      - '\wbadmin.exe'
      - '\wmic.exe'
    CommandLine|contains:
      - 'shadowcopy delete'
      - 'delete catalog'
      - 'delete systemstatebackup'
  condition: selection_security_tooling_kill and selection_backup_destruction
  timeframe: 30m
  # Escalate to critical if preceded within the same session by SMB/RDP
  # lateral movement using a recently-compromised legitimate account
falsepositives:
  - Scheduled AV/EDR agent reinstallation or upgrade during a maintenance window
  - Legitimate backup retention housekeeping that runs close in time to unrelated AV maintenance
level: high
```

## Prevention

- Store backup and shadow-copy deletion permissions separately from general endpoint administration - require a distinct, monitored credential path for any legitimate backup-purge operation.
- Alert on AV/EDR service or process termination as a standalone high-priority event, not just as one input to a broader correlation rule - it is rarely legitimate outside change windows.
- Keep offline, immutable, network-segmented backup copies that VantaCoreLoader's SMB/RDP-based lateral movement cannot reach even with valid compromised credentials.
- Restrict and monitor VPN/remote-access exposure, and treat credentials obtained from business partners as a distinct third-party risk category requiring their own access review.

*See also: [VantaCore - Pro-Ukraine Ransomware Rebrand Targeting Russian Enterprises](/actors/vantacore/) for the actor's broader behavioral pattern.*

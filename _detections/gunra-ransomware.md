---
title: "Gunra Ransomware - Fortinet Auth-Bypass Initial Access (Threat Brief)"
layout: default
---

## Overview

**Gunra** (also branded "Golden Community") is a double-extortion ransomware-as-a-service operation, built on leaked Conti source code, that CISA, the FBI, NSA, DC3, the U.S. Secret Service, and South Korea's National Police Agency jointly warned about on 2026-08-10 (advisory AA26-222A) following a sharp rise in attacks against healthcare, financial services, government, and nonprofit organizations worldwide.

The group's defining trait is **firewall authentication bypass as initial access**: affiliates exploit CVE-2024-55591 and CVE-2025-24472, two FortiOS/FortiProxy flaws, to gain super-admin privileges on internet-facing Fortinet devices, then abuse a scheduled task on the device to forge a new persistent superuser account with a hard-coded password. In at least one documented case, actors also compromised a default-credentialed SSL-VPN admin account and modified authentication files on a VDI portal so a single Gunra-chosen OTP value always authenticated - neutralizing MFA rather than phishing around it. From there, affiliates use Impacket's `psexec.py`/`smbclient.py`, RDP with harvested sessions, and pass-the-hash/pass-the-ticket to move laterally, then stage data with 7-Zip/WinRAR before exfiltrating via RClone, FileZilla, or OpenSSH to Mega or FTP. Encrypted files carry `.ENCRT`, `.CRYPT`, or `.GNRA` extensions with a `R3ADM3.txt` ransom note, and victims get 5-7 days before publication on Gunra's leak site.

## Why this matters for detection

Because initial access rides on two specific, patchable CVEs in edge devices rather than novel exploitation, unpatched Fortinet appliance inventory is the single largest exposure this group depends on - and it's fully within a defender's control. Once inside, Gunra affiliates reuse the same living-off-the-land pattern seen across other current RaaS crews: legitimate tools (Impacket, 7-Zip, RClone, FileZilla) chained together in a specific sequence. No individual tool is malicious in isolation, so the detectable signal is the **archive-then-exfil-tool chain** - a compression utility running against a file share shortly followed by RClone or FileZilla initiating an outbound transfer - combined with Impacket's distinctive remote-service-installation fingerprint on SMB.

## Detection Guidance

```yaml
title: Gunra-Pattern Archive-Then-Exfiltration Tool Chain
status: experimental
description: >-
  Detects a compression utility (7-Zip/WinRAR) executing against a file
  share host shortly followed by RClone or FileZilla initiating outbound
  transfer on the same host, consistent with the stage-then-exfiltrate
  sequence documented in Gunra ransomware intrusions (CISA AA26-222A)
  prior to encryption.
references:
  - https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-222a
  - https://thehackernews.com/2026/08/gunra-ransomware-exploits-fortinet-and.html
  - https://therecord.media/ransomware-south-korea-fbi-gunra
author: Aryan
date: 2026-08-25T00:00:00.000Z
tags:
  - attack.collection
  - attack.t1560
  - attack.exfiltration
  - attack.t1567
  - attack.lateral_movement
  - attack.t1021.002
logsource:
  category: process_creation
  product: windows
detection:
  selection_archive:
    Image|endswith:
      - '\7z.exe'
      - '\7za.exe'
      - '\winrar.exe'
  selection_exfil_tool:
    Image|endswith:
      - '\rclone.exe'
      - '\filezilla.exe'
  selection_impacket_service:
    EventID: 7045
    ServiceFileName|contains: 'ADMIN$'
  condition: (selection_archive and selection_exfil_tool) or selection_impacket_service
  timeframe: 45m
  # Escalate to critical if the same host also shows a new local admin
  # account creation (EventID 4720/4732) within the same window
falsepositives:
  - IT staff using RClone or FileZilla for legitimate scheduled backups or file transfers
  - Backup software that stages archives with 7-Zip/WinRAR before an approved transfer job
  - Sanctioned PsExec-based deployment tooling that also triggers EventID 7045
level: high
```

## Prevention

- Patch FortiOS and FortiProxy against CVE-2024-55591 and CVE-2025-24472 immediately, and treat any internet-facing Fortinet appliance as a priority patch target given this is the group's confirmed primary entry vector.
- Enforce account lockout policies and eliminate default credentials on VPN/VDI admin accounts - the documented MFA-bypass case depended entirely on a default-credentialed account with no lockout control.
- Audit scheduled tasks on network edge devices (firewalls, VPN concentrators) for unexpected new local admin accounts, which is how this group establishes persistence after initial exploitation.
- Alert on the archive-then-exfil-tool sequence rather than any single tool's presence, and maintain offline, immutable backups covering file shares and NAS - both directly targeted by this group's exfiltration and encryption chain.

*See also: [Gunra / Golden Community - Conti-Derived RaaS Targeting Critical Infrastructure](/actors/gunra/) for the actor's broader behavioral pattern.*

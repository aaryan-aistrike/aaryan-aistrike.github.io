---
title: "CHOSEN BRICK/HEAVYGRAM - Telegram-Controlled Spyware Detection (Threat Brief)"
layout: default
---

## Overview

**CHOSEN BRICK** (NCSC designation) / **HEAVYGRAM** (FBI designation) is a Windows spyware family attributed by a joint 2026-09-15 advisory from the UK NCSC, US FBI, and Netherlands AIVD to Iran's Ministry of Intelligence and Security (MOIS). Rather than registering its own C2 infrastructure, the malware communicates through the Telegram Bot API (`api.telegram.org`), with each infected device assigned a unique Telegram Bot ID. Delivery is via WhatsApp/Telegram social engineering, with payloads frequently disguised as Norton Antivirus or Adobe Flash Player installers. Once resident, it persists via an `HKCU` Run key, actively adds itself to Microsoft Defender's exclusion list, and uses commercial cloud/CDN and residential-proxy infrastructure (Backblaze B2, Vultr Object Storage, Storj, IPRoyal, Lightning Proxies) for exfiltration and secondary C2.

## Why this matters for detection

CHOSEN BRICK's defining evasion property is that its C2 channel is a legitimate, widely-allowed destination - `api.telegram.org` is rarely blocked at the perimeter and is indistinguishable from normal Telegram client traffic at the network layer alone. The signal that actually separates it from legitimate Telegram usage is **which process is making the call**: a desktop Telegram client talking to Telegram is normal, but a process with no legitimate reason to speak HTTPS to the Telegram API (and especially one that was just added to the Defender exclusion list, or just wrote to the `HKCU...\Run` key) is not. This detection focuses on that process-identity gap and on the Defender-tampering step, both of which are far more durable signals than the social-engineering lure or any specific file hash, which the operators can trivially change.

## Detection Guidance

```yaml
title: Suspicious Process Adds Microsoft Defender Exclusion and Persists via Run Key
status: experimental
description: >-
  Detects a non-security process adding an exclusion path/process to Windows
  Defender followed by Run-key persistence from the same or a related
  process, consistent with CHOSEN BRICK/HEAVYGRAM spyware defense evasion
  and persistence as described in the 2026-09-15 NCSC/FBI/AIVD joint advisory.
references:
  - https://www.ncsc.gov.uk/news/uk-allies-expose-spyware-iranian-state-actors-target-dissidents-activists-journalists
  - https://www.bleepingcomputer.com/news/security/iranian-hackers-use-chosen-brick-windows-malware-to-spy-on-targets/
  - https://thehackernews.com/2026/09/iranian-hackers-use-telegram-controlled.html
author: Aryan
date: 2026-10-27T00:00:00.000Z
tags:
  - attack.defense_evasion
  - attack.t1562.001
  - attack.persistence
  - attack.t1547.001
  - attack.command_and_control
  - attack.t1102.002
logsource:
  category: process_creation
  product: windows
detection:
  selection_defender_exclusion:
    CommandLine|contains|all:
      - 'Add-MpPreference'
      - '-Exclusion'
  selection_run_key_write:
    EventID: 13
    TargetObject|contains: '\Software\Microsoft\Windows\CurrentVersion\Run\'
  filter_known_admin_tools:
    Image|endswith:
      - '\MsMpEng.exe'
      - '\ConfigurationManager.exe'
  condition: (selection_defender_exclusion or selection_run_key_write) and not filter_known_admin_tools
  timeframe: 15m
  # Higher-confidence correlation: same host shows both selections within
  # the timeframe, followed by an outbound HTTPS connection to
  # api.telegram.org from a process other than Telegram's own client
  # (telegram.exe / Telegram.exe) - that three-part sequence is the
  # strongest single indicator of this specific campaign.
falsepositives:
  - Legitimate endpoint security or deployment tooling adding Defender exclusions during installation
  - Normal application installers writing to the Run key for auto-start (verify the binary/publisher)
  - Users running the genuine Telegram desktop client, which legitimately calls the Telegram API
level: high
```

## Prevention

- Treat unsolicited application installers received via WhatsApp or Telegram - even from an apparently known contact - as a credential/identity-compromise risk on the sender's end, not just a malware risk on the receiving end; verify through a second channel before opening.
- Alert on any non-security-vendor process modifying the Microsoft Defender exclusion list (`Add-MpPreference`, direct registry writes to `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`) - this is a narrow, high-signal action with very few legitimate non-admin callers.
- For at-risk individuals and the organizations that work with them (NGOs, media outlets, advocacy groups), consider Windows S mode or application allowlisting, which blocks unsigned installers like the Norton/Flash lures observed in this campaign outright.
- Monitor for outbound HTTPS connections to `api.telegram.org`, Backblaze B2, Vultr Object Storage, Storj, and residential-proxy endpoints (IPRoyal, Lightning Proxies) originating from processes other than recognized messaging or backup clients.
- Enable phishing-resistant MFA on all accounts tied to at-risk individuals, since the initial compromise vector here is social engineering rather than a technical exploit.

*See also: [Iran's MOIS - CHOSEN BRICK/HEAVYGRAM Spyware](/actors/mois-chosen-brick/) for the actor's broader behavioral pattern.*

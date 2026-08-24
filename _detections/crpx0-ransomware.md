---
title: "CRPx0 - OnlyFans-Lure Ransomware Delivery Chain (Threat Brief)"
layout: default
---

## Overview

**CRPx0** is a ransomware-as-a-service operation, first identified in June 2026, that scaled from fewer than 10 victims to 46 claimed victims in July 2026 and launched a clearnet/dark-web leak site on 2026-08-07. Rather than exploiting a vulnerability, CRPx0's most-documented infection chain relies entirely on social engineering: victims searching for "free OnlyFans accounts" (or opening fake FedEx shipping documents) download a ZIP archive containing a disguised shortcut (LNK) file.

Opening the shortcut silently runs hidden commands that launch a VBScript loader, which in turn prepares the host and installs a Python-based implant. That implant connects out to a CRPx0-controlled server for interactive commands, updates, and follow-on payload delivery - including a clipboard hijacker that swaps copied cryptocurrency wallet addresses, a BIP39 seed-phrase stealer, and, when the operator decides, a cross-platform ransomware module for double extortion.

## Why this matters for detection

The defining trait for detection engineering is that **encryption is operator-triggered, not automatic** - CRPx0's implant supports quiet reconnaissance, credential theft, and clipboard hijacking for an extended period before an affiliate decides to pull the ransomware trigger. That means the delivery chain itself (LNK-in-ZIP → script host → Python payload → outbound C2) is a more reliable and earlier detection point than waiting for file-encryption behavior. Because there's no CVE involved, this is a chain that pure vulnerability-management programs will never catch - it depends on catching living-off-the-land script execution and unusual Python interpreter activity spawned from a script host.

## Detection Guidance

```yaml
title: CRPx0-Style Shortcut-to-Script-to-Python Infection Chain
status: experimental
description: >-
  Detects a Windows script host (wscript.exe/cscript.exe/mshta.exe) launched
  from a user-writable path (Downloads, Temp, extracted archive folders) and
  subsequently spawning a Python interpreter, consistent with the CRPx0
  LNK-in-ZIP delivery chain (fake OnlyFans/FedEx lures) preceding
  clipboard-hijacking, credential theft, and operator-triggered ransomware
  deployment.
references:
  - https://www.securityweek.com/free-onlyfans-lure-used-to-spread-cross-platform-crpx0-malware/
  - https://www.scworld.com/brief/new-crpx0-malware-campaign-uses-onlyfans-lure-for-crypto-theft-and-ransomware
  - https://www.aryaka.com/blog/crpx0-ransomware-multi-stage-attack/
author: Aryan
date: 2026-08-24T00:00:00.000Z
tags:
  - attack.execution
  - attack.t1204.002
  - attack.t1059.005
  - attack.command_and_control
  - attack.impact
  - attack.t1486
logsource:
  category: process_creation
  product: windows
detection:
  selection_script_host_from_user_path:
    Image|endswith:
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
    ParentImage|endswith: '\explorer.exe'
    CommandLine|contains:
      - '\Downloads\'
      - '\AppData\Local\Temp\'
  selection_python_child_process:
    ParentImage|endswith:
      - '\wscript.exe'
      - '\cscript.exe'
  selection_python_process:
    Image|endswith:
      - '\python.exe'
      - '\pythonw.exe'
  condition: selection_script_host_from_user_path and selection_python_child_process and selection_python_process
  timeframe: 5m
falsepositives:
  - Legitimate internal tooling or installers that use VBScript wrappers around Python utilities
  - Developer workstations where Python is intentionally launched from automation scripts in user-writable directories
level: high
```

## Prevention

- Block or heavily restrict script-host execution (wscript.exe, cscript.exe, mshta.exe) launched from Downloads, Temp, and other user-writable directories via ASR rules or application control - CRPx0's entire chain depends on this step succeeding.
- Filter or sandbox archive attachments/downloads containing LNK files, especially from consumer file-sharing or "free account" lure sites.
- Monitor for unexpected Python interpreter installation or execution on endpoints that don't normally run Python - it's not a standard end-user tool and its sudden appearance is a strong signal.
- Deploy clipboard-monitoring or wallet-address-verification safeguards on any endpoint used for cryptocurrency transactions, since clipboard hijacking here precedes and is independent of the ransomware stage.
- Maintain offline, tested backups - because CRPx0 stages exfiltration and ransomware separately, early detection during the reconnaissance phase is the best chance to prevent the destructive stage entirely.

*See also: [CRPx0 - Scam-to-RaaS Cross-Platform Extortion Crew](/actors/crpx0/) for the actor's broader behavioral pattern.*

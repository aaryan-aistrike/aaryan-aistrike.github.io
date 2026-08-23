---
title: "Encoded / Obfuscated PowerShell Execution (High-Confidence)"
layout: default
---

## Overview

Base64-encoded (`-EncodedCommand` / `-enc`) and otherwise obfuscated PowerShell invocation is a long-standing technique ([MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)) used to evade command-line signature matching, string-based AV detection, and casual analyst review. It shows up across the kill chain — initial access droppers, staged download-and-execute loaders, and post-exploitation tooling (Empire, Cobalt Strike, Mimikatz wrappers) all commonly use it.

The rule below correlates **encoding/obfuscation flags with additional suspicious execution characteristics**, since encoded PowerShell alone is used legitimately (e.g. by some configuration management tools) and is too noisy as a standalone signature.

Key behavioral indicators:

- `-EncodedCommand`, `-enc`, `-e` flags combined with `-WindowStyle Hidden`, `-NoProfile`, or `-ExecutionPolicy Bypass`
- Decoded payload containing download cradles (`Net.WebClient`, `Invoke-WebRequest`, `IEX`, `DownloadString`)
- PowerShell spawned as a child of Office applications, browsers, or scripting hosts (wscript/cscript/mshta) rather than a terminal
- Unusually long command-line length, often a symptom of layered obfuscation or embedded encoded payloads

---

## Detection Rule

```yaml
title: Encoded or Obfuscated PowerShell Execution
status: stable
description: >-
  Detects PowerShell execution using encoded-command or hidden-window flags,
  optionally correlated with suspicious parent processes or download-cradle
  strings in decoded payloads, to reduce false positives from legitimate
  automation tooling.
references:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_powershell_exe
author: Aryan
date: 2026-08-23T00:00:00.000Z
tags:
  - attack.execution
  - attack.defense_evasion
  - attack.t1059.001
  - attack.t1027
logsource:
  category: process_creation
  product: windows
detection:
  selection_encoded_flag:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc '
      - '-e '
  selection_hidden_or_bypass:
    CommandLine|contains:
      - '-WindowStyle Hidden'
      - '-w hidden'
      - '-ExecutionPolicy Bypass'
      - '-NoProfile'
  selection_suspicious_parent:
    ParentImage|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
  selection_download_cradle:
    CommandLine|contains:
      - 'Net.WebClient'
      - 'DownloadString'
      - 'Invoke-WebRequest'
      - 'IEX'
  condition: >
    selection_encoded_flag and (
      selection_hidden_or_bypass or
      selection_suspicious_parent or
      selection_download_cradle
    )
falsepositives:
  - Configuration management tools (SCCM, DSC, some RMM agents) that encode commands by design
  - Scheduled maintenance scripts using -NoProfile for performance, without malicious intent
  - Security tooling itself invoking PowerShell for legitimate remediation actions
level: high
```

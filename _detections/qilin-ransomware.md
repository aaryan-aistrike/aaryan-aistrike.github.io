---
title: "Qilin - WSL-Based Linux Encryptor Execution for EDR Evasion (Threat Brief)"
layout: default
---

## Overview

**Qilin**, tracked as the most active ransomware-as-a-service operation of 2026, has been observed by Cisco Talos and independently confirmed by BleepingComputer running its **Linux ELF encryptor inside the Windows Subsystem for Linux (WSL)** on fully Windows victim hosts. Affiliates transfer the ELF binary onto a compromised endpoint - commonly via WinSCP - then launch it through legitimate remote-management software, specifically Splashtop's `SRManager.exe`, which spawns `wsl.exe` to execute the Linux payload. The encryptor can then read and encrypt files across the Windows filesystem (mounted under `/mnt/c/` inside WSL) while running in an execution context that most Windows-native EDR tooling does not inspect with the same depth as native PE processes.

This technique follows the group's typical initial-access pattern of exploiting internet-facing VPN/firewall appliances - CVE-2026-0257 (PAN-OS GlobalProtect authentication bypass) and CVE-2026-50751 (Check Point VPN authentication bypass) have both been documented as Qilin affiliate entry points in 2026 - followed by LSASS/NTDS credential harvesting, PsExec/RDP lateral movement, and Windows event log clearing immediately before encryption.

## Why this matters for detection

WSL is enabled by default on a large fraction of modern Windows fleets for legitimate developer and administrative use, which makes `wsl.exe` execution alone a poor detection signal - the value is entirely in **context and parentage**. A `wsl.exe` process spawned by remote-management software rather than an interactive user session, especially one whose child processes go on to touch files broadly across `/mnt/c/`, is a strong anomaly that a Windows-only detection posture - one that whitelists WSL as "just a dev tool" - will miss entirely. Because the payload itself is a Linux ELF binary, file-based and signature detection tuned for Windows PE ransomware families will not flag it either; the sequence of parent process, WSL invocation, and mass file writes is what has to be alerted on.

## Detection Guidance

```yaml
title: WSL Process Spawned by Remote-Management Software Preceding Mass File Writes
status: experimental
description: >-
  Detects wsl.exe or bash.exe launched by remote-management/remote-access
  software (e.g. Splashtop SRManager.exe, AnyDesk, ngrok) rather than an
  interactive console session, consistent with Qilin affiliate tradecraft
  of running a Linux ELF ransomware encryptor inside WSL to evade
  Windows-native EDR inspection.
references:
  - https://blog.talosintelligence.com/qilin-edr-killer/
  - https://www.bleepingcomputer.com/news/security/qilin-ransomware-abuses-wsl-to-run-linux-encryptors-in-windows/
  - https://arcticwolf.com/resources/blog/exploitation-of-cve-2026-0257-leads-to-qilin-ransomware/
  - https://thehackernews.com/2026/07/qilin-ransomware-attackers-exploit-pan.html
  - https://www.helpnetsecurity.com/2026/06/08/check-point-cve-2026-50751-qilin-ransomware/
author: Aryan
date: 2026-09-16T00:00:00.000Z
tags:
  - attack.defense_evasion
  - attack.t1202
  - attack.execution
  - attack.t1059.004
  - attack.impact
  - attack.t1486
logsource:
  category: process_creation
  product: windows
detection:
  selection_wsl_spawn:
    Image|endswith:
      - '\wsl.exe'
      - '\bash.exe'
  selection_remote_mgmt_parent:
    ParentImage|endswith:
      - '\SRManager.exe'
      - '\AnyDesk.exe'
      - '\ngrok.exe'
      - '\LogMeIn.exe'
  filter_perflogs_stage:
    CommandLine|contains: 'PerfLogs'
  condition: selection_wsl_spawn and selection_remote_mgmt_parent
  timeframe: 5m
  # Treat filter_perflogs_stage as a high-confidence escalator, not a filter -
  # C:\PerfLogs\ is a documented Qilin payload-staging location
falsepositives:
  - IT staff using Splashtop or AnyDesk for legitimate remote support who also happen to use WSL for development work on the same session
  - Automated deployment tooling that legitimately shells into WSL via a remote-management agent
level: high
```

## Prevention

- Patch internet-facing PAN-OS and Check Point VPN/firewall appliances promptly, and disable authentication-override cookie configurations on PAN-OS GlobalProtect where not strictly required - both have been documented Qilin affiliate entry points in 2026.
- Extend EDR/process-monitoring coverage into WSL process activity rather than treating it as an untracked blind spot; most agents that already collect Windows process telemetry can be configured to also ingest WSL process-creation events.
- Alert on `wsl.exe`/`bash.exe` spawned by remote-management or remote-access software specifically, since that parent-child relationship has no common legitimate cause outside of automated deployment tooling.
- Monitor `C:\PerfLogs\` and other default-but-rarely-used Windows directories for new executable or script writes - Qilin has staged payloads there specifically because it isn't commonly monitored.
- Enable centralized, tamper-resistant logging (ship Windows event logs off-host in near-real-time) since Qilin affiliates clear local event logs immediately before encryption in documented intrusions.

*See also: [Qilin / Agenda - Russian-Speaking RaaS and the Most Active Ransomware Operation of 2026](/actors/qilin/) for the actor's broader behavioral pattern.*

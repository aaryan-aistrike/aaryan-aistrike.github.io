---
title: "WMI-Based Lateral Movement (High-Confidence)"
layout: default
---

## Overview

Windows Management Instrumentation ([MITRE ATT&CK T1047](https://attack.mitre.org/techniques/T1047/), often paired with [T1021.006](https://attack.mitre.org/techniques/T1021/006/)) is a built-in, "living off the land" mechanism attackers use for remote process execution and lateral movement - no additional tooling needs to be dropped on disk, and traffic rides over legitimate DCOM/WMI ports (135 + a dynamic RPC port), making it harder to distinguish from admin activity than SMB-based methods like PsExec.

The most common malicious pattern is a **`wmiprvse.exe`-spawned child process** on the target host, initiated remotely via `Win32_Process.Create` - frequently used to launch `cmd.exe`, `powershell.exe`, or a staged payload.

Key behavioral indicators:

- `WmiPrvSE.exe` as the parent of an interactive shell or encoded PowerShell (a legitimate admin script rarely needs a live shell)
- Remote WMI process creation events correlated with a preceding authentication event from the same source host
- Use of `wmic.exe` or `Invoke-WmiMethod`/`Invoke-CimMethod` from a workstation targeting multiple hosts in a short window (indicative of scripted lateral movement / worming behavior)
- WMI event subscriptions (`__EventFilter`, `__EventConsumer`) created for persistence rather than one-off execution

---

## Detection Rule

```yaml
title: WMI-Based Lateral Movement - Remote Process Creation
status: stable
description: >-
  Detects remote process creation via WMI (wmiprvse.exe spawning a shell or
  interpreter), and source-host fan-out of WMI process creation across
  multiple targets, consistent with lateral movement rather than routine
  systems administration.
references:
  - https://attack.mitre.org/techniques/T1047/
  - https://attack.mitre.org/techniques/T1021/006/
author: Aryan
date: 2026-08-23T00:00:00.000Z
tags:
  - attack.execution
  - attack.lateral_movement
  - attack.t1047
  - attack.t1021.006
logsource:
  category: process_creation
  product: windows
detection:
  selection_wmi_parent:
    ParentImage|endswith: '\wmiprvse.exe'
  selection_shell_child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\powershell_ise.exe'
      - '\rundll32.exe'
      - '\regsvr32.exe'
  filter_known_management_tasks:
    CommandLine|contains: 'known_scheduled_task_signature_placeholder'
  condition: selection_wmi_parent and selection_shell_child and not filter_known_management_tasks
  # Correlate separately: single source host issuing WMI process-creation
  # requests against >= 3 distinct destination hosts within a 15m window
falsepositives:
  - Legitimate remote administration via WMI/PowerShell remoting by IT/helpdesk staff
  - Configuration management and monitoring agents that use WMI for health checks
  - SCCM/MECM software deployment, which can legitimately spawn shells via WMI
level: high
```

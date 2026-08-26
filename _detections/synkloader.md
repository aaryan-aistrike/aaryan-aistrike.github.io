---
title: "SynkLoader - Multi-Language Loader with Fake Lock-Screen Credential Theft (Threat Brief)"
layout: default
---

## Overview

**SynkLoader** is a newly documented malware loader that Expel discovered on 2026-08-18 after an EDR alert fired on a suspicious scheduled task in a customer environment. Compilation timestamps on recovered samples trace first distribution back to around 2026-07-28. The intrusion begins with a Microsoft Teams phishing message impersonating the target organization's internal IT help desk (sent from a lookalike `*.onmicrosoft.com` account), directing the victim to install a fake "PowerShell Cleaner" MSI package hosted on Azure Blob Storage - a hosting choice that lets the download inherit a trusted Microsoft domain.

Once installed, SynkLoader deploys seven distinct modules built across **Python, PowerShell, C#, and C++**, bundling its own embedded Python runtime and fake Microsoft-branded DLLs, with many components executed only in memory to avoid dropping scannable artifacts. Its most distinctive module, **PhishLocker**, renders a borderless, full-screen window that closely mimics the real Windows 11 lock screen - pulling the actual logged-in username and the victim's real lock-screen wallpaper to make the fake prompt convincing, then harvesting whatever password the victim types into it. Other modules provide a reverse proxy into the internal network, an interactive remote shell, VNC-based desktop streaming, and a system profiler that enumerates hostname, privileges, running processes/services, domain membership, and Active Directory computer counts. Expel and independent researcher Marcus Hutchins both assess with low-to-medium confidence that SynkLoader is operated by, or sold to, a ransomware group or initial access broker - based largely on the AD-sizing reconnaissance, which is a typical precursor to ransom-demand calibration rather than commodity credential theft.

## Why this matters for detection

SynkLoader's persistence mechanism is deliberately built to slip past a common blind spot: instead of calling `schtasks.exe` (which most EDR behavioral rules watch closely), it registers its scheduled task directly through the **Task Scheduler COM interface** (`CLSID_TaskScheduler` / `IID_ITaskService`), so no `schtasks.exe` process or suspicious command line ever appears in the process tree. The task itself runs `pythonw.exe` against a script named `ss.py` both at user logon and daily at 10:00 AM - a legitimate, often-unsigned-by-policy interpreter being used to execute a bundled payload is a classic LOLBin-style evasion. The four-language module design (Python/PowerShell/C#/C++) is also a deliberate hedge against static and EDR signature coverage that's typically tuned to just one or two languages, and the in-memory execution of most modules limits what shows up on disk for after-the-fact triage. Detection therefore has to anchor on **behavior** - a Python interpreter launched by the Task Scheduler at logon/on a fixed daily schedule, from a non-standard install path - rather than any single static indicator.

## Detection Guidance

```yaml
title: SynkLoader - Scheduled pythonw.exe Execution from Non-Standard Path at Logon
status: experimental
description: >-
  Detects pythonw.exe/python.exe executing a script from a user-writable
  directory (AppData/ProgramData) when spawned by the Task Scheduler service,
  consistent with SynkLoader's COM-registered scheduled task persistence
  that avoids schtasks.exe command-line indicators.
references:
  - https://expel.com/blog/synkloader-when-you-throw-in-everything-but-the-kitchen-sink/
  - https://www.bleepingcomputer.com/news/security/new-synkloader-malware-pushed-in-microsoft-teams-phishing-campaign/
  - https://thehackernews.com/2026/08/wordlistloader-delivers-amatera-via.html
  - https://gbhackers.com/new-synkloader-malware/
author: Aryan
date: 2026-08-26T00:00:00.000Z
tags:
  - attack.persistence
  - attack.t1053.005
  - attack.defense_evasion
  - attack.t1027
  - attack.credential_access
  - attack.t1056.002
  - attack.command_and_control
  - attack.t1090
detection:
  selection_python_interp:
    Image|endswith:
      - '\pythonw.exe'
      - '\python.exe'
  selection_scheduler_parent:
    ParentImage|endswith:
      - '\svchost.exe'
      - '\taskeng.exe'
      - '\taskhostw.exe'
  selection_userwritable_path:
    CommandLine|contains:
      - '\AppData\Local\'
      - '\AppData\Roaming\'
      - '\ProgramData\'
  filter_known_admin_scripts:
    CommandLine|contains:
      - '\Microsoft VS Code\'
      - '\Programs\Python'
  condition: selection_python_interp and selection_scheduler_parent and selection_userwritable_path and not filter_known_admin_scripts
falsepositives:
  - Legitimate scheduled automation (backup agents, monitoring tools) that intentionally runs Python from a per-user install directory
  - IT-deployed Python-based logon scripts placed in ProgramData for legitimate provisioning
level: high
```

## Prevention

- Don't rely solely on `schtasks.exe` command-line monitoring for scheduled task creation - also monitor the `Microsoft-Windows-TaskScheduler/Operational` event log (Event IDs 106/200/201), which logs new task registration regardless of whether it was created via the CLI or the COM API.
- Treat unsolicited Microsoft Teams messages claiming to be "IT Support" or "Help Desk" with the same scrutiny as email phishing, especially ones directing installation of software from a generic `*.blob.core.windows.net` Azure Storage link rather than an internal software portal.
- Flag any full-screen, borderless window that visually mimics the Windows lock screen appearing outside of an actual OS lock/session-lock event - PhishLocker's convincing replica depends on the victim not questioning why a "lock screen" appeared without them pressing Win+L or walking away.
- Restrict execution of `python.exe`/`pythonw.exe` from user-writable paths (AppData, ProgramData, Temp) via application control policy where feasible, since legitimate enterprise Python deployments are typically installed to Program Files or a managed virtual environment path.

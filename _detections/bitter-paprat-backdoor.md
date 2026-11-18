---
title: "Bitter / TA397 - PapRAT Backdoor Delivered via Trojanized LNK, VHDX, and WebDAV Lures (Threat Brief)"
layout: default
---

## Overview

In early November 2026, FortiGuard Labs disclosed a campaign by the South Asia-linked espionage actor **Bitter** (also tracked as TA397, APT-C-08, APT-Q-37, Hazy Tiger, Orange Yali, and T-APT-17) deploying a previously unreported backdoor, **PapRAT**, against government, energy, and engineering organizations - primarily in South Asia, with secondary exposure reported in Southeast Asia and South Korea. The campaign runs three distinct infection chains in parallel: an LNK file that abuses the native `ftp.exe` utility's `!` shell-escape syntax to run local commands and register scheduled tasks, a VHDX disk image ("Letter from the Ambassador - 11th Belt and Road Summit.vhdx") that opens a decoy spreadsheet while silently launching a hidden MSI installer, and an archived gala-dinner-invitation URL shortcut that pulls a payload over WebDAV before running a second MSI. PapRAT itself was recently rewritten from C++ to Rust, growing from 8 to 11 commands and gaining PowerShell execution. Its `DWW` command is used to fetch a secondary, previously documented implant - WmRAT - which researchers cite as further evidence tying this activity to Bitter.

## Why this matters for detection

None of the three chains rely on a software vulnerability, so patch-based defenses don't apply here - the entire campaign is deception plus living-off-the-land execution. The first chain is particularly evasive: it drops no custom malware at all during initial access, instead using `ftp.exe`'s rarely-used `!` prefix to execute local shell commands and register a scheduled task that polls for further instructions via `curl`. That technique blends into normal system-utility activity and won't trigger malware-signature tooling. The other two chains both rely on MSI installers launched from unusual containers (a mounted VHDX, a WebDAV share) rather than a double-clicked executable, which is a stronger and more durable signal than trying to match the PapRAT payload itself - especially since the group just rewrote that payload from C++ to Rust, aging out any binary-specific detection built against the older samples.

## Detection Guidance

```yaml
title: FTP.exe Shell-Escape Spawning Child Process (BITTER PapRAT Loader Chain)
status: experimental
description: >-
  Detects the native Windows ftp.exe utility spawning a shell or
  scripting interpreter as a child process, consistent with the '!'
  escape-to-shell technique used in BITTER/TA397's LNK-based PapRAT
  loader chain to run local commands and register scheduled tasks
  for C2 polling.
references:
  - https://www.fortinet.com/blog/threat-research/bitter-expands-its-arsenal-with-paprat
  - https://thehackernews.com/2026/11/bitter-hackers-deploy-new-paprat.html
  - https://www.darkreading.com/cyberattacks-data-breaches/paprat-cyberespionage-campaign-bitter-south-asia
author: Aryan
date: 2026-11-18T00:00:00.000Z
tags:
  - attack.execution
  - attack.t1059.003
  - attack.persistence
  - attack.t1053.005
  - attack.defense_evasion
  - attack.t1036
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith: '\ftp.exe'
  selection_child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\curl.exe'
      - '\schtasks.exe'
  condition: selection_parent and selection_child
  # Also flag MSI installer execution (msiexec.exe) with a parent process
  # of explorer.exe where the working directory resolves to a mounted
  # VHDX/VHD volume, or any msiexec.exe launch whose command line
  # references a WebDAV UNC path (\\*\DavWWWRoot\...)
falsepositives:
  - Legitimate scripted ftp.exe sessions that use '!' for local file management (rare in modern environments)
  - Administrative scripts that wrap curl/schtasks inside batch files unrelated to this campaign
level: high
```

## Prevention

- Treat `ftp.exe` spawning a shell or scripting interpreter as inherently suspicious - this utility is rarely used interactively on modern endpoints, and the `!` escape syntax has no legitimate business purpose for most organizations.
- Block or alert on disk-image files (VHD/VHDX/ISO/IMG) arriving as email attachments or downloads - this container type is increasingly used to smuggle MSI/EXE payloads past mail-gateway inspection.
- Restrict or monitor the WebClient (WebDAV) service; alert on `msiexec.exe` or `rundll32.exe` invocations referencing `\\*\DavWWWRoot\` UNC paths.
- Apply application allowlisting (AppLocker/WDAC) to block MSI execution from user-writable locations, removable media, or mounted virtual disks.
- Brief government, energy, and engineering staff who handle diplomatic or summit-related correspondence specifically on this lure pattern (fake ambassador letters, event invitations) given the actor's consistent reliance on these themes.

*See also: [Bitter / TA397 - South Asia-Linked Espionage Actor Behind the PapRAT/WmRAT Toolset](/actors/bitter/) for the actor's broader behavioral pattern.*

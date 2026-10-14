---
title: "Star Blizzard RedFlick - Scheduled-Task Delivery of the CosmicPulse Backdoor (Threat Brief)"
layout: default
---

## Overview

In a September 29, 2026 report, Microsoft detailed a new delivery technique used by the Russian FSB-linked actor **Star Blizzard** (SEABORGIUM), which it calls **RedFlick**. RedFlick replaces the group's earlier multi-step ClickFix-style chain with one that needs only a single victim interaction, using Windows Scheduled Tasks to stage and launch a malicious Control Panel applet (CPL) DLL - tracked as NOROBOT/BAITSWITCH - which downloads and decrypts the group's **CosmicPulse** (aka YESROBOT) Python backdoor. The AES key used to decrypt the payload is stored in the registry under `HKCU\Software\Classes\.mollis`.

Microsoft observed the activity affecting over 100 organizations, concentrated in the US and UK, and counted at least 13 distinct large-scale campaigns since January 2026 - each with a different lure (tax-audit notices, fake conference invitations, forged payment notices) but a converging delivery pattern once the victim opens the initial attachment.

## Why this matters for detection

Star Blizzard overhauls its lure content and file-delivery chain on almost every wave specifically to outrun static IOC lists, which makes hash- and domain-based detection a losing game against this actor. What stays constant across the January, April, and July 2026 chains Microsoft documented is the **mechanism**, not the wrapper: an MSI or script creates one or more scheduled tasks with innocuous, IT-sounding names shortly after a user interacts with an email attachment, and one of those tasks invokes `control.exe` to run a CPL file fetched from an external server, or uses WebDAV to run a remote DLL. That sequence - task creation immediately following mail-borne file execution, followed by Control Panel applet or `msiexec.exe` network activity - is the generalizable signal.

## Detection Guidance

```yaml
title: Suspicious Scheduled Task Creation Followed by Control Panel Applet Execution
status: experimental
description: >-
  Detects a newly created scheduled task invoking control.exe to run a
  Control Panel applet (CPL) DLL, or msiexec.exe/curl network activity
  shortly after scheduled task creation - consistent with the Star
  Blizzard RedFlick delivery chain used to stage the CosmicPulse backdoor.
references:
  - https://microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/
author: Aryan
date: 2026-10-14T00:00:00.000Z
tags:
  - attack.execution
  - attack.t1053.005
  - attack.defense_evasion
  - attack.t1218.002
  - attack.command_and_control
  - attack.t1105
logsource:
  category: process_creation
  product: windows
detection:
  selection_task_creation:
    EventID: 4698
    TaskContent|contains:
      - 'control.exe'
      - 'rundll32'
  selection_cpl_execution:
    Image|endswith: '\control.exe'
    CommandLine|contains: '.cpl'
  selection_followup_network:
    Image|endswith:
      - '\msiexec.exe'
      - '\curl.exe'
    ParentImage|endswith: '\schtasks.exe'
  condition: selection_task_creation or (selection_cpl_execution and selection_followup_network)
  timeframe: 15m
  # Also hunt: scheduled tasks named "Internet Quality Test Connection",
  # "Network Configuration Manager", or "System Health Monitor" - the
  # exact names observed in Microsoft's reported campaigns (expect
  # variants in future waves)
falsepositives:
  - Legitimate IT asset-management or monitoring software that creates
    scheduled tasks with generic network-diagnostic names
  - Help-desk use of Control Panel applets for genuine configuration tasks
level: high
```

## Prevention

- Enforce phishing-resistant authentication (FIDO2/passkeys) and Conditional Access on accounts likely to receive Ukraine/NGO/think-tank-themed lures - this actor's entire chain starts from a single email interaction.
- Treat scheduled task creation shortly after an email attachment or link is opened as a high-priority alert regardless of the task's name - this group deliberately renames its tasks every few campaigns.
- Block non-essential outbound SSH and restrict `ssh.exe` use with `PermitLocalCommand`, which this actor has abused as a delivery step.
- Enable attack surface reduction rules and EDR in block mode to stop CPL-based and `msiexec.exe`-driven payload downloads before the backdoor stage decrypts.

*See also: [Star Blizzard / SEABORGIUM - Russian FSB-Linked Credential Phishing and Espionage Actor](/actors/star-blizzard/) for the actor's broader behavioral pattern.*

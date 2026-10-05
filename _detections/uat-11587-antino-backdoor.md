---
title: "UAT-11587 - Antino Backdoor Abuses Microsoft Graph API for C2 (Threat Brief)"
layout: default
---

## Overview

**Antino** is a Rust-compiled Windows backdoor - built in both 32-bit and 64-bit variants - deployed by a China-nexus espionage actor Cisco Talos tracks as **UAT-11587**. Talos first observed the group in September 2025 via a spear-phishing campaign against Taiwan's academic, think-tank, and civil-society policy community, and by July 2026 had linked at least 16 affected or targeted institutions across eight Asian countries (Taiwan, India, the Philippines, Cambodia, Pakistan, Thailand, Myanmar, and Syria) - roughly 350 compromised endpoints in total.

What sets Antino apart technically is its command-and-control design: it has no bespoke C2 server at all. Instead it authenticates to an attacker-controlled Microsoft 365 tenant and uses the **Microsoft Graph API** to treat Outlook and OneDrive as its C2 transport. The backdoor polls a dead-drop Outlook mailbox roughly every 10 seconds for messages named `command_req_[session_id]`, executes whatever it finds, and replies with a `command_res_[session_id]` message carrying the results. Separately, it uploads host telemetry files to an OneDrive folder about once a minute. Delivery is via spear-phishing with tailored decoy documents, and persistence is a plain Registry Run key - the operation invests its engineering effort in the C2 channel, not in the implant's complexity.

## Why this matters for detection

Routing C2 through `graph.microsoft.com` and `login.microsoftonline.com` is deliberately chosen to be undetectable by network allow-listing, domain reputation, or TLS inspection tuned for "known-bad" infrastructure - those are exactly the hostnames every legitimate Outlook and OneDrive client contacts continuously, all day, in every Microsoft 365 environment. It also sidesteps the victim's own Microsoft 365 audit trail: because the dead-drop mailbox lives in infrastructure the *attacker* controls, none of this traffic shows up in the victim tenant's Entra ID sign-in logs or Unified Audit Log - there's no OAuth consent grant or sign-in event to hunt for on the defender's side of the boundary. That leaves exactly one place to catch it: the endpoint. The question isn't "is this hostname bad" - it's "which process on this host is calling that hostname, and is it a process Microsoft shipped."

## Detection Guidance

```yaml
title: Non-Microsoft Process Beaconing to Microsoft Graph/Login Endpoints With Registry Run-Key Persistence
status: experimental
description: >-
  Detects a process that is not a known Microsoft-signed Office/OneDrive/
  Teams binary both writing a Registry Run-key value and making outbound
  HTTPS connections to graph.microsoft.com or login.microsoftonline.com,
  consistent with the Antino backdoor's (UAT-11587) Microsoft 365-based
  C2 channel, which polls an attacker-controlled Outlook mailbox roughly
  every 10 seconds and periodically uploads telemetry to OneDrive.
references:
  - https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/
  - https://thehackernews.com/2026/10/antino-backdoor-uses-outlook-and.html
  - https://securityaffairs.com/200264/apt/antino-backdoor-uses-your-inbox-as-its-control-panel.html
author: Aryan
date: 2026-10-05
tags:
  - attack.persistence
  - attack.t1547.001
  - attack.command_and_control
  - attack.t1102.002
  - attack.t1071.001
logsource:
  category: process_creation
  product: windows
  definition: 'Requires Sysmon Event ID 13 (registry value set) correlated against Event ID 3 (network connection) for the same Image/process, or equivalent EDR process+network telemetry'
detection:
  selection_runkey_write:
    TargetObject|contains: '\Software\Microsoft\Windows\CurrentVersion\Run\'
  selection_graph_beacon:
    DestinationHostname:
      - 'graph.microsoft.com'
      - 'login.microsoftonline.com'
  filter_known_ms_binaries:
    Image|endswith:
      - '\outlook.exe'
      - '\onedrive.exe'
      - '\teams.exe'
      - '\ms-teams.exe'
      - '\OneDriveSetup.exe'
  condition: selection_runkey_write and selection_graph_beacon and not filter_known_ms_binaries
  timeframe: 5m
falsepositives:
  - Enterprise RMM agents or Power Automate desktop flows that legitimately call Microsoft Graph on a schedule and also configure their own Run-key entry during install
  - Custom-branded or repackaged Office/OneDrive deployments whose binary name does not match the standard filter list above
level: high
```

## Prevention

- Baseline which processes on an endpoint are permitted to call `graph.microsoft.com`/`login.microsoftonline.com` (Outlook, OneDrive, Teams, approved RMM/automation tools) and alert on any binary outside that set contacting them at all, not only alongside the Run-key signal.
- Don't rely on the victim tenant's own Entra ID sign-in logs or Unified Audit Log to catch this activity - Antino authenticates against the attacker's own Microsoft 365 tenant, so none of this traffic generates an event inside the victim's cloud audit boundary.
- Apply the same decoy-document scrutiny used against known spear-phishing lures to inbound mail aimed at government, policy, defense, and civil-society staff - sandbox attachments before they reach the end user.
- Monitor Registry Run-key creation as a standing, low-noise detection in sensitive environments; Antino has no fallback persistence mechanism if this one is caught and removed.

*See also: [UAT-11587 - China-Nexus Espionage Actor Behind the Antino Microsoft 365 C2 Backdoor](/actors/uat-11587/) for the actor's broader behavioral pattern.*

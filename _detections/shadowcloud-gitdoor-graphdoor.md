---
title: "Operation ShadowCloud - GitDoor & GraphDoor Backdoors Abuse GitHub and SharePoint for Cloud-Based C2 (Threat Brief)"
layout: default
---

## Overview

**Operation ShadowCloud** is a cyber-espionage campaign that Kaspersky's Global Research and Analysis Team (GReAT) disclosed on 2026-11-17, targeting government organizations across Southeast Asia, Africa, and Central Asia. Kaspersky says infrastructure preparation dates back to late 2024, with the activity itself first identified in early 2026. Intrusions begin through the legitimate **MeshCentral Agent** remote-management tool, which delivers a loader that launches one of two previously undocumented Windows backdoors: **GitDoor** or **GraphDoor**.

GitDoor's defining trait is using **GitHub itself as a command-and-control channel**. It registers each victim via a GitHub issue, then polls a public repository for task files while toggling an issue label as a signaling mechanism; results are posted back to a separate, private repository so operators can read output without exposing it publicly. GitDoor supports 26 commands spanning file management, keylogging, and proxy operation, and can load on-demand plug-ins for screenshots, process listing, and keystroke capture. A secondary channel abuses **Ably**, a legitimate real-time messaging service - one plug-in (`ab2channel.ts`) runs a covert SOCKS5 proxy tunneled through Ably's Pusher-compatible WebSocket service, letting operators pivot into the victim network without ever touching attacker-owned infrastructure.

**GraphDoor** takes the same cloud-abuse approach through a different vendor: it authenticates to Microsoft Entra ID via the OAuth 2.0 client-credentials flow using a hardcoded application ID and client secret, obtains a Microsoft Graph access token tied to an application identity rather than a user sign-in, and exchanges data through a victim's own **SharePoint** tenant - stolen host data is uploaded to a document library disguised as a JavaScript source-map file, while commands are read from a SharePoint list. Its plug-ins cover screenshots, process enumeration, and keylogging, with captured keystrokes stored locally at `%APPDATA%\Microsoft\SystemCertificates\Cache\logs.dat`. Kaspersky notes technical overlaps with the FamousSparrow and CopperTurtle (BlackTech) clusters consistent with a Chinese-speaking developer or operator, but is explicit that this does not establish a confirmed link to either named group - the campaign remains formally unattributed.

## Why this matters for detection

GitDoor and GraphDoor are built specifically to defeat network-perimeter and domain-reputation defenses: `api.github.com`, `*.sharepoint.com`, and Ably's realtime endpoints are all domains that enterprise proxies and DNS filters allow by default, and traffic to them is indistinguishable from legitimate developer or Office 365 activity at the TLS layer. Static IOC lists (specific repo names, SharePoint site names, Ably tokens) are also a losing strategy here, since each campaign wave can spin up new GitHub repositories and SharePoint sites trivially. What's durable is the **process-to-destination pairing**: a workstation or server process that is not a browser, Office application, or approved developer tool making repeated, regular outbound calls to GitHub's API, a SharePoint tenant it has no business reason to reach, or Ably's WebSocket service is the signal that survives infrastructure rotation. The MeshCentral Agent initial-access step is also notable - it's a legitimate, signed RMM tool, so its mere presence isn't malicious, but its appearance on a host that didn't provision it through an approved deployment process is.

## Detection Guidance

```yaml
title: Non-Browser Process Beaconing to GitHub API, SharePoint, or Ably Realtime Endpoints
status: experimental
description: >-
  Detects outbound network connections to api.github.com, SharePoint
  tenant hosts, or Ably's realtime/pusher WebSocket endpoints from a
  process that is not a browser, Office application, or recognized
  developer tool - consistent with the GitDoor/GraphDoor cloud-based C2
  channels observed in Operation ShadowCloud (Kaspersky GReAT, 2026-11-17).
references:
  - https://securelist.com/operation-shadowcloud-gitdoor/122004/
  - https://thehackernews.com/2026/11/new-gitdoor-and-graphdoor-backdoors.html
  - https://kaspersky.com/about/press-releases/kaspersky-operation-shadowcloud-targets-government-networks-across-asia-and-africa
author: Aryan
date: 2026-11-21T00:00:00.000Z
tags:
  - attack.command_and_control
  - attack.t1102.002
  - attack.t1567.001
  - attack.collection
  - attack.t1056.001
  - attack.defense_evasion
  - attack.t1574.002
logsource:
  category: network_connection
  product: windows
detection:
  selection_cloud_c2_hosts:
    DestinationHostname|contains:
      - 'api.github.com'
      - '.sharepoint.com'
      - 'realtime.ably.io'
      - 'rest.ably.io'
  filter_approved_processes:
    Image|endswith:
      - '\chrome.exe'
      - '\msedge.exe'
      - '\firefox.exe'
      - '\outlook.exe'
      - '\onedrive.exe'
      - '\teams.exe'
      - '\git.exe'
      - '\code.exe'
  condition: selection_cloud_c2_hosts and not filter_approved_processes
  timeframe: 1h
  # Escalate to critical if the parent process is meshagent.exe (MeshCentral
  # Agent) or any other RMM tool not present in the environment's approved
  # tooling baseline, or if the same process also writes to
  # %APPDATA%\Microsoft\SystemCertificates\Cache\logs.dat
falsepositives:
  - Developer workstations with legitimate git/IDE integrations polling GitHub
  - Native SharePoint sync clients (OneDrive) and Power Automate/Graph-based line-of-business integrations
  - Legitimate Ably SDK usage by approved internal applications
level: high
```

## Prevention

- Baseline which processes on each host legitimately talk to `api.github.com`, SharePoint, and Ably - flag any new or unapproved process making these calls rather than relying on domain blocklisting, which these channels are specifically designed to evade.
- Audit Entra ID app registrations and client secrets for unrecognized applications holding SharePoint/Graph permissions (`Sites.ReadWrite.All` or similar); GraphDoor depends entirely on a valid, hardcoded application credential.
- Restrict and monitor deployment of remote-management tools like MeshCentral Agent - require it to arrive only through an approved provisioning pipeline, and alert when it appears on a host outside that pipeline.
- Hunt for `%APPDATA%\Microsoft\SystemCertificates\Cache\logs.dat` and similarly disguised file paths used to stage keylogger output before exfiltration.
- Don't treat "traffic to a well-known cloud service" as inherently benign for perimeter monitoring purposes - GitHub, SharePoint, and Ably are chosen precisely because they're already trusted and allow-listed almost everywhere.

---
title: "CaptiveCrunch - Hotel Wi-Fi Captive Portal Hijack (Threat Brief)"
layout: default
---

## Overview

**CaptiveCrunch** is a campaign, disclosed by Microsoft on 2026-07-31, in which the Russian threat cluster **Storm-2945** - assessed as a sub-cluster of Midnight Blizzard (APT29) - manipulates DNS and HTTP traffic on shared captive-portal Wi-Fi services used by hotels and conference venues. Rather than compromising each venue's network individually, the actor appears to have gained access to shared infrastructure within portions of the captive-portal ecosystem itself, letting it redirect sign-in traffic across many properties at once.

The delivery mechanism abuses network-connectivity-status-indicator (NCSI) requests - the automatic checks Windows and browsers make when a device joins a new Wi-Fi network - to serve fake browser/OS update prompts that drop malware, or to redirect victims toward Microsoft 365-spoofing domains for device-code and adversary-in-the-middle (AiTM) credential theft. Two custom payloads have been observed: **CornFlake**, a Go-based RAT with keylogging, media-capture, and Chrome App-Bound Encryption bypass; and **ChocoShell**, an in-memory PowerShell infostealer that chains a three-stage UAC bypass (SilentCleanup, wsreset.exe, sdclt.exe hijacks) and beacons to C2 disguised as pixel-tracking requests.

## Why this matters for detection

The initial compromise happens at the network layer, on infrastructure the victim organization doesn't own or control - there is no phishing email, malicious attachment, or suspicious link for a SOC to flag, and no way for a traveler to visually distinguish a hijacked captive portal from a legitimate one. Detection has to shift to what happens *on the endpoint* immediately after joining an untrusted network: a file write arriving within moments of an NCSI check, a Windows service registering under a name designed to blend in with legitimate system processes, or a UAC-bypass chain firing through binaries (wsreset.exe, sdclt.exe) that are never normally spawned as part of an update flow. Each of these is a strong, narrow signal precisely because the network-layer redirect itself is invisible to host-based tooling.

## Detection Guidance

```yaml
title: CaptiveCrunch - Post-Wi-Fi-Join Malware Staging and UAC Bypass Chain
status: experimental
description: >-
  Detects Windows service registration masquerading as a system process
  (as used by the CornFlake RAT) or execution of wsreset.exe/sdclt.exe
  immediately spawning a child process consistent with the ChocoShell
  three-layer UAC bypass, both associated with the Storm-2945 CaptiveCrunch
  captive-portal Wi-Fi hijack campaign.
references:
  - https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/
  - https://www.zscaler.com/blogs/security-research/captivecrunch-midnight-blizzard-weaponizes-hotel-wi-fi-captive-portals
  - https://thehackernews.com/2026/08/hijacked-hotel-wi-fi-pushes-fake.html
author: Aryan
date: 2026-08-30T00:00:00.000Z
tags:
  - attack.persistence
  - attack.t1543.003
  - attack.defense_evasion
  - attack.t1548.002
  - attack.credential_access
  - attack.t1555.003
logsource:
  category: process_creation
  product: windows
detection:
  selection_fake_service:
    EventID: 7045
    ServiceName: 'svchost32'
    ServiceFileName|contains:
      - '\Users\'
      - '\AppData\'
  selection_uac_bypass_parent:
    ParentImage|endswith:
      - '\wsreset.exe'
      - '\sdclt.exe'
  selection_uac_bypass_child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
  condition: selection_fake_service or (selection_uac_bypass_parent and selection_uac_bypass_child)
  # Escalate to critical if either fires within 5m of a new Wi-Fi SSID
  # association event (EventID 8001/Microsoft-Windows-WLAN-AutoConfig) or
  # an NCSI check to msftconnecttest.com on the same host
falsepositives:
  - Legitimate third-party "Cloud Sync" or backup agents that register a similarly generic service name
  - IT-approved scripts that legitimately invoke wsreset.exe or sdclt.exe for troubleshooting
level: high
```

## Prevention

- Block OAuth device-code authentication flows via Conditional Access unless explicitly required, since this campaign relies on device-code phishing for Microsoft 365 account takeover.
- Require enterprise travelers to use mobile hotspots or MDM-issued travel routers rather than hotel or conference-venue Wi-Fi; disable manual Wi-Fi network configuration via MDM policy where feasible.
- Route unavoidable guest-network access through a Security Service Edge / Global Secure Access proxy so DNS and HTTP responses can't be silently rewritten in transit.
- Alert on service creation events where the service name mimics a core Windows process (svchost, svchost32, etc.) but the executable path points outside System32 - a strong, low-noise indicator regardless of which campaign is behind it.

*See also: [Storm-2945 / Midnight Blizzard - CaptiveCrunch Hotel Wi-Fi Hijack Operators](/actors/storm-2945/) for the actor's broader behavioral pattern.*

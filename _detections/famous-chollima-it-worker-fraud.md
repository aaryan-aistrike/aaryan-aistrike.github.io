---
title: "Famous Chollima / Jasper Sleet - Concurrent Remote-Access Tooling on Newly Onboarded Endpoints (Threat Brief)"
layout: default
---

## Overview

**Famous Chollima** (CrowdStrike) / **Jasper Sleet** (Microsoft, formerly Storm-0287) is a North Korean state-backed operation that gets DPRK-trained IT workers hired as remote developers and contractors at Western companies using stolen or fabricated identities. CrowdStrike attributes 47% of all state-backed activity targeting the tech sector between April 2025 and May 2026 to this cluster, tracking 320+ incidents (+220% year-over-year) across 100+ infiltrated companies. A five-week honeypot operation ("Ballena Azul," a fake crypto startup run by researchers Mauro Eldritch and Heiner García) publicly documented in August 2026 confirmed the operational tradecraft first-hand: onboarded operators deployed Google/Chrome Remote Desktop via unattended PowerShell with a fixed, trivial PIN, then layered it on top of AnyDesk to maintain persistent, concurrent control of the company-issued endpoint - alongside browser extensions for AI-assisted interview cheating and OTP interception.

## Why this matters for detection

This scheme's entry point is HR, not a technical exploit, which means most of an intrusion's lifecycle is invisible to conventional network detection - the "attacker" has valid credentials, a valid badge, and a valid paycheck. The one place the tradecraft does leave a technical fingerprint is the endpoint itself: legitimate remote employees don't typically install *two* independent remote-control tools on day one, and IT admins don't typically stand up Chrome Remote Desktop through unattended PowerShell with a hardcoded PIN instead of the normal interactive/OAuth flow. Correlating that endpoint pattern against how recently the associated account was provisioned turns a generic "remote access tool present" alert (high noise on its own) into a high-confidence insider-fraud signal.

## Detection Guidance

```yaml
title: Concurrent Remote Access Tooling on Recently Provisioned Endpoint
status: experimental
description: >-
  Detects two or more independent remote access tools (AnyDesk, Chrome/Google
  Remote Desktop) present or executing on the same endpoint, or Chrome Remote
  Desktop being set up via unattended PowerShell/CLI with a hardcoded PIN,
  consistent with DPRK fraudulent remote IT worker tradecraft (Famous
  Chollima / Jasper Sleet) used to maintain covert, concurrent control of a
  company-issued device.
references:
  - https://www.crowdstrike.com/en-us/adversaries/famous-chollima/
  - https://www.microsoft.com/en-us/security/blog/2025/06/30/jasper-sleet-north-korean-remote-it-workers-evolving-tactics-to-infiltrate-organizations/
  - https://thehackernews.com/2026/08/researchers-built-fake-crypto-startup.html
author: Aryan
date: 2026-08-28T00:00:00.000Z
tags:
  - attack.initial_access
  - attack.t1078
  - attack.persistence
  - attack.t1219
detection:
  selection_anydesk:
    Image|endswith: '\anydesk.exe'
  selection_chrome_remote_desktop:
    Image|endswith: '\remoting_host.exe'
  selection_unattended_crd_setup:
    CommandLine|contains|all:
      - 'powershell'
      - 'remoting_start_host'
      - '--pin='
  condition: (selection_anydesk and selection_chrome_remote_desktop) or selection_unattended_crd_setup
  timeframe: 7d
  # Correlate against HR/IdP provisioning data: prioritize when the host's
  # assigned user account was created within the last 14 days
logsource:
  category: process_creation
  product: windows
falsepositives:
  - MSP or IT-support environments where dual remote-access tooling is standard practice
  - IT staff scripting bulk Chrome Remote Desktop deployment for legitimate fleet management
level: medium
```

## Prevention

- Treat remote-access tool installation on freshly provisioned accounts (first 14-30 days) as a review-worthy event, not routine noise - correlate EDR telemetry with HR/IdP onboarding dates.
- Require live, unscripted video verification during hiring and again at first-day IT onboarding; refusal or evasive behavior on camera is a documented red flag for this specific scheme.
- Restrict which remote-access tools are approved for company-issued devices and alert on any tool outside that allowlist, especially ones installed via unattended CLI/PowerShell rather than interactive setup.
- Cross-check new hires' banking, shipping, and claimed-location details for internal consistency, and flag VPN/proxy egress geography that doesn't match the employee's stated location.

*See also: [Famous Chollima / Jasper Sleet - DPRK Fraudulent Remote IT Worker Scheme](/actors/famous-chollima/) for the actor's broader behavioral pattern.*

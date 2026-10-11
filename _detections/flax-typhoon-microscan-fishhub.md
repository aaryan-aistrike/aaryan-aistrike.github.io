---
title: "Flax Typhoon - SoftEther VPN Bridge Disguised as a System Process (Threat Brief)"
layout: default
---

## Overview

On 2026-10-08, the US Department of Justice and FBI seized seven domains tied to **MicroScan** and **FishHub** - a vulnerability scanner and a spear-phishing platform built and operated by Integrity Technology Group, the Beijing-based company US authorities attribute to the China-nexus espionage actor Microsoft tracks as **Flax Typhoon** (CrowdStrike: Ethereal Panda). A companion eight-nation advisory (CISA/FBI/NSA plus UK, Australia, Canada, Japan, New Zealand, and Spain) detailed the group's use of MicroScan to mass-identify victims running long-unpatched software - CISA added five of the resulting CVEs (spanning ProFTPD, ONLYOFFICE Docs, Strapi, Apache Struts, and ISC BIND) to its Known Exploited Vulnerabilities catalog, with a federal patch-or-disconnect deadline of 2026-10-11. Documented MicroScan targets include a South Carolina power company, airports in Japan and Poland, and Taiwanese natural-gas, power, and university networks.

Critically, the exploited CVE varies by target, but the group's **post-access tradecraft has stayed consistent since Microsoft first documented it in 2023**: a legitimate SoftEther VPN client, fetched via `Invoke-WebRequest`, renamed to impersonate a benign Windows system binary (commonly `conhost.exe`), and run to open a persistent VPN-over-HTTPS bridge back into the victim environment. Lateral movement then relies on built-in tooling (WMIC, WinRM, Mimikatz, Juicy Potato) rather than custom malware.

## Why this matters for detection

Because Flax Typhoon's initial-access vulnerability rotates with whatever unpatched public-facing software MicroScan finds, a detection strategy built around any single CVE will age out the moment the group's scanning turns up a different target. The far more durable signal is the **SoftEther-as-a-system-binary** pattern that has held across years of reporting: a renamed VPN client executed from a path or name it has no legitimate reason to occupy, downloaded through PowerShell rather than installed through normal software deployment, immediately followed by an outbound HTTPS connection that behaves like a persistent tunnel rather than a browser request. This generalizes across whichever CVE got the actor in the door, and it doesn't depend on catching the exploitation attempt itself.

## Detection Guidance

```yaml
title: SoftEther VPN Client Downloaded via PowerShell and Executed as a Renamed System Binary
status: experimental
description: >-
  Detects a PowerShell-initiated download of an executable followed by
  execution of a process using the filename of a legitimate Windows
  system binary (e.g. conhost.exe) from a non-standard path, consistent
  with Flax Typhoon's documented use of a renamed SoftEther VPN client
  to establish a persistent VPN-over-HTTPS bridge after exploiting a
  public-facing application.
references:
  - https://www.justice.gov/usao-wdpa/pr/justice-department-and-fbi-seize-vulnerability-scanning-and-spear-phishing-tools
  - https://thehackernews.com/2026/10/flax-typhoon-exploits-five-flaws-as.html
  - https://cyberscoop.com/doj-fbi-seize-flax-typhoon-hacking-tools-microscan-fishhub/
  - https://thehackernews.com/2023/08/china-linked-flax-typhoon-cyber.html
author: Aryan
date: 2026-10-11
tags:
  - attack.initial_access
  - attack.t1190
  - attack.command_and_control
  - attack.t1572
  - attack.defense_evasion
  - attack.t1036.005
  - attack.lateral_movement
  - attack.t1021
logsource:
  category: process_creation
  product: windows
detection:
  selection_powershell_download:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - 'Invoke-WebRequest'
      - 'IWR '
      - 'DownloadFile'
  selection_renamed_system_binary:
    Image|endswith:
      - '\conhost.exe'
      - '\dllhost.exe'
      - '\svchost.exe'
    NOT Image|startswith: 'C:\Windows\System32\'
    NOT Image|startswith: 'C:\Windows\SysWOW64\'
  condition: selection_powershell_download and selection_renamed_system_binary
  timeframe: 15m
  # Correlate: the renamed binary should also be checked for an outbound
  # HTTPS connection held open significantly longer than a normal browser
  # request - consistent with a VPN-over-HTTPS tunnel rather than a single
  # transaction
falsepositives:
  - Legitimate software deployment tools that stage renamed helper binaries outside System32 during installation
  - Endpoint management agents that legitimately execute process names matching Windows system binaries from vendor-specific paths
level: high
```

## Prevention

- Treat any process using a Windows system-binary filename (`conhost.exe`, `svchost.exe`, `dllhost.exe`, etc.) running from outside `System32`/`SysWOW64` as a near-certain red flag - no legitimate copy of these binaries belongs anywhere else.
- Fully decommission legacy application versions rather than leaving them installed alongside current ones; four of the five CVEs CISA added here are a decade or more old, meaning they only matter to organizations that never finished a retirement they thought was done.
- Alert on PowerShell-initiated downloads (`Invoke-WebRequest`, `DownloadFile`) that are immediately followed by execution of the downloaded file, independent of what that file is named.
- Monitor for and restrict outbound SoftEther VPN traffic and other VPN-over-HTTPS tunneling tools at the network egress layer; these tools are legitimate but have no business running unmanaged on a standard endpoint.

*See also: [Flax Typhoon / Ethereal Panda - China-Nexus Espionage Actor Behind the MicroScan/FishHub Toolset](/actors/flax-typhoon/) for the actor's broader behavioral pattern.*

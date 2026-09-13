---
title: "PaperCut NG/MF AI-Orchestrated Exploitation Swarm (Threat Brief)"
layout: default
---

## Overview

Starting 2026-08-31, a suspected Russian-speaking actor ran an **AI-orchestrated exploitation campaign** against internet-facing PaperCut NG/MF print management servers, using hundreds of concurrent AI agents rather than a human operating team. Per GreyNoise's research, the operator wired an OpenAI Codex harness to a DeepSeek model, added a persistent-memory layer ("Hindsight") and a multi-agent driver ("AionUi"), and pulled its target list directly from the Netlas.io internet-scanning service using an exposed API key. The agents then independently built, tested, and fixed exploits for two PaperCut flaws - **CVE-2026-81578** (authentication bypass) and **CVE-2026-82078** (unsafe dynamic class loading leading to RCE) - and chained them with a standard offensive toolkit: Mimikatz, Certipy, BloodHound/SharpHound, Rubeus, Impacket, NetExec, Ligolo-ng, and custom Rust credential-collection utilities.

The results were compiled by GreyNoise from telemetry tied to source IP `45.142.193.132` (previously flagged since early July 2026 for probing Palo Alto, Ubiquiti, Citrix, SonicWall, and Proxmox VE infrastructure): at least **440 PaperCut instances** compromised across **395 organizations in 48 countries**, with the United States hit hardest (98 victims), followed by the UK (59), France (31), Spain (31), and Canada (24). Education was the most-targeted sector (204 victims). The operator had instructed its agents to avoid 28 named countries, but the automation didn't fully respect that list - GreyNoise observed victims inside Russia, China, Kazakhstan, and Pakistan anyway, a failure researchers dubbed "agents gone wild."

The speed is the headline finding: the operator went from an empty workspace to remote code execution against a real victim in **under four hours**, reached first Domain Admin **two hours after that**, and once the campaign was fully live, compromised at least 11 organizations in a single **26-second** window. Credentials were harvested from 280 victims, OS/domain secrets from 147, and full domain admin from 12.

## Why this matters for detection

This campaign is a preview of what AI-orchestrated intrusion sets look like operationally: **exploit development, exploitation, credential theft, and lateral movement compressed into a single automated pipeline that runs at machine speed and in parallel across hundreds of targets simultaneously.** The individual tools involved (Mimikatz, Certipy, Rubeus, Impacket, NetExec) are all well-known and already covered by mature detection content - what's different is the *tempo and orchestration*: dozens of victims can move from initial access to domain admin inside a single shift, which collapses the response window a SOC would normally rely on between stages. It also reinforces that exposed application-scanning API keys (here, a leaked Netlas.io key) function as an initial-access enabler in their own right, by handing an automated attacker a ready-made target list.

## Detection Guidance

```yaml
title: PaperCut Process Spawning Shell Followed by Credential-Theft Tooling
status: experimental
description: >-
  Detects a PaperCut NG/MF server process (or its bundled Java runtime)
  spawning a command interpreter, followed shortly after by execution of
  common post-exploitation credential-theft or AD-enumeration tooling -
  consistent with automated exploitation of CVE-2026-81578 /
  CVE-2026-82078 as seen in the AI-orchestrated PaperCut campaign that
  began 2026-08-31.
references:
  - https://www.greynoise.io/blog/ai-orchestrated-campaign-against-papercut-ng-mf
  - https://thehackernews.com/2026/09/papercut-attacker-uses-hundreds-of-ai.html
  - https://www.helpnetsecurity.com/2026/09/11/ai-agents-papercut-ng-mf-attack-campaign/
author: Aryan
date: 2026-09-13T00:00:00.000Z
tags:
  - attack.initial_access
  - attack.t1190
  - attack.credential_access
  - attack.t1003
  - attack.discovery
  - attack.t1482
  - attack.lateral_movement
logsource:
  category: process_creation
  product: windows
detection:
  selection_papercut_shell_spawn:
    ParentImage|endswith:
      - '\pc-app.exe'
      - '\pc-server-service.exe'
      - '\java.exe'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
  selection_credential_tooling:
    Image|endswith:
      - '\mimikatz.exe'
      - '\certipy.exe'
      - '\rubeus.exe'
      - '\sharphound.exe'
      - '\netexec.exe'
    CommandLine|contains:
      - 'secretsdump'
      - 'certipy'
      - 'sekurlsa'
  condition: selection_papercut_shell_spawn and selection_credential_tooling
  timeframe: 1h
  # This campaign moved from initial shell to domain admin in ~2h and
  # compromised 11 orgs in 26s at peak - treat any hit here as urgent,
  # not queue-and-review
falsepositives:
  - PaperCut administrators running legitimate scripted maintenance via its scripting/print-provisioning hooks
  - Authorized red team or purple team exercises validating PaperCut exposure
level: critical
```

## Prevention

- Patch PaperCut NG/MF to the versions fixing CVE-2026-81578 and CVE-2026-82078 immediately - both are being actively, automatedly exploited at the time of writing.
- Never expose PaperCut's admin/web interface directly to the internet; place it behind a VPN or authenticated reverse proxy and restrict source IPs.
- Audit and rotate any exposed API keys for internet-scanning services (Netlas.io, Shodan, Censys) used internally - a leaked key here functioned as a ready-made target list for the attacker's automation.
- Treat detection latency as the primary risk with AI-orchestrated campaigns: alert on the *first* post-exploitation shell rather than waiting to correlate a full credential-theft chain, since the gap between initial access and domain admin can now be measured in hours, not days.
- Hunt for known offensive-tooling process names and command-line fragments (Mimikatz, Certipy, Rubeus, NetExec, Impacket's `secretsdump`) as a standing detection, independent of any single campaign - this toolkit is now common to both human-operated and AI-orchestrated intrusions.

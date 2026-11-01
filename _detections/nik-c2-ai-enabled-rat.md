---
title: "NIK C2 - AI-Enabled Windows RAT with OpenAI-Assisted Operations and Screen-Locking Extortion (Threat Brief)"
layout: default
---

## Overview

On 2026-10-29, Cisco Talos published research on **NIK C2**, a Go-based Windows remote access framework that embeds a direct integration with the OpenAI Chat Completions API. An `ai_generate` command lets an operator forward data pulled from a compromised host - stolen files, screenshots, system reconnaissance output - directly to an LLM and get back an analysis or next-step suggestion, without leaving the C2 panel. If the operator hasn't supplied their own API key, the implant falls back to any `OPENAI_API_KEY` already present in the victim's own environment variables, effectively billing the AI usage to the victim.

The implant itself is a conventional but fully-featured RAT: Talos catalogued more than 52 operator commands spanning browser password/cookie theft, Discord token and cryptocurrency wallet harvesting, keylogging, screenshot and microphone capture, RDP session hijacking, and process hollowing. It communicates over TLS WebSockets on port 443 (with an HTTP long-poll fallback every 250ms) using AES-256-GCM encryption on top of TLS, and is built with three prioritized C2 tiers so the framework survives takedown of any single server. Talos identified live infrastructure at `87.120.196[.]120`, tied to the domain `total-sitevv[.]lol`, with a TLS certificate common name of "nik-panel." Rather than a full file-encrypting ransomware module, the framework ships a non-destructive **screen-locking extortion** component: it backs up the victim's Master Boot Record, writes an HTML ransom page demanding Bitcoin or USDT, and launches it full-screen via `mshta.exe`, with a watchdog loop that relaunches the lock screen within seconds if the victim closes it. Talos assessed with moderate confidence that NIK C2 is an actively used, functional framework rather than a proof of concept, and has not attributed it to a specific named threat actor.

## Why this matters for detection

NIK C2 is notable less for novel tradecraft than for **collapsing two attacker workflows into one tool**: full-featured espionage/credential-theft RAT functionality and extortion, available together off the shelf. Its screen-lock-only "ransomware" leaves none of the artifacts most ransomware detections key on - no mass file renames, no new file extensions, no shadow-copy deletion - because it never touches victim files; the signal instead has to come from the `mshta.exe`-launched lock screen and its registry persistence. The OpenAI API integration is also a quiet but meaningful shift: outbound HTTPS traffic to `api.openai.com` from a host that shouldn't be making direct LLM API calls, especially correlated with a victim's own leaked API key, is a new and currently under-monitored exfiltration/C2 channel that most egress-filtering policies don't yet account for.

## Detection Guidance

```yaml
title: NIK C2 Lock-Screen Persistence via mshta.exe and SystemLock Run Key
status: experimental
description: >-
  Detects the NIK C2 screen-locking extortion module's installation
  pattern: a "SystemLock" autorun registry value invoking a batch script
  that relaunches an HTML ransom page through mshta.exe, consistent with
  Cisco Talos's October 2026 reporting on the NIK C2 framework.
references:
  - https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/
  - https://www.infosecurity-magazine.com/news/nik-c2-malware-victims-openai-keys/
  - https://cyberpress.org/nik-c2-abuses-openai/
  - https://gbhackers.com/nik-c2-malware/
author: Aryan
date: 2026-11-01
tags:
  - attack.command_and_control
  - attack.t1071.001
  - attack.persistence
  - attack.t1547.001
  - attack.impact
  - attack.t1491.001
  - attack.exfiltration
  - attack.t1567
logsource:
  category: process_creation
  product: windows
detection:
  selection_registry_persistence:
    TargetObject|contains: '\Software\Microsoft\Windows\CurrentVersion\Run\SystemLock'
  selection_mshta_lockscreen:
    Image|endswith: '\mshta.exe'
    CommandLine|contains:
      - 'lock_screen.html'
      - 'lock_start.bat'
  selection_openai_egress:
    Image|endswith:
      - '\svchost.exe'
      - '\csrss.exe'
    DestinationHostname|contains: 'api.openai.com'
    Initiated: 'true'
  condition: selection_registry_persistence or selection_mshta_lockscreen or selection_openai_egress
  falsepositives:
    - none of these selections individually occur during normal operation; csrss.exe/svchost.exe never make direct outbound HTTPS calls to third-party API endpoints
level: high
```

## Prevention

- Alert on any new autorun registry value under `Run`/`RunOnce` that invokes `cmd /c` against a `.bat` file in a user-writable temp directory - legitimate software rarely persists this way.
- Treat `mshta.exe` execution as inherently suspicious in modern environments; it has few legitimate business uses and is a long-standing LOLBin for both initial payload delivery and, as here, ransom-note display.
- Egress-filter or alert on direct process-level connections to LLM provider API endpoints (`api.openai.com`, `api.anthropic.com`, etc.) from endpoints that aren't an approved application - this is an emerging exfiltration/C2 channel, not just a productivity-tool traffic pattern.
- Rotate and scope API keys (including `OPENAI_API_KEY` and similar) stored in user environment variables rather than system-wide, and monitor for anomalous usage/billing spikes on LLM provider accounts, which can be the first visible sign of this kind of abuse.
- Maintain offline backups of the Master Boot Record/boot configuration on critical endpoints, since this and similar screen-lock extortion tooling target boot-level recovery as leverage even without encrypting data.

---
title: "Cereal / CerealBox - Turla's In-Memory Exchange Transport-Agent Hijack for Email Espionage (Threat Brief)"
layout: default
---

## Overview

**Cereal** is a previously undocumented malware toolset disclosed by ESET Research in November 2026 and attributed with high confidence to the Russia-aligned FSB-linked espionage actor Turla (Secret Blizzard / Snake / Uroburos). ESET first observed it on a government Exchange server in Kazakhstan on 2025-11-28, and later on a government Exchange server in Romania, where operators used it to selectively collect email exchanged with NATO and EU representatives.

The toolset's standout component, **CerealBox**, injects into `EdgeTransport.exe` - the Exchange process responsible for moving mail - and wraps the handlers of transport agents already loaded in memory, rather than registering a new transport agent of its own. Because no new agent is added, Exchange's transport-agent configuration appears completely unchanged while mail is being intercepted; ESET says this specific hijack technique has not been documented in any other malware family. CerealBox was configured to selectively harvest messages carrying document attachments (`.doc`, `.docx`, `.pdf`) rather than performing bulk exfiltration. A companion component, **CerealNeuron**, listens for incoming encrypted web requests on URL paths crafted to resemble legitimate Exchange service endpoints, giving operators an on-demand tasking channel that blends into normal webmail-adjacent traffic. ESET found no dedicated external C2 infrastructure tied to the observed intrusions - collection and tasking both ride on the compromised Exchange server's own legitimate-looking traffic.

## Why this matters for detection

Transport-agent abuse is typically hunted by auditing Exchange's agent configuration (`Get-TransportAgent`) for anything unexpected - and that approach is exactly what CerealBox is built to defeat, since it never registers as a distinct agent. The only reliable detection surface is **process- and module-level behavior on the Exchange server itself**: unexpected code injection into `EdgeTransport.exe`, unsigned or unfamiliar modules loaded by that process, or anomalous threads running inside it. The lack of conventional outbound C2 traffic also closes off the usual network-beaconing detection path, which is precisely why defenders need host-level EDR visibility on mail servers that are often under-instrumented compared to user endpoints.

## Detection Guidance

```yaml
title: Unsigned or Unexpected Module Load into Exchange EdgeTransport.exe
status: experimental
description: >-
  Detects an unsigned or non-Microsoft-signed module being loaded into
  EdgeTransport.exe outside of a known Exchange Cumulative Update install,
  consistent with in-memory transport-agent-handler hijacking as used by
  Turla's CerealBox component against government Exchange servers.
references:
  - https://www.welivesecurity.com/en/eset-research/exchange-for-breakfast-turlas-cereal-tricks-are-not-for-kids/
  - https://bleepingcomputer.com/news/security/turla-hackers-use-new-ceral-malware-to-spy-on-govt-exchange-servers
  - https://securityaffairs.com/202800/apt/russia-linked-apt-turla-turned-exchange-servers-into-their-own-control-room.html
author: Aryan
date: 2026-11-17T00:00:00.000Z
tags:
  - attack.persistence
  - attack.t1505.002
  - attack.collection
  - attack.t1114.002
  - attack.defense_evasion
  - attack.t1055
logsource:
  category: image_load
  product: windows
  definition: 'Requires Sysmon Event ID 7 (ImageLoad) enabled on Exchange mailbox/Edge Transport servers'
detection:
  selection_target_process:
    Image|endswith: '\EdgeTransport.exe'
  selection_image_load:
    EventID: 7
  filter_microsoft_signed:
    Signed: 'true'
    Signature|contains: 'Microsoft'
  filter_known_transport_agents:
    ImageLoaded|contains:
      - '\v15\TransportRoles\agents\'
  condition: selection_target_process and selection_image_load and not filter_microsoft_signed and not filter_known_transport_agents
  # Correlate: cross-reference against the Exchange CU/patch install window - an
  # unsigned module load into EdgeTransport.exe outside that window is high-signal
falsepositives:
  - Legitimate third-party transport agents (backup, DLP, antimalware connectors) registered with Exchange that load vendor-signed but non-Microsoft modules
  - Exchange Cumulative Update (CU) installation, which legitimately replaces or loads new EdgeTransport-related binaries
level: high
```

## Prevention

- Baseline the modules normally loaded by `EdgeTransport.exe` on each Exchange server and alert on deviation, rather than relying solely on `Get-TransportAgent` output, which CerealBox is specifically designed to leave unchanged.
- Restrict and audit who can install or modify transport agents (`Install-TransportAgent`/`Enable-TransportAgent`) - this capability requires elevated Exchange permissions that should be tightly scoped and logged.
- Deploy host-based EDR with code-injection and unsigned-module-load detection on Exchange servers specifically - these systems are frequently under-instrumented relative to user endpoints despite holding organization-wide mail.
- Patch Exchange promptly and reduce its internet-facing attack surface; while ESET did not publish the initial access vector for Cereal, Turla has a long history of exploiting unpatched Exchange and other edge infrastructure to gain the server access this toolset depends on.

*See also: [Turla / Secret Blizzard - Russian FSB-Linked Espionage Actor Behind the Cereal Exchange Mail-Interception Toolset](/actors/turla/) for the actor's broader behavioral pattern.*

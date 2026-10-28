---
title: "k0t Edge-Device Campaign - Credential Harvesting via FortiWeb and GlobalProtect Exploitation (Threat Brief)"
layout: default
---

## Overview

Group-IB and NyxLab published a joint investigation in October 2026, "Stray Cat, Open Doors: How k0t Wanders Through the Network Edge," documenting a large-scale credential-harvesting campaign run by an initial access broker tracked as **k0t** (aliases: CryptoFeel, Member19, QazWsxShop) and active since 2025-10-22. Between February and June 2026, the actor targeted internet-exposed FortiGate, FortiWeb, and Palo Alto GlobalProtect appliances - exploiting CVE-2025-64446 against FortiWeb, brute-forcing FortiGate SSL VPN logins, and using CVE-2026-0257 against GlobalProtect - and exposed more than 70,000 credentials drawn from network device logins and LDAP dumps.

For persistence, k0t ran a self-hosted MeshCentral server (`mesh[.]buttruyen[.]com`, agents hosted separately at `agent[.]afahimsa[.]top`) configured to auto-approve new agents, alongside AdaptixC2 as a second C2 channel, and layered commercial RMM tools - Atera, AnyDesk, Teramind, and ngrok - on top for additional access. Data was exfiltrated with Rclone to Wasabi and MEGA cloud storage. Victims subsequently appeared on the Qilin and The Gentlemen ransomware leak sites, though Group-IB stresses that link is unconfirmed; the campaign also showed negligible credential overlap with the separate FortiBleed harvesting dataset.

## Why this matters for detection

k0t's entire persistence and exfiltration stack is built from products that are legitimate in isolation - MeshCentral, AdaptixC2 client agents, Atera, AnyDesk, Teramind, ngrok, and Rclone are all in routine use by IT and MSP teams. Signature- or presence-based detection on any single tool generates too much noise to act on. What's detectable is the **combination within a short window on the same host**: an RMM or remote-access agent installing shortly before Rclone runs with a Wasabi or MEGA remote configured is a pattern this campaign's own tooling choices make distinctive, and it holds regardless of which specific RMM product an affiliate happens to use.

## Detection Guidance

```yaml
title: RMM Tool Install Followed by Rclone Exfiltration to Wasabi or MEGA
status: experimental
description: >-
  Detects installation of MeshAgent, AdaptixC2, Atera, AnyDesk, Teramind,
  or ngrok followed within 24 hours by rclone.exe execution configured
  against a Wasabi or MEGA remote on the same host - the RMM/C2 and
  cloud-exfiltration stack documented in the k0t edge-device credential
  theft campaign against FortiGate, FortiWeb, and GlobalProtect appliances.
references:
  - https://www.group-ib.com/blog/stray-cat-network-edge/
  - https://gbhackers.com/k0t-credential-theft/
  - https://securityonline.info/k0t-fortigate-globalprotect-attacks/
author: Aryan
date: 2026-10-28T00:00:00.000Z
tags:
  - attack.persistence
  - attack.t1133
  - attack.command_and_control
  - attack.t1219
  - attack.exfiltration
  - attack.t1567.002
logsource:
  category: process_creation
  product: windows
detection:
  selection_rmm_install:
    Image|endswith:
      - '\meshagent.exe'
      - '\AdaptixAgent.exe'
      - '\AteraAgent.exe'
      - '\anydesk.exe'
      - '\teramind.exe'
      - '\ngrok.exe'
  selection_rclone_exfil:
    Image|endswith: '\rclone.exe'
    CommandLine|contains:
      - 'wasabisys.com'
      - 'mega.nz'
      - 'mega.io'
  condition: selection_rmm_install and selection_rclone_exfil
  timeframe: 24h
  # Escalate to critical if preceded by FortiGate, FortiWeb, or GlobalProtect
  # admin-plane authentication from an unrecognized source IP in the prior 72h
falsepositives:
  - Legitimate MSP use of Atera, AnyDesk, or Teramind for remote support
  - Authorized Rclone backup jobs configured against a Wasabi or MEGA backend
level: high
```

## Prevention

- Patch FortiWeb against CVE-2025-64446 and GlobalProtect against CVE-2026-0257 without delay, and enforce MFA plus source-IP restriction on FortiGate SSL VPN to blunt brute-force attempts.
- Maintain an allowlist of approved RMM tools per environment and alert on any RMM binary - MeshAgent, AdaptixC2, Atera, AnyDesk, Teramind, ngrok - installing outside that list, especially on servers adjacent to edge appliances.
- Monitor outbound traffic to Wasabi and MEGA API endpoints from hosts that have no legitimate business reason to use either service, and treat Rclone invocation against either as worth investigating regardless of volume.
- Treat any confirmed compromise of an internet-facing FortiGate, FortiWeb, or GlobalProtect appliance as a precursor to broker-sold access rather than a single named ransomware brand - this campaign's victims fed more than one leak site.

*See also: [k0t / CryptoFeel - Edge-Device Initial Access Broker Behind a 70,000-Credential FortiGate/GlobalProtect Campaign](/actors/k0t/) for the actor's broader behavioral pattern.*

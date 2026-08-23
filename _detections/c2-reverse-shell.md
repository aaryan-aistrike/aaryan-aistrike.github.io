---
title: "C2 / Reverse Shell Activity - Network Beaconing (High-Confidence)"
layout: default
---

## Overview

Reverse shells and C2 frameworks (Cobalt Strike, Sliver, Metasploit, custom implants) rely on the compromised host initiating **outbound** connections to attacker infrastructure, since inbound connections are far more likely to be blocked by perimeter controls. This makes network-layer behavioral analysis - beaconing interval regularity, JA3/JA3S fingerprints, and destination reputation - more durable than payload-specific signatures, which change per campaign.

This rule combines **process-level indicators** (an unexpected process making outbound network connections) with **network-level indicators** (beacon-like periodicity) to raise confidence, since either alone produces excessive noise in most environments.

Key behavioral indicators:

- Living-off-the-land binaries (`cmd.exe`, `powershell.exe`, `rundll32.exe`, `certutil.exe`) making direct outbound TCP connections rather than a browser or expected network service
- Long-lived, low-and-slow beacon connections with consistent time intervals between packets (classic C2 heartbeat pattern) - jitter percentage is often visible in Cobalt Strike traffic if unencrypted metadata is inspectable
- Outbound connections to newly registered or freshly resolved domains, or to IPs with no corresponding DNS resolution (raw IP C2)
- Uncommon destination ports (4444, 8080, 8443, 50050) combined with process/user context that has no legitimate reason to use them

## Why this matters for detection

Because inbound connections are commonly blocked at the perimeter, virtually every C2 framework relies on outbound beaconing instead - which means network-layer behavioral signals like periodicity and LOLBin-initiated connections generalize across tooling and campaigns in a way payload-specific signatures never do, making them a far more durable detection investment.

---

## Detection Rule

```yaml
title: C2 / Reverse Shell - Suspicious Outbound Process Network Activity
status: stable
description: >-
  Detects living-off-the-land binaries or unsigned processes establishing
  direct outbound network connections, optionally correlated with beacon-like
  periodicity or connections to common C2 default ports, consistent with
  reverse shell or command-and-control activity.
references:
  - https://attack.mitre.org/techniques/T1071/
  - https://attack.mitre.org/techniques/T1105/
  - https://attack.mitre.org/techniques/T1571/
author: Aryan
date: 2026-08-23T00:00:00.000Z
tags:
  - attack.command_and_control
  - attack.t1071
  - attack.t1571
  - attack.t1105
logsource:
  category: network_connection
  product: windows
detection:
  selection_lolbin_network:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\rundll32.exe'
      - '\certutil.exe'
      - '\mshta.exe'
      - '\regsvr32.exe'
    Initiated: 'true'
  selection_common_c2_ports:
    DestinationPort:
      - 4444
      - 8080
      - 8443
      - 50050
  filter_known_proxies:
    DestinationIp|cidr: 'known_egress_proxy_subnets_placeholder'
  condition: (selection_lolbin_network or selection_common_c2_ports) and not filter_known_proxies
  # Correlate: same source host + destination pair repeating at a regular
  # interval (+/- low jitter) over an extended window as a beacon indicator
falsepositives:
  - Internal tooling or admin scripts that legitimately use cmd/PowerShell for outbound API calls
  - Development/test environments running services on non-standard high ports
  - Legacy applications using certutil for certificate operations rather than payload retrieval
level: high
```

## Prevention

- Restrict outbound network access from endpoints to an allow-list of required destinations/ports where feasible (egress filtering).
- Deploy TLS inspection or JA3/JA3S fingerprinting at the perimeter to flag known C2 client fingerprints.
- Alert on LOLBins (`cmd`, `powershell`, `rundll32`, `certutil`) making direct outbound connections, independent of destination.
- Baseline expected beaconing patterns per host/service so a genuinely new periodic connection stands out against normal traffic.

---
title: "Kerberoasting — Anomalous Service Ticket Requests (High-Confidence)"
layout: default
---

## Overview

Kerberoasting ([MITRE ATT&CK T1558.003](https://attack.mitre.org/techniques/T1558/003/)) abuses the Kerberos service ticket (TGS) request process to extract crackable password hashes for service accounts. Any authenticated domain user can request a TGS for any SPN-registered account, so the technique requires no elevated privileges and blends into normal authentication traffic.

This detection focuses on the **volume and encryption-type signature** of TGS requests rather than a single indicator, since a single RC4 ticket request is common in mixed environments and is not inherently malicious.

Key behavioral indicators:

- A single source account requesting TGS tickets for an unusually large number of distinct SPNs in a short window
- Preference for weaker encryption (RC4, etype 0x17) over AES when both are supported by the target account — a common sign of hash-cracking tooling (e.g. Rubeus, Impacket `GetUserSPNs.py`)
- TGS requests for service accounts the requesting user has never authenticated to before
- Requests originating from non-standard hosts (workstations rather than the systems that normally host the service)

---

## Detection Rule

```yaml
title: Kerberoasting - Anomalous Service Ticket Requests
status: stable
description: >-
  Detects potential Kerberoasting via high-volume TGS requests using RC4
  encryption for multiple distinct SPNs from a single account, consistent
  with automated hash-extraction tooling rather than normal service access.
references:
  - https://attack.mitre.org/techniques/T1558/003/
  - https://github.com/GhostPack/Rubeus
author: Aryan
date: 2026-08-23T00:00:00.000Z
tags:
  - attack.credential_access
  - attack.t1558.003
logsource:
  product: windows
  service: security
  definition: 'Requires Kerberos service ticket auditing (Event ID 4769) enabled via Advanced Audit Policy'
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
  filter_machine_accounts:
    TargetUserName|endswith: '$'
  filter_known_service_hosts:
    IpAddress|cidr: 'known_service_subnets_placeholder'
  condition: selection and not filter_machine_accounts and not filter_known_service_hosts
  timeframe: 10m
  # Correlate: same source account requesting TGS for >= 5 distinct SPNs within timeframe
falsepositives:
  - Legacy applications and older domain controllers that only support RC4
  - Legitimate service account provisioning scripts that enumerate SPNs
  - Vulnerability scanners performing Kerberos configuration checks
level: high
```

---
title: "Orova - ESXi VM Kill via esxcli Preceding Mass Encryption (Threat Brief)"
layout: default
---

## Overview

**Orova** is a ransomware-as-a-service operation running a purpose-built Linux/ESXi encryptor, first documented by SonicWall Capture Labs in August 2026. Tracker data dates the earliest confirmed attack to 2026-05-03, and the group's dark-web leak site went live on 2026-08-04, posting 24 victims on debut day and 35 within 72 hours. The encryptor is a ~90KB statically linked, stripped ELF64 binary with no external dependencies, built around a Curve25519 key exchange and ChaCha20 file encryption. Its most distinctive trait is deliberate hypervisor targeting: the binary enumerates running virtual machines via `esxcli` and force-kills them before encrypting datastore contents, denying defenders any window to gracefully shut down or migrate VMs first. Claimed victims span manufacturing, retail/e-commerce, healthcare, technology, hospitality, and agriculture, concentrated in the US with recurring clusters in Hong Kong and Taiwan - consistent with opportunistic exploitation of exposed VPN/remote-access infrastructure rather than narrow vertical targeting.

## Why this matters for detection

Because the encryptor itself is small, dependency-free, and stripped of symbols, signature-based detection on the binary is a weak bet - especially since a fresh sample can be recompiled per campaign. What's reliable is the **behavioral sequence on the hypervisor host**: `esxcli`-driven VM kill commands issued against multiple distinct virtual machines from a single shell session in a short window, followed by high-volume write activity against `.vmdk`/`.vmx` files on the same datastore. Most organizations instrument Sysmon/EDR on Windows endpoints but have little or no logging on the ESXi shell itself (`shell.log`, `hostd.log`, syslog) - which is exactly the blind spot this technique is built to exploit. Detecting the mass-kill precursor, rather than waiting for encryption to complete, is the only point in the chain where defenders still have time to isolate the datastore.

## Detection Guidance

```yaml
title: Orova-Style ESXi VM Mass Kill via esxcli Preceding Encryption
status: experimental
description: >-
  Detects rapid, repeated esxcli VM-kill invocations against multiple
  distinct virtual machines from a single ESXi shell session within a
  short window, consistent with ransomware pre-encryption VM
  termination (as seen in Orova intrusions).
references:
  - https://www.sonicwall.com/blog/orova-a-new-linux-ransomware-targeting-esxi-hypervisors
  - https://www.watchguard.com/wgrd-security-hub/ransomware-tracker/orova
  - https://www.kaspersky.com/blog/linux-vmware-esxi-ransomware-attacks/47988/
author: Aryan
date: 2026-09-27T00:00:00.000Z
tags:
  - attack.impact
  - attack.t1489
  - attack.t1486
  - attack.defense_evasion
  - attack.t1070.004
logsource:
  category: process_creation
  product: esxi
  definition: 'Requires ESXi shell/syslog forwarding (shell.log, hostd.log) to a central log collector'
detection:
  selection_vm_kill:
    CommandLine|contains|all:
      - 'esxcli'
      - 'vm process kill'
  condition: selection_vm_kill
  timeframe: 5m
  # Escalate to critical when >= 3 distinct VM world IDs are killed by the
  # same shell session within the timeframe, followed by write activity
  # against .vmdk/.vmx files on the same datastore
falsepositives:
  - Planned maintenance windows or DR failover scripts that forcibly power off VMs in bulk
  - vCenter-orchestrated host evacuation during patching or hardware replacement
level: high
```

## Prevention

- Disable ESXi shell and SSH access by default; when enabled for maintenance, require MFA through a jump host and re-disable immediately afterward - this is the surface Orova's kill/encrypt sequence runs on.
- Forward ESXi `shell.log`, `hostd.log`, and syslog to a central collector outside the hypervisor itself, since an attacker with host-level access can otherwise tamper with or delete local logs before detection.
- Harden and patch internet-facing VPN and remote-access appliances, and require MFA on them - consistent with Orova's opportunistic, VPN-edge initial access pattern.
- Keep VM backups and snapshots off the ESXi datastore itself (immutable, offline, or air-gapped), since an encryptor with force-kill capability can reach anything reachable from the compromised host.

*See also: [Orova - Curve25519/ChaCha20 Linux-ESXi Ransomware-as-a-Service](/actors/orova/) for the actor's broader behavioral pattern.*

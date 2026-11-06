---
title: "DeadLock Ransomware - BYOVD EDR Kill Chain and Polygon Blockchain C2 (Threat Brief)"
layout: default
---

## Overview

**DeadLock** is a financially motivated Windows ransomware operation, first observed around July 2025, that resurfaced and scaled sharply through mid-2026 - Microsoft's August 2026 analysis counted 80+ claimed victims, and SOCRadar's October 2026 tracking put cumulative leak-site claims above 120, more than half concentrated in Europe. Cisco Talos documented the operation's bring-your-own-vulnerable-driver (BYOVD) step: a previously undocumented loader (`EDRGay.exe`) drops a vulnerable signed Baidu Antivirus kernel driver (`BdApiUtil.sys`, disguised on disk as `DriverGay.sys`, tracked as **CVE-2024-51324**) and sends it a `DeviceIOControl` call with IOCTL `0x800024b4` and a target PID. The driver fails to validate the caller's privilege level and calls `ZwTerminateProcess` on its behalf, letting an unprivileged loader kill EDR/antivirus processes from kernel mode before the Rust-based encryptor runs. Talos assesses initial access comes via compromised valid accounts, with roughly five days of dwell time before deployment, AnyDesk installed for persistence, and interactive RDP/MMC-based lateral movement rather than scripted propagation.

The operation is also notable for concealing its victim-communication infrastructure on the **Polygon blockchain** (documented by Group-IB and Microsoft): an HTML wrapper dropped post-encryption resolves its chat-proxy address via a read-only `eth_call` against a Polygon smart contract, with failover across six public Polygon RPC endpoints - a deliberate hedge against infrastructure takedown, a technique researchers call EtherHiding.

## Why this matters for detection

The BYOVD step is the single highest-confidence, most reusable detection opportunity in this chain: `BdApiUtil.sys`/`DriverGay.sys` is a specific, known-vulnerable signed driver with no legitimate reason to load outside an active Baidu Antivirus deployment, and its appearance followed shortly by security-service termination is a strong, low-false-positive signal regardless of which ransomware deploys it next - BYOVD loaders are commonly reused across unrelated campaigns once documented. The encryptor's deliberate self-throttling (to keep the host responsive during encryption) means detections built purely around disk-I/O-volume anomalies will likely miss this operation; the kernel-driver-load event and the AnyDesk-installation-following-valid-authentication pattern are more durable signals than encryption-speed heuristics here. The blockchain-backed C2 also means takedown of the operation's web/file infrastructure alone will not fully disrupt victim communication, so detection and prevention at the host level matters more than it would against a conventional single-point-of-failure C2 setup.

## Detection Guidance

```yaml
title: DeadLock Ransomware Precursor - Vulnerable Baidu Driver Load Preceding Security Service Termination
status: experimental
description: >-
  Detects the loading of the vulnerable signed Baidu Antivirus kernel
  driver (BdApiUtil.sys / CVE-2024-51324, often renamed to DriverGay.sys)
  shortly before Windows Defender or another security service is stopped,
  consistent with the BYOVD loader (EDRGay.exe) DeadLock ransomware
  affiliates use to blind EDR/AV prior to encryption.
references:
  - https://blog.talosintelligence.com/byovd-loader-deadlock-ransomware/
  - https://www.group-ib.com/blog/deadlock-ransomware-polygon-smart-contracts
  - https://cyble.com/threat-actor-profiles/deadlock-ransomware/
  - https://thehackernews.com/2026/08/deadlock-ransomware-uses-polygon-smart.html
author: Aryan
date: 2026-11-06T00:00:00.000Z
tags:
  - attack.defense_evasion
  - attack.t1562.001
  - attack.privilege_escalation
  - attack.t1068
  - attack.impact
  - attack.t1486
logsource:
  category: driver_load
  product: windows
detection:
  selection_vulnerable_driver:
    EventID: 6
    ImageLoaded|endswith:
      - '\DriverGay.sys'
      - '\BdApiUtil.sys'
  selection_security_service_stop:
    EventID: 7036
    param1|contains:
      - 'Windows Defender'
      - 'Antivirus'
      - 'Endpoint'
  condition: selection_vulnerable_driver and selection_security_service_stop
  timeframe: 15m
  # Also alert independently on selection_vulnerable_driver alone on any host
  # without Baidu Antivirus installed - the driver has no other legitimate
  # reason to be present and is a high-confidence IOC on its own
falsepositives:
  - Legitimate Baidu Antivirus installations actively in use (uncommon outside China-region deployments) loading their own unmodified driver
level: high
```

## Prevention

- Add the Baidu Antivirus `BdApiUtil.sys` driver to Microsoft's recommended vulnerable-driver blocklist and enforce it via WDAC with HVCI - this closes the specific BYOVD path this operation relies on, and the same driver can be reused by unrelated actors once documented.
- Enable EDR tamper protection and alert independently on any unexpected kernel driver load on endpoints that don't run Baidu Antivirus as a matter of policy.
- Treat AnyDesk (or other remote-access tooling) installation shortly after a valid authentication event as worth investigating, not ignoring - this operation uses it for persistence after compromising legitimate credentials rather than deploying custom malware.
- Maintain offline, immutable backups and verify restoration procedures - because this operation routes victim communication through blockchain-backed infrastructure, takedown of its web presence alone will not stop extortion pressure, making backup integrity the more reliable mitigation.

*See also: [DeadLock - Blockchain-Concealed C2 Ransomware Operation](/actors/deadlock/) for the actor's broader behavioral pattern.*

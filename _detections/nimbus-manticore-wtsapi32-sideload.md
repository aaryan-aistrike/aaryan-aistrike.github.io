---
title: "Nimbus Manticore - TWOSTROKE-Like Backdoor via wtsapi32.dll Sideloading (Threat Brief)"
layout: default
---

## Overview

On 2026-08-26, Group-IB disclosed an expanded toolset used by **Nimbus Manticore** - one of the aliases tracked under the same Iran-linked cluster as **Mirage Kitten / UNC1549** (also known as Tortoiseshell, Smoke Sandstorm, and Subtle Snail), assessed as IRGC-affiliated. The new activity centers on two components that both masquerade as `wtsapi32.dll`, the legitimate Windows Terminal Server SDK DLL: a C++ backdoor related to the previously documented **TWOSTROKE** family, and a reverse SSH tunneling utility.

Both components are sideloaded via DLL search-order hijacking, with the malicious `wtsapi32.dll` forwarding the real DLL's exports to stay functional while running attacker code. The backdoor supports shell and file command execution, file upload/exfiltration, and host reconnaissance. The SSH tunneler routes its reverse tunnel over TCP/443 - a port almost always open outbound for HTTPS - to blend C2 traffic past firewall egress rules, with observed infrastructure including a C2 endpoint at `172.86.98.113:443`. Persistence is established through a Windows service whose `ImagePath` points at the sideloaded DLL rather than the legitimate one in `System32`. Group-IB reports the group's infrastructure and targeting now span Europe and the Middle East, in addition to this cluster's historical focus on defense, aerospace, IT services, and military organizations.

## Why this matters for detection

Because the payload DLL shares its filename with a legitimate, commonly-present Windows component, filename-based allowlisting is useless here - the signal is **location and loader context**, not the name. A `wtsapi32.dll` living anywhere other than `System32` is already anomalous regardless of what it does next, and a Windows service whose `ImagePath` resolves to that off-path copy is a second, independent confirmation of the same tampering. The choice of port 443 for the reverse SSH tunnel is specifically meant to defeat simplistic "block non-standard ports" egress filtering, so detection has to inspect the protocol riding on 443 (SSH handshake bytes), not just the port number, to catch a tunnel hiding inside what looks like ordinary HTTPS traffic.

## Detection Guidance

```yaml
title: Wtsapi32.dll Sideloading Outside System32 - Nimbus Manticore Backdoor/Tunneler
status: experimental
description: >-
  Detects a wtsapi32.dll file written or loaded from a path other than
  System32, or a Windows service whose ImagePath resolves to such a file,
  consistent with the DLL search-order hijacking used by Nimbus Manticore
  (Mirage Kitten/UNC1549) to sideload a TWOSTROKE-like backdoor and
  reverse SSH tunneler.
references:
  - https://thehackernews.com/2026/08/nimbus-manticore-expands-toolset-with.html
  - https://www.group-ib.com/blog/tortoiseshell-apt-toolset-infrastructure/
  - https://www.scworld.com/brief/nimbus-manticore-expands-infrastructure-and-malware-arsenal
author: Aryan
date: 2026-10-07T00:00:00.000Z
tags:
  - attack.defense_evasion
  - attack.t1574.001
  - attack.t1036.005
  - attack.persistence
  - attack.t1543.003
  - attack.command_and_control
  - attack.t1572
logsource:
  category: file_event
  product: windows
detection:
  selection_dll_write_outside_system32:
    TargetFilename|endswith: '\wtsapi32.dll'
  filter_legitimate_path:
    TargetFilename|contains:
      - '\Windows\System32\'
      - '\Windows\SysWOW64\'
      - '\Windows\WinSxS\'
  selection_service_imagepath:
    EventID: 7045
    ImagePath|contains: 'wtsapi32.dll'
  condition: (selection_dll_write_outside_system32 and not filter_legitimate_path) or selection_service_imagepath
  # Correlate: outbound connection from the sideloaded process to
  # 172.86.98.113:443, or any TLS-port destination carrying an SSH
  # protocol banner instead of a TLS ClientHello
falsepositives:
  - Legitimate software bundling or caching its own copy of system DLLs (rare, but seen in some portable/legacy application packaging)
  - Backup or imaging tools that stage a full System32 copy outside the normal path during restore operations
level: high
```

## Prevention

- Treat any `wtsapi32.dll` (or other well-known system DLL) found outside `System32`/`SysWOW64`/`WinSxS` as a confirmed compromise indicator, not a tuning exception - legitimate software has no reason to ship its own copy of this specific SDK DLL.
- Alert on new Windows services (Event ID 7045) whose `ImagePath` references a DLL host (`svchost.exe`, `rundll32.exe`) loading a path outside standard system directories.
- Inspect traffic on port 443 for protocol identity, not just port number - an SSH handshake on a port reserved for TLS is a strong anomaly signal independent of IP reputation.
- Apply application allowlisting or Windows Defender Application Control to block unsigned or mismatched-hash DLLs from loading under system process names.
- Monitor for outbound connections to `172.86.98.113` and rotate blocklists as Group-IB and other vendors publish updated infrastructure.

*See also: [Mirage Kitten / UNC1549 - Iranian Recruiter-Lure Espionage Actor](/actors/mirage-kitten/) for the actor's broader behavioral pattern - Nimbus Manticore is tracked as the same IRGC-affiliated cluster under a different vendor alias.*

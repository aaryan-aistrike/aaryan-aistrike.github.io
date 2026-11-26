---
title: "HYFLOCK - Partial-Encryption Flaw and Edge-Updater Masquerade (Threat Brief)"
layout: default
---

## Overview

**HYFLOCK** is a ransomware-as-a-service operation that emerged on underground forums around March 2026, began recruiting affiliates in May 2026, and has shipped four distinct build generations since April 2026. Check Point Research's deepest technical analysis targets an October 17, 2026 build, which stages itself under `ProgramData\EdgeUpdate_<suffix>\eu.exe` with a companion `eu.cfg` configuration file - a naming choice designed to pass a casual glance as legitimate Microsoft Edge auto-update infrastructure. That build registers a scheduled task for persistence, enumerates and interacts with network-share resources, and attempts to interfere with system recovery before encrypting files.

A per-directory ransom note ("How to Restore My Files.html") claims HC-128 encryption, but WatchGuard's binary analysis found the actual scheme is a hybrid AES-128-CTR + RSA-4096 implementation - the note's crypto claim doesn't match the code. More significantly for defenders and victims alike: Check Point found the October 17 build's encryption routine only processes the first 4,096 bytes of files larger than that, leaving the remainder of file content untouched. Testing against encrypted Office documents (ZIP containers composed of many internal parts) recovered 73 internal components intact from 7 test files. A key-backup artifact, `system_config.dat`, is also present on disk. No general decryptor was released since the key itself wasn't recovered, but the flaw means naive "all data is lost" assumptions may be wrong for files above the 4KB threshold.

## Why this matters for detection

Most of HYFLOCK's defender-relevant signal isn't in the encryption math - it's in the deployment artifacts around it. A process or scheduled task named to resemble Edge's updater (`eu.exe` / `eu.cfg`) staged under a `ProgramData\EdgeUpdate_*` directory that doesn't match Microsoft's actual Edge update service naming and install path is a concrete, checkable anomaly, especially when it's immediately followed by mass file writes/renames and a same-named HTML file ("How to Restore My Files.html") appearing in many directories in a short window. Because the group is only months old and has already shipped four build generations, specific extensions and marker strings should be expected to keep shifting - the sequence (fake-updater staging -> scheduled task creation -> mass file modification -> ransom note drop) is the more durable signal than any single filename.

## Detection Guidance

```yaml
title: HYFLOCK Ransomware - Edge-Updater Masquerade Staging and Mass Ransom Note Drop
status: experimental
description: >-
  Detects a process staged under a ProgramData\EdgeUpdate_* path with an
  eu.exe/eu.cfg naming pattern that does not match Microsoft's legitimate
  Edge Update service install location, followed by scheduled task creation
  and/or the appearance of "How to Restore My Files.html" ransom notes
  across multiple directories, consistent with HYFLOCK RaaS deployment.
references:
  - https://blog.checkpoint.com/security/hyflock-ransomware-evolves-with-new-builds-and-encryption-weaknesses/
  - https://www.watchguard.com/wgrd-security-hub/ransomware-tracker/hyflock
  - https://cybersecuritynews.com/hyflock-ransomware/
  - https://gbhackers.com/hyflock-ransomware/
author: Aryan
date: 2026-11-26T00:00:00.000Z
tags:
  - attack.defense_evasion
  - attack.t1036.005
  - attack.persistence
  - attack.t1053.005
  - attack.impact
  - attack.t1486
logsource:
  category: process_creation
  product: windows
detection:
  selection_fake_updater_path:
    Image|contains: '\ProgramData\EdgeUpdate_'
    Image|endswith: '\eu.exe'
  selection_scheduled_task:
    EventID: 4698
  selection_ransom_note_write:
    TargetFilename|endswith: '\How to Restore My Files.html'
  condition: selection_fake_updater_path or (selection_scheduled_task and selection_ransom_note_write)
  timeframe: 1h
  # Escalate to critical if selection_fake_updater_path fires on 3+ distinct
  # hosts, or if selection_ransom_note_write fires across 5+ distinct
  # directories within the timeframe - both indicate active mass deployment
falsepositives:
  - Legitimate Microsoft Edge Update (MicrosoftEdgeUpdate.exe) runs from
    "Program Files (x86)\Microsoft\EdgeUpdate\", not ProgramData\EdgeUpdate_*
    with a random suffix - a genuine match on this pattern is unlikely but
    should still be confirmed against the real install path before escalating
  - Third-party backup or sync tools that drop per-directory HTML instruction
    files (rare, but worth excluding by known hash/publisher)
level: high
```

## Prevention

- Baseline and alert on any process executing from a `ProgramData\EdgeUpdate_*` path - Microsoft's real Edge Update service installs under `Program Files (x86)\Microsoft\EdgeUpdate\`, not a randomized ProgramData subdirectory.
- Enable Scheduled Task creation auditing (Event ID 4698) and correlate new task registration with recent file-write bursts rather than treating either signal alone as actionable.
- Maintain offline, immutable backups and test restoration regularly - at least one HYFLOCK build variant has a processing defect that can permanently destroy file content rather than merely encrypt it, meaning payment wouldn't recover those files even with a working key.
- Before writing off encrypted files as unrecoverable, check whether they exceed 4KB and retain ZIP-container-based formats (Office documents, etc.) - the October 17 build's partial-encryption flaw leaves most of the file content intact in some cases.
- Restrict and monitor SMB/network-share access from endpoints that have no legitimate business reason to enumerate shares, since the October build expanded network-share interaction as part of its deployment.

*See also: [HYFLOCK - Emerging RaaS with a Self-Destructing Encryption Flaw](/actors/hyflock/) for the actor's broader behavioral pattern.*

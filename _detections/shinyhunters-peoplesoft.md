---
title: "ShinyHunters - Oracle PeopleSoft Zero-Day Exploitation (Threat Brief)"
layout: default
---

## Overview

Beginning around 2026-05-27, the extortion group tracked as **ShinyHunters** (with the underlying exploitation activity attributed by Mandiant to **UNC6240**) began exploiting **CVE-2026-35273**, a critical (CVSS 9.8) remote-code-execution flaw in Oracle PeopleSoft Enterprise PeopleTools. The vulnerability required no authentication and no user interaction - network access to the exposed HTTP service was enough to take over the server. Oracle did not publish an advisory until 2026-06-10, meaning the flaw was actively exploited as a zero-day for roughly two weeks before a patch or public guidance existed.

By the time the campaign was disclosed, ShinyHunters had exploited more than 300 PeopleSoft instances across 100+ organizations worldwide, using automated scripts capable of scanning and compromising exposed environments at scale. The education sector was hit hardest - the only publicly confirmed victim as of 2026-06-11 was a university where more than 40 GB of data covering roughly 500,000 current and former students (across UK, Malaysia, and China campuses) was published.

## Why this matters for detection

PeopleSoft and similar large ERP platforms have historically been treated as "too complex and obscure" to be a priority attack surface - patched on a slower cadence than internet-facing web apps, and often not covered by the same EDR/telemetry standards applied to standard endpoints. This campaign is a direct counterexample: a single unauthenticated RCE in an ERP platform was enough to enable automated, at-scale compromise across a huge number of organizations before a patch existed. Detection needs to treat ERP/back-office application servers with the same exposure-monitoring rigor as any other internet-facing service, and hunt for exploitation *patterns* (unexpected process spawns from an application server, anomalous outbound data transfer) rather than waiting on a CVE-specific signature that won't exist until after public disclosure.

## Detection Guidance

```yaml
title: Anomalous Process Execution or Data Egress from ERP Application Server
status: experimental
description: >-
  Detects unexpected child process creation or large outbound data transfer
  originating from a PeopleSoft/ERP application server process, consistent
  with post-exploitation activity following an unauthenticated RCE such as
  CVE-2026-35273, independent of a CVE-specific signature.
references:
  - https://thehackernews.com/2026/06/shinyhunters-exploits-oracle-peoplesoft.html
  - https://www.csoonline.com/article/4184408/oracle-peoplesoft-zero-day-fuels-shinyhunters-extortion-spree.html
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35273
author: Aryan
date: 2026-08-23T00:00:00.000Z
tags:
  - attack.initial_access
  - attack.t1190
  - attack.exfiltration
  - attack.t1567
logsource:
  category: process_creation
  product: windows
detection:
  selection_erp_parent:
    ParentImage|contains:
      - 'psoft'
      - 'peoplesoft'
      - 'tuxedo'
  selection_unexpected_child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\bash'
      - '\sh'
      - '\wget'
      - '\curl'
  condition: selection_erp_parent and selection_unexpected_child
falsepositives:
  - Scheduled PeopleSoft batch/nVision reporting jobs that legitimately spawn shell processes
  - Administrative maintenance scripts run by the platform team - verify against change records
level: high
```

## Prevention

- Treat ERP and other "back office" platforms as first-class internet-facing attack surface: same patch SLAs, same exposure scanning, same EDR coverage as any public web app.
- Where a zero-day precedes vendor disclosure, virtual-patch at the network layer (WAF rules, restricting access to known admin IP ranges) rather than waiting on an official fix.
- Monitor for anomalous outbound data volume from application servers - large, unscheduled egress from a system that doesn't normally originate bulk transfers is a durable signal independent of the specific exploit used to get there.

*See also: [UNC6240 / ShinyHunters - Zero-Day-Enabled Mass Extortion](/actors/unc6240-shinyhunters/) for the actor's broader behavioral pattern.*

---
title: "CVE-2026-102764 - ARMORY CASTLE Exploits BeyondTrust Remote Support Zero-Day (Threat Brief)"
layout: default
---

## Overview

On 2026-10-15, BeyondTrust and Google's Threat Intelligence Group (GTIG) jointly disclosed **CVE-2026-102764**, a critical (CVSS 9.3) unauthenticated arbitrary-file-upload vulnerability in **BeyondTrust Remote Support** (formerly Bomgar), affecting all supported versions up to 26.2.3. GTIG attributes exploitation to **ARMORY CASTLE**, a PRC-nexus espionage actor it previously tracked as UNC5221 (CrowdStrike: WARP PANDA), with a history of burning zero-days in edge appliances, most notably Ivanti products. Exploitation began as a zero-day in late August 2026 - roughly seven weeks before public disclosure. BeyondTrust patched its SaaS tenants on October 9 and released BT26-05 for self-hosted customers.

The intrusion chain observed by Mandiant is unusually well-documented. Initial exploitation hit an undisclosed PHP endpoint (`/app_84304470%2Ephp`); about 11 minutes later the **SAWFLY** webshell (`mangoapi.php`) appeared, running as the appliance's unprivileged service account. The actor then escalated to root by copying `/bin/sh` to a disguised path (`/usr/bin/dbus-authd`), setting it root-owned with the SUID bit, and used sudo access to dump the appliance's credential vault via its own `bt-secrets` CLI. Persistence was written directly into the appliance's configuration templates - `/ns/config/sudoers.template` for passwordless sudo and `/ns/config/haproxy.conf` to route a disguised URI (`/uidchanarge`) to a hidden **BARECLAW** SOCKS5-over-WebSocket tunneler - so it survives a reboot or config reset. Throughout the intrusion the actor repeatedly deleted authentication, access, and error logs, then used a compromised Administrator account to escalate a Jump Item/Team role to Administrator and exfiltrate documents via the built-in file-transfer feature.

## Why this matters for detection

This campaign is a case study in why "patch and move on" is insufficient for internet-facing privileged-access appliances: the actor's persistence lives in the appliance's own *configuration templates*, not in a location a standard OS-level persistence sweep would check, and it specifically survives the kind of config reset an administrator might use expecting to clean the box. The SUID-backdoor technique - copying a legitimate shell to a disguised path and setting the SUID bit - is also not BeyondTrust-specific; it's a generic, high-fidelity Linux privilege-escalation pattern worth hunting for on any appliance or server, regardless of which initial-access vector got the attacker a foothold. Because the actor deleted logs continuously rather than once at the end, on-box log review alone is unreliable here - external log forwarding (syslog, WAF, firewall) captured before an appliance is touched is the only trustworthy record.

## Detection Guidance

```yaml
title: SUID Root Shell Creation via Disguised Shell Binary Copy on Linux Appliance
status: experimental
description: >-
  Detects copying a shell interpreter (/bin/sh, /bin/bash) to a
  non-standard path followed by setting the SUID bit and root
  ownership, consistent with the privilege-escalation technique
  ARMORY CASTLE used against BeyondTrust Remote Support
  (CVE-2026-102764), where /bin/sh was copied to /usr/bin/dbus-authd
  and given root:root SUID to create a persistent root backdoor.
references:
  - https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-beyondtrust
  - https://www.bleepingcomputer.com/news/security/beyondtrust-patches-zero-day-exploited-in-attacks-since-august/
  - https://www.scworld.com/news/beyondtrust-zero-day-exploited-by-china-linked-group-armory-castle
author: Aryan
date: 2026-10-22
tags:
  - attack.privilege_escalation
  - attack.t1548.001
  - attack.persistence
  - attack.t1543
  - attack.defense_evasion
  - attack.t1070.002
  - attack.initial_access
  - attack.t1190
logsource:
  category: process_creation
  product: linux
detection:
  selection_shell_copy:
    Image|endswith:
      - '/cp'
      - '/install'
    CommandLine|contains:
      - '/bin/sh'
      - '/bin/bash'
  selection_suid_set:
    Image|endswith:
      - '/chmod'
    CommandLine|re: '(u\+s|[0-7]?[4][0-7][0-7][0-7])'
  selection_owner_root:
    Image|endswith:
      - '/chown'
    CommandLine|contains: 'root'
  condition: selection_shell_copy and 1 of (selection_suid_set or selection_owner_root)
  timeframe: 10m
falsepositives:
  - Legitimate package installation or OS hardening scripts that intentionally stage a SUID-root helper binary
  - Container image build steps that copy and chmod a shell as part of a minimal-base-image workflow (should not appear on a running production appliance)
level: critical
```

## Prevention

- Apply BT26-05 immediately; self-hosted instances below 24.3.1 must be upgraded first, since upgrading alone does not remediate exposure that occurred before patching.
- Treat any internet-reachable Remote Support instance that ran a vulnerable version during the exposure window as potentially compromised - snapshot and preserve evidence before rebooting, then rebuild from a clean, patched image rather than cleaning in place.
- Rotate every credential class the appliance stores or brokers only *after* rebuilding: `/appliance` admin, `/login` admins, API secrets, SAML signing keys, and vault/PRA credentials at the target system.
- Restrict `/login` and `/appliance` management interfaces to an explicit IP allow-list, and front the appliance with a WAF or reverse proxy that logs full request URIs - the initial exploitation path in this campaign was an unlisted `.php` endpoint that would stand out against a known-path baseline.
- Extend file-integrity monitoring and EDR-equivalent coverage to appliance-layer Linux hosts (PAM, remote-support, VPN) - this class of asset is routinely excluded from the telemetry applied to standard servers and endpoints, which is exactly where this campaign lived.

*See also: [ARMORY CASTLE / UNC5221 - PRC-Nexus Espionage Actor Behind the BeyondTrust Remote Support Zero-Day](/actors/armory-castle/) for the actor's broader behavioral pattern.*

---
title: "Ted Backdoor - DPRK-Linked HAProxy Trojanization Toolkit (Threat Brief)"
layout: default
---

## Overview

On 2026-09-04, Rapid7 Labs disclosed a previously undocumented Linux espionage toolkit found compiled directly into the trojanized HAProxy load-balancer builds of two South Korean organizations - one in the automotive sector, one in media. The centerpiece, which Rapid7 named **ted**, isn't a separate process dropped alongside HAProxy - it's built into HAProxy 2.8.12 itself, using the software's own filter API, internal memory pools, event scheduler, and process-management infrastructure to hook the HTTP parser and intercept traffic at the exact point where TLS is terminated and decrypted. Because HAProxy is typically an organization's SSL/TLS termination point, this gave the backdoor a plaintext view of every login request, session cookie, and header passing through it, with the ability to serve altered pages to a specific range of visitor IPs and hide the tampering from everyone else.

Alongside ted, the toolkit included trojanized versions of `crond`, `agetty`, `atd`, `sshd`, and `polkitd`, plus a companion implant called **curlRAT** for file upload/download, command execution, and beaconing. Command-and-control rode over covert HTTP requests to custom-looking static-asset paths (e.g. image-style URIs) that never actually reached a backend server and were scrubbed from HAProxy's own connection counters and logs, so neither the application nor the load balancer's own statistics recorded them. Initial access began with exploitation of a vulnerability in an edge-facing Groupware login portal, followed by a trojanized SSH keylogger (hooking PAM) used to harvest credentials and move laterally. The toolkit ran undetected for an estimated 9-10 months, with the earliest affected HAProxy build dating to late 2024. Rapid7 attributes the campaign with **medium confidence** to North Korean state-sponsored activity, naming both APT37 and **Lazarus Group** as candidate operators rather than a single confirmed cluster.

## Why this matters for detection

This toolkit specifically targets the piece of infrastructure organizations are least likely to be watching closely: the load balancer itself, which is usually treated as plumbing rather than an endpoint requiring EDR-grade telemetry or file-integrity monitoring. Because ted is compiled into the legitimate HAProxy binary rather than running as a separate malicious process, process-based detection (looking for an unrecognized executable) is a dead end - the artifact *is* haproxy, just a version of it that doesn't match any signed, vendor-published build. That reframes detection around two angles the toolkit can't fully hide from: binary integrity (a haproxy binary whose hash doesn't match the vendor-published release or the organization's own build pipeline) and network behavior (a load balancer process, which should only ever proxy connections between clients and its configured backend pool, instead making outbound calls to destinations outside that pool). The 9-10 month dwell time in the disclosed cases is itself evidence that neither check was in place at either victim.

## Detection Guidance

```yaml
title: HAProxy Process Network Connection Outside Configured Backend Pool
status: experimental
description: >-
  Detects the haproxy process establishing outbound network connections to
  destinations that fall outside its configured backend/upstream pool,
  consistent with a compiled-in C2 channel piggybacking on the load
  balancer's own process (as documented in Rapid7's DPRK-attributed "ted"
  backdoor and curlRAT campaign against trojanized HAProxy builds).
references:
  - https://www.rapid7.com/blog/post/tr-dprk-apts-ted-backdoor-curlrat-target-south-korean-media-automotive-sectors/
  - https://thehackernews.com/2026/09/new-ted-backdoor-hides-inside-victims.html
  - https://securityaffairs.com/198656/apt/north-korea-linked-hackers-hide-a-backdoor-inside-haproxy.html
author: Aryan
date: 2026-09-17
tags:
  - attack.persistence
  - attack.t1554
  - attack.command_and_control
  - attack.t1071.001
  - attack.credential_access
  - attack.t1556.003
  - attack.defense_evasion
  - attack.t1027
logsource:
  category: network_connection
  product: linux
detection:
  selection_process:
    Image|endswith: '/haproxy'
  filter_known_backend_pool:
    DestinationIp|cidr: 'configured_backend_subnets_placeholder'
  filter_management_plane:
    DestinationPort:
      - 8404   # stats/admin socket, adjust to local config
  condition: selection_process and not filter_known_backend_pool and not filter_management_plane
  timeframe: 24h
  # Correlate with binary integrity: alert immediately, regardless of the
  # network signal above, if the running haproxy binary's hash does not
  # match the vendor-published release or the organization's last known-good
  # build artifact
falsepositives:
  - Health-check or monitoring probes explicitly configured in haproxy.cfg to reach third-party uptime services
  - DNS-based backend resolution briefly routing through addresses not yet on an allow-list
  - Legitimate HAProxy plugins or Data Plane API integrations that call external endpoints by design
level: high
```

## Prevention

- Treat HAProxy (and other edge/load-balancer software) as a first-class target for file-integrity monitoring and binary hash verification against vendor-published checksums, not just as network plumbing exempt from endpoint controls - this is the single check that would have caught ted directly, since the backdoor is compiled into the binary itself.
- Patch and monitor Groupware and other edge-facing login portals aggressively; this campaign's initial access came through exploitation of exactly that kind of internet-facing application server.
- Audit PAM module chains on Linux authentication servers for unauthorized modules or modifications - the SSH keylogger in this toolkit worked by hooking PAM, which is a detectable but rarely-monitored persistence surface.
- Baseline expected outbound destinations for load-balancer and reverse-proxy hosts, and alert on any deviation - a correctly functioning load balancer has no legitimate reason to originate connections outside its configured backend pool and management plane.
- Where available, enable independent (out-of-band) logging of connections seen at the network layer (e.g., a TAP or NetFlow collector upstream of the load balancer) rather than relying solely on the load balancer's own logs and counters, since this toolkit specifically scrubbed its C2 traffic from HAProxy's self-reported statistics.

*See also: [Lazarus Group / Operation Dream Job - DPRK Zero-Day Recruitment-Lure Intrusions](/actors/lazarus-group/) - Rapid7 attributes this campaign with medium confidence to North Korean state-sponsored activity, naming Lazarus Group and APT37 as candidate operators.*

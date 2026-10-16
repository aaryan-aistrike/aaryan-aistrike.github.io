---
title: "UTA0576 - Chained Ivanti Connect Secure Zero-Days to Unauthenticated Root RCE (Threat Brief)"
layout: default
---

## Overview

On 2026-10-13, Volexity disclosed that a threat actor it tracks as **UTA0576** chained three zero-day flaws in Ivanti Connect Secure VPN appliances - active in the wild since around 2026-10-03 - to achieve unauthenticated, root-level code execution against a fully patched (22.8R2.4) appliance. The entry point, **CVE-2026-104935** (CVSS 8.6, CWE-290 authentication bypass by spoofing), abuses the public `welcome.cgi` endpoint: the appliance's auth check evaluates the requested URL, but the request is actually routed to whatever script is named in an attacker-supplied `X-DSCGI-PATH` header, letting an unauthenticated request reach protected code. The actor then won a race condition in the appliance's upload handler - firing parallel requests to upload a malicious Perl payload and invoke it via the same header trick before the appliance's validation routine deleted the file - to get initial code execution. A third, separate zero-day in the privileged `dsinvoked` service and its DSCache configuration store escalated that access to full root; unlike the first two steps, this privilege-escalation flaw remained unpatched at disclosure time.

UTA0576 dropped no backdoor or web shell, instead issuing commands and retrieving output through the HTTPS exploit-chain requests themselves, and evaded Ivanti's Integrity Checker Tool by patching code in memory and restoring it afterward. After reaching root, the actor used a compromised Active Directory service account and a custom Python LDAP tool to search for LAPS passwords, BitLocker recovery keys, and other password-bearing AD attributes, and exfiltrated domain credentials, limited AD metadata, and raw packet captures. Volexity assesses with low confidence that the actor is financially motivated rather than state-sponsored. CISA added CVE-2026-104935 to its Known Exploited Vulnerabilities catalog on 2026-10-13 with a 2026-10-16 remediation deadline for federal agencies. Fixes for the auth-bypass/RCE chain shipped in versions 25.1.1.2, 25.1.3.0, 25.1.3.1, and 22.8R2.5; the privilege-escalation flaw has no fix yet.

## Why this matters for detection

This chain is detectable almost entirely from the appliance's own web logs, which matters because it leaves none of the usual artifacts - no new local account, no dropped binary, no persistent backdoor - and can produce a clean result from Ivanti's own integrity-checking tool. The one constant across every stage of the chain is the mismatch between the URL an unauthenticated request targets and the internal script path named in the `X-DSCGI-PATH` header; that header should never diverge from the requested path in legitimate traffic, making it a chain-agnostic signal that holds even as the specific exploited endpoints change across patch cycles.

## Detection Guidance

```yaml
title: Ivanti Connect Secure Request With Mismatched X-DSCGI-PATH Header
status: experimental
description: >-
  Detects HTTP requests to an Ivanti Connect Secure appliance where the
  X-DSCGI-PATH header names a script path that differs from the requested
  URL, consistent with the authentication-bypass-to-root exploit chain
  (CVE-2026-104935) used by UTA0576 since approximately 2026-10-03.
references:
  - https://www.volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/
  - https://thehackernews.com/2026/10/attacker-chains-three-ivanti-connect.html
  - https://www.bleepingcomputer.com/news/security/cisa-warns-admins-to-immediately-fix-ivanti-flaw-exploited-as-zero-day/
author: Aryan
date: 2026-10-16T00:00:00.000Z
tags:
  - attack.initial_access
  - attack.t1190
  - attack.privilege_escalation
  - attack.t1068
  - attack.defense_evasion
  - attack.t1562
  - attack.credential_access
  - attack.t1555
logsource:
  category: webserver
  product: ivanti_connect_secure
  definition: 'Requires access to Ivanti Connect Secure HTTP request logs capturing request headers (X-DSCGI-PATH) and target URL path'
detection:
  selection_header_present:
    http_header_X-DSCGI-PATH|exists: true
  selection_path_mismatch:
    http_header_X-DSCGI-PATH|contains:
      - '/dana/fb/smb/wu.cgi'
      - '/home/webserver/htdocs/dana/'
  filter_expected_endpoint:
    url_path:
      - '/dana/fb/smb/wu.cgi'
  condition: selection_header_present and selection_path_mismatch and not filter_expected_endpoint
  timeframe: 5m
  # Escalate to critical if followed by a write under /home/runtime/tmp/ or
  # by an unexpected child process spawned from the web server's service
  # account, or by LDAP queries for ms-Mcs-AdmPwd (LAPS) or BitLocker
  # recovery attributes from the appliance's service account
falsepositives:
  - Legitimate internal monitoring or vulnerability scanning tooling that replays raw requests with unusual headers (should be allow-listed by source IP)
  - None expected from normal end-user or administrator VPN client traffic - this header is not used in standard login/session flows
level: critical
```

## Prevention

- Patch Ivanti Connect Secure immediately to 25.1.1.2, 25.1.3.0, 25.1.3.1, or 22.8R2.5 (or later) to close the authentication-bypass and race-condition RCE steps; treat the privilege-escalation flaw as unresolved and apply Ivanti's mitigations/monitoring guidance until a fix ships.
- Do not rely on a clean Integrity Checker Tool scan alone as proof of a clean appliance - this chain is specifically able to evade it by restoring in-memory changes.
- Rotate credentials for any Active Directory service account configured for Connect Secure LDAP integration, and audit it for anomalous LDAP queries targeting LAPS or BitLocker attributes.
- Restrict and monitor administrative/API access to internet-facing VPN appliances, and treat any Connect Secure appliance with suspected compromise as a full AD-credential-exposure incident, not just an appliance-level one, given this actor's confirmed pivot toward LAPS and BitLocker data.

*See also: [UTA0576 - Financially Motivated Actor Behind the Ivanti Connect Secure Zero-Day Chain](/actors/uta0576/) for the actor's broader behavioral pattern.*

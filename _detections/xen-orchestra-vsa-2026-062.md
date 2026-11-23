---
title: "VSA-2026-062 - Xen Orchestra Authentication Bypass via Empty-Object Token Cookie, Actively Exploited (Threat Brief)"
layout: default
---

## Overview

On 2026-11-10, virtualization vendor Vates disclosed **VSA-2026-062**, a critical authentication-bypass vulnerability in Xen Orchestra and the Xen Orchestra Appliance (XOA), the web-based management console used to administer XCP-ng hypervisor pools. The root cause is a parsing flaw in how the server reads the `authenticationToken` session cookie: a crafted cookie value such as `j:{}` (URL-encoded as `j:%7B%7D`) is deserialized into an empty object rather than rejected as malformed. The REST authentication layer passes that empty object straight to the token lookup function without first checking that it is a string, and the lookup - built as an unfiltered match - returns the *first* token in its collection, silently authenticating the request as that token's owner as long as the token hasn't expired.

Vates confirmed the flaw "is actively exploited by a threat actor" at time of disclosure. Once authenticated via the bypass, attackers were observed calling the `/rest/v0/users/me/authentication_tokens` endpoint to harvest additional, reusable login token IDs - giving them durable access independent of the original bypass - and in some cases chaining into a second, related flaw in the VM import workflow (tracked separately as VSA-2026-063, for which a fix was still in development at disclosure time) to achieve full administrative control over managed XCP-ng hosts. No CVE had been formally assigned to VSA-2026-062 as of this writing, though third-party trackers have proposed CVE-2026-133469. Fixed builds are available in the 6.9.x and 6.10.x release lines; organizations should confirm the exact patched version against Vates' own advisory rather than relying on third-party summaries, which disagree on the precise point release.

## Why this matters for detection

This is not a credential-theft or brute-force bypass - it's a type-confusion bug that turns a malformed cookie into a universal admin key, which means there is no failed-login trail, no password-spray signature, and no anomalous source-IP velocity to key off of. The only reliable detection surface is the cookie value itself: a legitimate `authenticationToken` cookie is an opaque token string, never a serialized empty object. Because Xen Orchestra sits at the control-plane layer for an entire virtualization fleet, a successful bypass doesn't just expose one account - it can hand an attacker the keys to every VM, snapshot, and storage repository the XO instance manages, making this a fleet-takeover primitive rather than a single-host compromise.

## Detection Guidance

```yaml
title: Xen Orchestra Empty-Object Authentication Token Cookie
status: experimental
description: >-
  Detects an HTTP request to a Xen Orchestra / Xen Orchestra Appliance
  management interface carrying an authenticationToken cookie whose value
  is a serialized empty object rather than an opaque token string,
  consistent with exploitation of the VSA-2026-062 authentication bypass.
references:
  - https://www.criminalip.io/knowledge-hub/blog/39197
  - https://www.runzero.com/blog/vates-xen-orchestra/
  - https://blog.ostorlab.co/xen-orchestra-auth-bypass-vsa-2026-062.html
author: Aryan
date: 2026-11-23T00:00:00.000Z
tags:
  - attack.initial_access
  - attack.t1190
  - attack.credential_access
  - attack.t1606
  - attack.persistence
  - attack.t1098
logsource:
  category: webserver
  definition: 'Requires reverse-proxy or Xen Orchestra server access logging that captures the full Cookie header on requests to /rest/* and /api/*'
detection:
  selection_malformed_token_cookie:
    Cookie|contains:
      - 'authenticationToken=j:%7B%7D'
      - 'authenticationToken=j:{}'
  selection_token_harvest:
    cs-uri-stem|contains: '/rest/v0/users/me/authentication_tokens'
  condition: selection_malformed_token_cookie or (selection_malformed_token_cookie and selection_token_harvest)
  timeframe: 5m
  # Treat any single hit on selection_malformed_token_cookie as high-confidence
  # on its own - a well-formed client never sends this cookie value - and
  # escalate to critical if followed by a VM import/clone API call from the
  # same session.
falsepositives:
  - None expected; a benign client cannot produce this cookie value through normal use of the application
level: critical
```

## Prevention

- Patch Xen Orchestra and XOA to the fixed release in the 6.9.x or 6.10.x line immediately, verifying the exact build number against Vates' own advisory rather than a third-party mirror.
- Never expose the Xen Orchestra / XCP-ng management interface directly to the internet; restrict it to a management VLAN or VPN-only access path.
- At a reverse proxy or WAF in front of Xen Orchestra, block or strip any `authenticationToken` cookie value matching a serialized-object pattern (`j:{...}`) as a stopgap ahead of patching.
- If exploitation is suspected, rotate all Xen Orchestra authentication tokens and local-user credentials, and audit recent VM import, clone, and snapshot activity for unauthorized changes across every pool the instance manages.

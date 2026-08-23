---
title: "ERMAC V3.0 Banking Trojan – C2 Backend & Panel (High-Confidence)"
layout: default
---

## Overview

This detection focuses on identifying **ERMAC V3.0 C2/panel/builder traffic** based on the leaked source code analysis. Unlike broad signatures, the rule emphasizes **multi-indicator correlations in a single event**, reducing false positives and providing **high-confidence coverage** for SOCs and IR teams.

ERMAC's backend follows a fairly predictable structure:

- `/api/v1/…` routes for bot management, logs, and account operations
- Auth artifacts (`ermac_session`, hardcoded JWTs, Bearer tokens)
- Exfil endpoints like `gate.php`, `/upload`, `/exfil`
- Injects directory references and Android callback beacons
- Unique UI titles for *panel*, *builder*, and *registration* pages
- Default operator creds (root / changemeplease) baked into the login flow

This rule integrates those elements into a single layered detection approach.

## Why this matters for detection

ERMAC's backend follows a predictable, fingerprintable API and URL structure derived directly from the leaked source, so multi-indicator correlation (title strings + auth artifacts + exfil paths) gives genuinely high-confidence coverage without leaning on a single brittle IOC like a destination IP, which can be rotated or sinkholed at any time.

---

## Detection Rule

```yaml
title: ERMAC V3.0 Banking Trojan – C2 Backend & Panel (High-Confidence)
status: stable
description: >-
  Detects ERMAC V3.0 C2/panel/builder traffic using backend API routes, auth
  artifacts, exfil paths, injects directory indicators, and unique strings from
  the source leak. Emphasizes multi-indicator matches in the same event for high
  confidence.
references:
  - https://hunt.io/blog/ermac-v3-banking-trojan-source-code-leak
author: Aryan
date: 2025-08-15T00:00:00.000Z
tags:
  - attack.command_and_control
  - attack.t1071
  - malware.ermac
  - os.android
logsource:
  category: proxy
  product: zeek
detection:
  selection_panel_title:
    http.title|re: (?i)ermac\\s*3(\\.0)?\\s*panel
  selection_builder_title:
    http.title|re: (?i)ermac\\s*3(\\.0)?\\s*builder
  selection_cookie:
    http.header|contains: ermac_session
  selection_authz_header:
    http.header|re: (?i)Authorization:\\s*(Bearer|JWT)\\s+[A-Za-z0-9-_\\.]+
  selection_hardcoded_jwt:
    http.header|contains: h3299xK7gdARLk85rsMyawT7K4yGbxYbkKoJo8gO3lMdl9XwJCKh2tMkdCmeeSeK
  selection_api_v1:
    uri_path|re: >-
      (?i)/api/v1/(sign-?in|smartInjections(/session(/list|/\\{?session(Id)?\\}?))?|injects(/(getInjectionsList|createInjection|deleteInjection|\\{?injection\\}?/editInjection))?|sendBotsCommand|deleteBot|deleteAllRemovedApp|\\{?bot\\}?/(setBotType|commands/getCommandsList|settings/updateBotSettings|injects/updateBotInjections)|deleteLog|editLogComment|accounts(/(getAccountsList|createAccount|\\{?user\\}?/(editAccount|deleteAccount)))?|permissions(/(getPermissionsList|updatePermission))?|counts/(getCounts|getStats)|autoCommands(/(getAutoCommandsList|updateAutoCommand))?|search)$
  selection_injects_dir:
    uri_path|re: (?i)/(public/)?injects(/|$)
  selection_android_callback:
    http.body|contains: Android.send_log_injects
  selection_registration:
    uri_path|re: (?i)/(panel/register|api/auth/register|register\\.php)
  selection_exfil_paths:
    uri_path|re: (?i)/(gate\\.php|exfil|upload)(/|$)
  selection_ioc_ip:
    destination.ip:
      - 20.162.226.228
      - 43.160.253.145
      - 91.92.46.12
      - 98.71.173.119
      - 121.127.231.161
      - 121.127.231.163
      - 121.127.231.198
      - 141.164.62.236
      - 172.191.69.182
      - 206.123.128.81
      - 5.188.33.192
  selection_default_creds_post:
    http.method: POST
    uri_path|re: (?i)/api/v1/sign-?in$
    http.body|contains|all:
      - root
      - changemeplease
  # --- High-confidence multi-indicator logic ---
  condition: >
    selection_hardcoded_jwt
    or ( selection_api_v1 and ( selection_cookie or selection_authz_header ) )
    or ( ( selection_injects_dir or selection_android_callback ) and ( selection_api_v1 or selection_exfil_paths ) )
    or ( ( selection_panel_title or selection_builder_title or selection_registration ) and ( selection_cookie or selection_authz_header ) )
    or ( selection_exfil_paths and ( selection_cookie or selection_authz_header or selection_api_v1 ) )
    or ( selection_ioc_ip and ( selection_cookie or selection_authz_header or selection_api_v1 or selection_panel_title or selection_builder_title or selection_injects_dir or selection_exfil_paths ) )
    or selection_default_creds_post
falsepositives:
  - Legitimate dev/test systems that coincidentally reuse similar API route names (low likelihood).
  - Generic Authorization headers are common; rule require pairing with ERMAC-specific routes/titles/paths to fire.
  - IPs may be reassigned or sinkholed; treat IP hits as supportive, not primary.
level: high
```

## Prevention

- Block outbound connections to known ERMAC C2 IOCs (the destination IP list above) at the perimeter, keeping in mind these are likely to rotate over time.
- Monitor mobile device management (MDM) telemetry for sideloaded APKs requesting excessive accessibility/SMS permissions - a common ERMAC delivery vector.
- Educate users against installing APKs from outside official app stores.
- Treat any hit on the hardcoded JWT indicator as high-priority - it's unique to this leaked build and carries essentially zero false-positive risk.


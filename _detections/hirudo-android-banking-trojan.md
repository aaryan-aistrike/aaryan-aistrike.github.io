---
title: "Hirudo - Android Banking Trojan That Replaces Apps Instead of Overlaying Them (Threat Brief)"
layout: default
---

## Overview

**Hirudo** is a newly documented Android banking trojan and RAT, first detailed by ThreatFabric on 2026-10-14. It breaks from the standard overlay-phishing playbook used by most Android banking malware: instead of drawing a fake login screen on top of the real banking app, Hirudo's hooking engine physically **replaces the legitimate app with a trojanized copy**, then returns the genuine app's signing certificate to any code that checks it - defeating signature-verification checks that would normally flag a tampered APK.

The hooking engine also hides enabled Accessibility services from on-device inspection, strips the `FLAG_SECURE` flag to defeat screen-capture restrictions (enabling screen recording of sensitive banking UI), and relays Google Play Integrity API requests to an operator-controlled server to forge passing device/app integrity attestations. Delivery is via dropper apps disguised as shopping, adult-video, or short-drama apps (observed names include Shopora, 1V1 X, KoiShort, and ZoyaTV), distributed through social media promotion and a fake in-app "update" prompt that sideloads the payload post-install. One dropper variant deliberately creates a broken VPN connection during install, theorized as an attempt to manipulate device reputation/risk scoring. Confirmed app-replacement activity has hit 8 banking apps across 7 Indonesian banks, with broader credential-theft targeting also observed in China, India, Mexico, Morocco, and Thailand. No named threat actor or nation-state has been attributed; ThreatFabric assesses it as a financially motivated operation, likely run as a managed malware-as-a-service backend.

## Why this matters for detection

Hirudo's app-replacement approach defeats the detection logic most mobile security tooling relies on - "does the installed banking app's signature match the expected one?" - by serving a forged answer at query time rather than tampering with the APK's actual signature block. That makes attestation-layer monitoring (server-side Play Integrity verdicts cross-checked against expected device telemetry, not just client-reported results) more important than on-device signature checks alone. The notable defensive gift here is that Hirudo's hooking engine ships with a publicly leaked attestation keybox, which can itself be fingerprinted as an IOC. Organizations relying solely on client-side integrity checks for mobile banking risk decisions should treat this family as proof that client-reported attestation can be relayed and forged.

## Detection Guidance

```yaml
title: Hirudo Android Trojan - Suspicious Sideload Following Fake In-App Update Prompt
status: experimental
description: >-
  Detects the Hirudo dropper pattern - installation of a new APK from a
  non-Play-Store source shortly after a shopping/video/short-drama app
  requests an "update," combined with newly granted Accessibility service
  permissions, consistent with Hirudo's app-replacement banking trojan
  delivery chain.
references:
  - https://thehackernews.com/2026/10/hirudo-android-trojan-uses-patched.html
  - https://www.bleepingcomputer.com/news/security/hirudo-android-malware-replaces-banking-apps-to-evade-security-checks
  - https://securityaffairs.com/?p=200970
author: Aryan
date: 2026-10-17T00:00:00.000Z
tags:
  - attack.initial_access
  - attack.t1476
  - attack.defense_evasion
  - attack.t1222
  - attack.collection
  - attack.t1417
  - attack.credential_access
  - attack.t1414
logsource:
  category: application
  product: android
detection:
  selection_sideload:
    EventType: 'package_install'
    InstallSource|not_contains: 'com.android.vending'
  selection_accessibility_grant:
    EventType: 'permission_grant'
    Permission: 'android.permission.BIND_ACCESSIBILITY_SERVICE'
  selection_lure_category:
    SourceAppCategory:
      - 'shopping'
      - 'video'
      - 'entertainment'
  condition: selection_sideload and selection_accessibility_grant and selection_lure_category
  timeframe: 1h
  # Escalate if the newly-sideloaded package subsequently overlays or
  # shares a package-name prefix with an installed banking app
falsepositives:
  - Legitimate enterprise MDM-pushed sideloaded applications
  - Accessibility services granted for genuine accessibility use (screen readers, switch access)
  - Third-party app stores used deliberately by technically sophisticated users
level: high
```

## Prevention

- Block installation from unknown sources at the MDM/EMM policy level on any device enrolled for corporate banking or financial access.
- Treat client-side Play Integrity API results as advisory only for high-value transactions; cross-check server-side against expected device/session telemetry rather than trusting a device-reported "pass" verdict alone.
- Educate users that legitimate banking apps never require a separate "update" prompt triggered from an unrelated shopping or video app - that pattern alone is a strong phishing/dropper signal.
- Monitor for Accessibility service grants on banking-app-adjacent packages (shopping, video, entertainment categories) as a high-signal indicator, since Hirudo depends on Accessibility access to operate its RAT capabilities.

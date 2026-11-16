---
title: "Poisoned Source - APT29 Hijacks Plerdy Analytics Script to Deliver N-Day Mobile Exploit Chains (Threat Brief)"
layout: default
---

## Overview

**Poisoned Source** is a watering-hole campaign that Sekoia attributed on 2026-11-04 to **APT29** (Midnight Blizzard / Cozy Bear), the Russian SVR-linked actor this site tracks as **Storm-2945**, with moderate-to-high confidence. Between 2026-08-27 and 2026-09-03, the intrusion set compromised **a.plerdy[.]com**, the hosting domain for a legitimate Ukrainian web-analytics tracker (`/public/js/click/main.js`) loaded by thousands of websites worldwide. Sekoia discovered the activity in mid-October 2026 after spotting it independently on direct JavaScript injections into other legitimate sites and on lookalike domains mimicking the Plerdy script - three separate delivery vectors feeding the same exploitation backend.

The injected script fingerprints each visitor's browser and device, filters out bots, scanners, and automated/headless browsers, and then routes genuine mobile visitors toward a device-appropriate N-day exploit chain rather than serving a generic payload. iPhones running iOS 16.7 receive a chain built on CVE-2025-43529 and CVE-2024-27834 to steal browser cookies; iPhones on iOS 18.4-18.7 receive the **DarkSword** chain (CVE-2025-43529, CVE-2026-20700, CVE-2025-14174, CVE-2025-43510, CVE-2025-43520) - a suspected commercial-surveillance-vendor exploit kit first seen on VirusTotal in September 2026 and also observed in unrelated intrusions in Saudi Arabia, Turkey, and Malaysia. Android visitors on Chrome 139-145 receive a payload Sekoia calls **AndroSnitch**, which halts execution if it detects a Samsung Galaxy S25 Ultra (SM-S938B) - a likely anti-research check against a common test device. Reported compromised or targeted sites include a U.S. chemical-industry trade association, a European political party, and a Bulgarian military-themed site, consistent with espionage rather than mass-financial targeting. Critically, every exploit used is **N-day, not zero-day** - fully patched iOS and Android devices are not at risk.

## Why this matters for detection

This campaign compromises infrastructure the victim organization never touches - a third-party analytics script loaded transitively by sites the victim happens to visit - so there is no phishing email, attachment, or malicious link for a SOC to flag, and the initial delivery vector sits entirely outside the enterprise perimeter. Static indicator matching also degrades quickly: the operators rotate between direct injection, lookalike domains, and supply-chain compromise of the same tracker, and the exploit chain itself is selected dynamically per-device rather than fixed. What's durable is the **behavioral sequence**: a mobile client loading a third-party analytics/tag script and being redirected through a short, rapid chain of distinct external domains it has never otherwise contacted - a pattern that looks identical regardless of which specific script gets compromised next. Equally durable from an asset-management angle: this entire campaign only works against devices still running patched-but-outdated OS/browser builds, which makes mobile fleet patch currency a direct, measurable control against it.

## Detection Guidance

```yaml
title: Mobile Client Redirected Through Rapid Cross-Domain Chain After Third-Party Analytics Script Load
status: experimental
description: >-
  Detects an iOS/Android user agent requesting a third-party web-analytics
  or tag-manager script followed within a short window by HTTP redirects
  to multiple distinct external domains not previously seen from that
  client, consistent with watering-hole delivery of device-tailored N-day
  exploit chains via a compromised analytics script (as seen in the
  Poisoned Source / APT29 campaign abusing the Plerdy tracker).
references:
  - https://www.sekoia.com/blog/poisoned-source-apt29-watering-holes-targets-mobile-devices-with-n-day-exploits
  - https://thehackernews.com/2026/11/apt29-linked-hackers-hijack-web.html
  - https://www.helpnetsecurity.com/2026/11/04/apt29-watering-hole-mobile-devices-n-day-exploits/
author: Aryan
date: 2026-11-16T00:00:00.000Z
tags:
  - attack.initial_access
  - attack.t1189
  - attack.t1195.002
  - attack.resource_development
  - attack.t1608.004
  - attack.execution
  - attack.t1203
logsource:
  category: proxy
  product: other
detection:
  selection_mobile_client:
    c-useragent|contains:
      - 'iPhone'
      - 'iPad'
      - 'Android'
  selection_analytics_script_request:
    cs-uri-stem|contains:
      - '/public/js/click/'
      - 'plerdy'
      - 'analytics'
      - 'tag-manager'
  selection_redirect_response:
    sc-status:
      - 301
      - 302
      - 307
      - 308
  condition: selection_mobile_client and selection_analytics_script_request and selection_redirect_response
  timeframe: 2m
  # Escalate to critical if the same client IP subsequently contacts 3+
  # distinct external domains it has never been observed reaching before,
  # within the same short window
falsepositives:
  - Legitimate ad-tech, consent-management, or analytics redirect chains that bounce mobile visitors across several vendor domains as part of normal page load
  - CDN or load-balancer domain rotation for the analytics provider itself
level: high
```

## Prevention

- Enforce Subresource Integrity (SRI) hashes on third-party analytics, tag-manager, and tracking scripts wherever the platform supports it, so a compromised remote script fails closed instead of executing silently.
- Keep mobile fleets (iOS and Android) on current OS and browser builds through MDM-enforced update policies - every exploit in this chain requires an already-patched vulnerability on an unpatched device.
- Restrict or proxy outbound mobile browsing on managed devices through a web gateway capable of inspecting and blocking unexpected multi-hop redirect chains, not just known-bad domains.
- Treat third-party JavaScript dependencies loaded by your own site as part of your supply-chain attack surface, and monitor for unannounced changes to vendor-hosted script content you don't control.

*See also: [Storm-2945 / Midnight Blizzard - CaptiveCrunch Hotel Wi-Fi Hijack Operators](/actors/storm-2945/) for the actor's broader behavioral pattern.*

---
title: "Storm-3075 - AI-Brand Malvertising Payload Delivery (Threat Brief)"
layout: default
---

## Overview

Between 2026-03-10 and 2026-03-14, the threat actor Microsoft tracks as **Storm-3075** ran a malvertising campaign centered on a fake "Awesome AI Windows Plugin" - promoted through ads on free movie-streaming sites and promising improved video quality - that reached over 66,000 devices worldwide, hitting Japan, South Africa, the United States, and France hardest. Clicking the ad delivered a signed installer (observed sample `ProFluxeFlowAi-win-Setup.exe`) whose code-signing certificate (thumbprint `4f5c5b3ef45cfff7721754487a86aeff9a2e6e32`) was obtained through a malware-signing-as-a-service operation Microsoft attributes to a separate actor it tracks as Fox Tempest. Command-and-control activity from this wave was observed reaching `brokeapt[.]com`, `pan.ssffaa19[.]xyz`, and `pan.rongtv[.]xyz`.

Storm-3075 repeated the pattern about six weeks later: within roughly 45 minutes of DeepSeek publicly previewing its V4 model on 2026-04-24, the group had stood up a fake "DeepSeek-V4" GitHub organization (repository `shippingtechnologymovie`, folder `AI-techVideos`) loaded with stolen branding to distribute a trojanized "release." Microsoft describes Storm-3075 as a pure initial access broker: it does not monetize the resulting infections itself, instead distributing final payloads - Vidar Stealer, Lumma Stealer, Hijack Loader, Oyster, and SilabRAT - on behalf of multiple downstream actors, so the specific malware family a given victim receives rotates across campaigns.

## Why this matters for detection

The campaign is built to defeat two trust signals defenders lean on by default: the installer is **code-signed** (via Fox Tempest's signing service, specifically to pass signature-based allowlisting), and it's **branded as AI tooling** at a moment when users are primed to install unfamiliar AI plugins and command-line tools without much scrutiny. Because Storm-3075 operates as a broker that rotates the delivered payload family, detection tuned to one specific stealer's static signature will catch this wave but miss the next. The stable pattern is the delivery mechanics themselves: an installer with an AI-branded filename, downloaded through a browser from an ad or search result (not a vendor's own domain), executed from a Downloads/Temp path, followed shortly by outbound connections to freshly registered domains.

## Detection Guidance

```yaml
title: AI-Branded Installer Executed from Download Path with Rapid Outbound Connection
status: experimental
description: >-
  Detects execution of an AI-themed-named installer or executable from a
  browser download directory (Downloads/Temp), followed shortly by an
  outbound network connection to a non-corporate domain, consistent with
  Storm-3075's malvertising/SEO-poisoning delivery of code-signed stealer
  and loader payloads impersonating ChatGPT, Copilot, Claude, and DeepSeek.
references:
  - https://www.microsoft.com/en-us/security/blog/2026/09/10/detect-and-disrupt-ai-themed-attacks-with-microsoft-defender/
  - https://www.microsoft.com/en-us/security/blog/2026/06/08/ai-brands-as-bait-how-threat-actors-are-using-the-ai-hype-in-social-engineering/
  - https://cyberpress.org/ai-brands-fuel-phishing/
author: Aryan
date: 2026-09-23T00:00:00.000Z
tags:
  - attack.resource_development
  - attack.t1608.006
  - attack.initial_access
  - attack.t1204.002
  - attack.defense_evasion
  - attack.t1553.002
  - attack.command_and_control
  - attack.t1071.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_download_path:
    Image|contains:
      - '\Downloads\'
      - '\AppData\Local\Temp\'
  selection_ai_branded_name:
    Image|contains:
      - 'AI-Plugin'
      - 'AiPlugin'
      - 'FluxAI'
      - 'FluxProAI'
      - 'ChatGPT'
      - 'DeepSeek'
      - 'ClaudeAI'
      - 'CopilotAI'
  selection_parent_browser:
    ParentImage|endswith:
      - '\chrome.exe'
      - '\msedge.exe'
      - '\firefox.exe'
      - '\explorer.exe'
  condition: selection_download_path and selection_ai_branded_name and selection_parent_browser
  timeframe: 15m
  # Escalate to critical if the same process establishes an outbound
  # connection to a domain registered within the last 30 days shortly after launch
falsepositives:
  - Legitimate AI-vendor installers downloaded directly from the vendor's own verified domain (openai.com, anthropic.com, microsoft.com, deepseek.com)
  - IT-approved AI plugin deployments pushed through an internal software portal rather than a browser download
level: high
```

## Prevention

- Block or flag executables with AI-brand keywords in the filename that were downloaded from an ad click-through or search result rather than the vendor's own verified domain.
- Don't treat a valid code-signing signature as sufficient trust on its own for newly observed executables - Storm-3075's payloads are signed specifically to defeat that check via a commercial signing-as-a-service pipeline.
- Educate users that OpenAI, Anthropic, Microsoft, and DeepSeek do not distribute their consumer AI products as third-party "Windows plugin" installers surfaced through streaming-site ads or unofficial GitHub repos.
- Monitor for newly executed binaries that immediately connect to newly registered or rarely seen domains, independent of what malware family the binary turns out to be - this generalizes across Storm-3075's rotating payload roster.

*See also: [Storm-3075 - AI-Brand Malvertising Initial Access Broker](/actors/storm-3075/) for the actor's broader behavioral pattern.*

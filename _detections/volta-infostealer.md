---
title: "VOLTA / VOLTA-AUTODOXER - Infostealer That Outsources Victim Appraisal to a Commercial LLM (Threat Brief)"
layout: default
---

## Overview

**VOLTA** (also referenced as **VOLTA-AUTODOXER**) is a Windows-only, self-deleting infostealer disclosed by Cisco Talos on 2026-10-31, with samples first observed in the wild on 2026-10-11. Its core collection routine is a conventional, already-mature stealer: it harvests saved browser credentials, cookies, and payment card data from Chromium-based browsers - including attempts to defeat Chrome's App-Bound Encryption, the credential-store hardening Google shipped specifically to stop this class of theft - plus data from Firefox, Thunderbird, and Outlook. It also targets cryptocurrency wallets by attempting to crack wallet passwords locally on the infected host rather than just exfiltrating the encrypted wallet files, and mines the victim's Gmail inbox for e-commerce and delivery receipts (Amazon, DoorDash, Uber Eats, Walmart, PayPal) specifically to corroborate the victim's real-world home address.

What makes VOLTA notable is an optional step layered on top of that collection: once harvesting finishes, it compiles the stolen data into a structured dossier and submits it to a commercial large language model through the OpenRouter API, defaulting to Claude Opus 4.6 with an automatic fallback chain to Kimi K2 and then Gemini 2.5 Flash if the first-choice model refuses the request. The model's job is to appraise and triage the victim - rating stolen assets by monetization tier and assessing the victim's security posture/password hygiene - solving, for the attacker, the "big data" problem of a stealer-log glut where most harvested data is low-value and manual review doesn't scale. The LLM response is saved locally and bundled with the stolen data into a final exfiltration archive. Talos has not confirmed a distribution vector or attributed VOLTA to a named criminal group; it appears to be financially motivated crimeware, possibly still in early or limited-distribution use.

## Why this matters for detection

VOLTA's AI step is the headline, but it's also the weakest link for detection: Talos explicitly cautions that a connection to `openrouter.ai` is **not** inherently malicious - OpenRouter and the underlying model providers are legitimate commercial services used by countless benign applications. The signal only emerges from **correlation**: an unsigned, short-lived process creating a specific set of local artifacts (a structured victim dossier, a saved AI response file) immediately before making an outbound HTTPS call to a commercial LLM-routing API. Network destination alone is a dead end; host-based artifact creation tied to that network behavior is what separates VOLTA from normal AI-tooling traffic. The self-deletion behavior also means the debug log left behind in `%APPDATA%` can be the only forensic trace once the main binary is gone, making file-creation telemetry more valuable here than process-execution telemetry alone.

## Detection Guidance

```yaml
title: VOLTA Infostealer - Victim Dossier Artifacts Preceding LLM API Exfiltration
status: experimental
description: >-
  Detects creation of VOLTA infostealer artifacts (victim dossier, AI
  appraisal output, debug log, or exfiltration archive) in %APPDATA%,
  optionally correlated with outbound HTTPS to a commercial LLM-routing
  API (e.g. openrouter.ai) from the same process tree. Network
  destination alone is not sufficient to flag, since OpenRouter is a
  legitimate service used by unrelated applications.
references:
  - https://blog.talosintelligence.com/appraisal-by-ai-model-driven-victim-prioritization-in-the-volta-infostealer/
  - https://thehackernews.com/2026/11/new-volta-infostealer-uses-claude.html
  - https://labs.cloudsecurityalliance.org/research/csa-research-note-volta-llm-victim-ranking-infostealer-20261/
author: Aryan
date: 2026-11-15T00:00:00.000Z
tags:
  - attack.credential_access
  - attack.t1555.003
  - attack.t1539
  - attack.collection
  - attack.t1114.001
  - attack.exfiltration
  - attack.t1041
  - attack.defense_evasion
  - attack.t1070.004
logsource:
  category: file_event
  product: windows
detection:
  selection_dossier_files:
    TargetFilename|endswith:
      - '\Identity_Report.txt'
      - '\AI_Analysis.txt'
      - '\volta_debug.txt'
  selection_exfil_archive:
    TargetFilename|contains: 'volta_dox'
    TargetFilename|endswith: '.zip'
  condition: selection_dossier_files or selection_exfil_archive
  # Higher confidence: correlate with a network connection event to
  # openrouter.ai from the same ProcessGuid within a 5m window
falsepositives:
  - Unrelated files that happen to share the generic "Identity_Report" or "AI_Analysis" naming - verify file path and surrounding process context
  - Legitimate automation or research tooling that calls OpenRouter/Claude/Gemini/Kimi APIs - this is why network destination alone must not be the sole trigger
level: high
```

## Prevention

- Keep Chrome/Chromium updated and don't disable App-Bound Encryption - VOLTA's credential-theft routine specifically targets bypassing this hardening.
- Treat connections to LLM-routing APIs (OpenRouter and similar aggregators) from unexpected or unsigned processes as worth investigating, even though the destination itself is benign - the risk is in which process is calling it, not the API.
- Monitor `%APPDATA%` for the creation of structured text/archive files immediately followed by outbound HTTPS traffic, especially from short-lived or self-deleting processes.
- User awareness: Gmail/Outlook receipt data (delivery confirmations, order histories) can be mined to corroborate a home address even when financial data is otherwise well-protected - this is a reminder that email retention policy is also a privacy control.

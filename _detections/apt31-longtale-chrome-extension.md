---
title: "SUPERSTOMP/LONGTALE - Malicious Chrome Extension Sideloaded via Secure Preferences Tampering (Threat Brief)"
layout: default
---

## Overview

Starting around 2026-08-28, the Chinese state-sponsored group tracked as **APT31/JungleBamboo** (also known as Violet Typhoon and TA412) used a shared Chrome/Windows zero-day exploit chain - combining a V8 type-confusion bug (CVE-2026-85046), a WebAssembly sandbox-escape flaw (CVE-2026-87491), and a Windows ALPC heap overflow (CVE-2026-85880) - to gain code execution on target machines at NGOs, mining companies, and US commodity trading firms. Where other clusters using the same exploit chain (including UTA0560, see its own profile) dropped a standalone backdoor, APT31/JungleBamboo's post-exploitation payload was a loader dubbed **SUPERSTOMP**, whose sole job is to silently install a malicious Chrome extension - tracked as **LONGTALE** (also called GemStone) - that impersonates a "Google Gemini" assistant extension.

SUPERSTOMP does this without using Developer Mode or any Chrome Web Store upload: it copies the browser profile's `Secure Preferences` file, strips the existing per-preference integrity hashes and the overall `super_mac` hash, registers the rogue extension and the settings needed to enable it, then forges valid **legacy HMAC values** for the modified file and recomputes a new `super_mac`. Because Chrome still accepts legacy-MAC validation as a migration path, it accepts the forged file as authentic, silently re-encrypts it under the current integrity scheme, and enables the extension with no tampering warning shown to the user. Once active, LONGTALE logs keystrokes, captures form submissions, steals cookies and session-storage tokens, takes screenshots when operator-defined keywords appear on screen, and accepts further remote collection commands from its C2.

## Why this matters for detection

This technique defeats the two controls most organizations actually rely on for extension security: Chrome Web Store review (the extension is never published there) and Chrome's own tamper-evident Secure Preferences design (the integrity check is satisfied with forged-but-valid legacy hashes, not bypassed outright). There is no malicious executable dropped to disk in the classic sense - the "malware" is a browser extension with normal extension permissions, which most EDR process- and file-based detection logic is not tuned to flag as hostile. The two durable signals are (1) a non-browser process writing to a Chrome profile's `Secure Preferences` file, which legitimate Chrome updates never do (Chrome manages that file itself from within its own process), and (2) a newly enabled extension ID appearing in a Chrome profile's `extensions.settings` without a corresponding ExtensionInstallForcelist/enterprise-policy entry or Web Store install event.

## Detection Guidance

```yaml
title: Non-Browser Process Writing to Chrome Secure Preferences File
status: experimental
description: >-
  Detects a process other than chrome.exe or its installer/update helpers
  writing to a Chrome/Chromium user profile's Secure Preferences file,
  consistent with SUPERSTOMP-style forged-HMAC tampering used to silently
  sideload a malicious extension (as seen in the APT31/JungleBamboo
  LONGTALE campaign).
references:
  - https://www.volexity.com/blog/2026/09/09/mind-the-patch-gap-multiple-chinese-threat-actors-chain-0-day-exploits-in-chrome-windows/
  - https://thehackernews.com/2026/09/china-linked-hackers-exploit-chrome.html
  - https://securityaffairs.com/199104/apt/one-exploit-chain-two-espionage-campaigns-chrome-and-windows-under-fire.html
author: Aryan
date: 2026-10-04T00:00:00.000Z
tags:
  - attack.persistence
  - attack.t1176
  - attack.credential_access
  - attack.t1539
  - attack.defense_evasion
  - attack.t1553
logsource:
  category: file_event
  product: windows
detection:
  selection_target_file:
    TargetFilename|endswith: '\User Data\Default\Secure Preferences'
  filter_known_browser_writers:
    Image|endswith:
      - '\chrome.exe'
      - '\GoogleUpdate.exe'
      - '\msedge.exe'
      - '\MicrosoftEdgeUpdate.exe'
  condition: selection_target_file and not filter_known_browser_writers
falsepositives:
  - Enterprise browser-management agents or profile-provisioning tools that legitimately rewrite Secure Preferences during managed deployment
  - Browser migration/profile-sync utilities run during OS imaging
level: high
```

## Prevention

- Deploy Chrome extensions exclusively via `ExtensionInstallForcelist`/`ExtensionInstallAllowlist` enterprise policy, and alert on any enabled extension ID not present in that policy - this defeats SUPERSTOMP-style sideloading regardless of how the integrity check was bypassed.
- Monitor file-integrity or EDR file-write telemetry on `Secure Preferences` and `Preferences` inside Chrome/Edge profile directories for writes from any process other than the browser or its official updater.
- Patch Chrome/Chromium to the version addressing CVE-2026-85046/CVE-2026-87491 and apply the Windows update for CVE-2026-85880 - closing the initial-access chain removes the opportunity to drop SUPERSTOMP in the first place.
- Treat AI-assistant-branded extensions (Gemini, Copilot look-alikes, etc.) requesting broad `cookies`, `webRequest`, or `<all_urls>` permissions as high-scrutiny items in any extension review process, since brand impersonation is being used specifically to blunt user suspicion.

*See also: [APT31 / JungleBamboo - Chinese MSS-Linked IP Theft Actor Behind the LONGTALE Browser Implant](/actors/apt31-junglebamboo/) for the actor's broader behavioral pattern.*

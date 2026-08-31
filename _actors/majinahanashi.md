---
title: "Majinahanashi - Emerging RaaS with WFP/QoS-Based EDR Interference"
layout: default
---

## Who they are

Majinahanashi is a ransomware operation first tracked by researchers around 2026-08-12, with sample compile timestamps dating to 2026-07-02 - placing its active emergence in mid-2026. The name (Japanese for roughly "ghost stories") follows the branding convention of other recent Japanese-themed lockers such as Yurei, Sinobi, and Tengu, though - unlike The Gentlemen, whose Russian-speaking origin is inferred from an internal CIS-targeting prohibition - no public reporting attributes Majinahanashi's operators to any specific nationality; the branding theme alone is not evidence of origin. As of late August 2026 it had claimed 12-18+ victims across nine or more countries (reporting varies, with Italy, the US, France, Germany, Switzerland, Portugal, Colombia, Lithuania, Chile, Bulgaria, and India all named among victims), spanning healthcare, hospitality, e-commerce, manufacturing, agri-food, retail, and technology sectors.

## Behavioral pattern

- **Performance-aware encryption.** Windows-based, compiled in C/C++ (~90 KB samples), encrypting files with AES-256 using a unique per-file key protected by RSA, and appending the `.majin` extension.
- **Aggressive anti-recovery.** Before encrypting, it deletes volume shadow copies, removes the USN journal, disables System Restore and hibernation, modifies boot-recovery settings, and clears Windows event logs - a thorough attempt to foreclose recovery without paying.
- **Named EDR/backup interference.** It targets a specific, extensive list of security and backup processes by name for termination, including CrowdStrike Falcon, SentinelOne, Carbon Black, FortiEDR, Cylance, Microsoft Defender for Endpoint, Qualys, Tanium, Veeam, Backup Exec, and Acronis.
- **Novel network-layer evasion.** Uses Windows Filtering Platform (WFP) and QoS policy controls to interfere with or throttle EDR/cloud-agent network communications - a comparatively unusual technique versus the more common approach of simply killing the agent process.
- **Double extortion with a leak-site countdown.** Publishes stolen PII as proof of compromise and runs countdown timers on its leak site to pressure negotiation before full data release.
- **Mid-market targeting.** Victims skew toward mid-sized enterprises (average reported victim revenue around $25M) rather than large enterprises, spread broadly across sectors and geographies rather than concentrated in one vertical.
- **Infostealer-adjacent access.** Roughly half of confirmed victims show prior exposure to infostealer malware (browser-stored credential/session-token theft), suggesting initial access is often built on previously stolen, resold credentials rather than novel exploitation.

## What this means for defenders

Because Majinahanashi's EDR interference goes beyond simple process termination - reaching into WFP filters and QoS policy manipulation to blind security tooling's *network* visibility - defenders should treat unexpected WFP/QoS policy changes on endpoints as a meaningful signal in their own right, not just process-kill attempts against named agents. The strong link between infostealer exposure and victimization also means credential hygiene (rotating browser-stored credentials, invalidating stale session tokens) is a real prevention lever here, not just an incidental best practice.

*See also: [Majinahanashi Ransomware - WFP/QoS-Based EDR Interference](/detections/majinahanashi-ransomware/) for detection logic.*

**Sources:** [Broadcom Protection Bulletin](https://www.broadcom.com/support/security-center/protection-bulletin/majinahanashi-ransomware), [The Raven File - Majinahanashi Ransomware: Yet Another Japanese Locker](https://theravenfile.com/2026/08/14/majinahanashi-ransomware-another-japanese-locker/), [Breachsense - Majinahanashi Ransomware: Victims and Activity](https://www.breachsense.com/ransomware-groups/majinahanashi/)

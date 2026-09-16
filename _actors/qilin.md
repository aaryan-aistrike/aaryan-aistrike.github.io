---
title: "Qilin / Agenda - Russian-Speaking RaaS and the Most Active Ransomware Operation of 2026"
layout: default
---

## Who they are

**Qilin** (originally launched as **Agenda** in mid-2022 before rebranding) is a Russian-speaking ransomware-as-a-service operation that has ranked as the single most active ransomware group tracked by multiple threat intelligence firms for four consecutive quarters through Q2 2026. Between July 2025 and June 2026 the group claimed 1,403 victims on its leak site - an average of roughly 117 per month - and in a single 72-hour window in early June 2026 it posted 15 new victims across nine countries. Operators take a 15-20% cut and leave intrusion tradecraft to affiliates, which produces meaningfully different attack chains from one Qilin victim to the next even though the encryptor and extortion infrastructure are shared.

## Behavioral pattern

- **Edge-device exploitation for initial access.** Qilin affiliates have chained CVE-2026-0257 (a PAN-OS GlobalProtect authentication-bypass flaw exploitable when auth-override cookies are enabled with specific certificate configurations) and CVE-2026-50751 (a Check Point VPN Remote/Mobile Access authentication bypass) to establish unauthenticated VPN sessions as a foothold, rather than relying on phishing.
- **WSL abuse for EDR evasion.** In intrusions documented by Cisco Talos and BleepingComputer, affiliates transfer a Linux ELF encryptor onto a compromised Windows host (commonly via WinSCP), launch it through legitimate remote-management software such as Splashtop's `SRManager.exe`, and execute it inside the Windows Subsystem for Linux - a space most Windows-native EDR tooling does not inspect at the same fidelity as native PE processes.
- **Living-off-the-land post-exploitation.** Credential harvesting via LSASS dumping and NTDS extraction, PsExec/RDP for lateral movement, and commodity remote-access tools (AnyDesk, ngrok, LogMeIn) for persistence - all tools with legitimate uses, chosen specifically to blend into normal admin activity.
- **Anti-forensic discipline.** Windows event logs are cleared before encryption in multiple documented intrusions, and the ransomware payload has been staged in `C:\PerfLogs\` - a default, rarely-monitored Windows directory - rather than a more conspicuous location.
- **Triple-extortion pressure.** Beyond encryption and leak-site exposure, Qilin's negotiation panel added a "Call Lawyer" feature connecting victims to legal consultants to amplify regulatory-exposure pressure, and the group added DDoS capability to its affiliate toolkit in 2025 as a third lever.
- **Toolkit evolution.** The group has shifted its encryptor codebase from Go to Rust, added Chrome credential-harvesting capability, and deployed BYOVD (Bring Your Own Vulnerable Driver) techniques to kill EDR processes prior to encryption.
- **Geographic self-restriction.** Consistent with a Russian-speaking operation, Qilin's targeting avoids CIS-region organizations, and the group's heaviest victim concentration is North America (370+ attacks in H1 2026) followed by Western Europe.

## What this means for defenders

Because Qilin affiliates vary their post-exploitation tradecraft (ranging from rapid encryption-only runs to full double-extortion with data exfiltration), the two most consistent, actionable signals across campaigns are the **edge-device initial access vector** and the **WSL execution pattern**: an unauthenticated VPN session establishing itself right before LSASS/NTDS access is a strong precursor, and a `wsl.exe` or `bash.exe` process spawned by remote-management software (rather than an interactive administrator) - especially one that goes on to touch files across the Windows filesystem - is a detectable anomaly that most Windows-only EDR rulesets are not tuned to catch. Patching internet-facing VPN/firewall appliances promptly and extending detection coverage into WSL process activity closes both gaps at once.

*See also: [Qilin - WSL-Based Linux Encryptor Execution for EDR Evasion](/detections/qilin-ransomware/) for detection logic.*

**Sources:** [Cisco Talos - Qilin EDR killer infection chain](https://blog.talosintelligence.com/qilin-edr-killer/), [BleepingComputer - Qilin ransomware abuses WSL to run Linux encryptors in Windows](https://www.bleepingcomputer.com/news/security/qilin-ransomware-abuses-wsl-to-run-linux-encryptors-in-windows/), [Arctic Wolf - Cookie Crumbles: How Exploitation of CVE-2026-0257 Leads to Qilin Ransomware](https://arcticwolf.com/resources/blog/exploitation-of-cve-2026-0257-leads-to-qilin-ransomware/), [The Hacker News - Qilin Ransomware Attackers Exploit PAN-OS Authentication Bypass](https://thehackernews.com/2026/07/qilin-ransomware-attackers-exploit-pan.html), [Help Net Security - Qilin ransomware affiliate exploited Check Point VPN zero-day](https://www.helpnetsecurity.com/2026/06/08/check-point-cve-2026-50751-qilin-ransomware/), [MOXFIVE - Qilin Ransomware 2026: TTPs, Victims and Defense Guide](https://www.moxfive.com/blog/qilin-ransomware-2026-ttps-victims-and-defense-guide)

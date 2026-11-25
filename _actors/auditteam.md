---
title: "AuditTeam - Ransomware Group Disguising Extortion as a Paid Security Audit"
layout: default
---

## Who they are

AuditTeam is a ransomware group that Kaspersky's GReAT team publicly detailed on 2026-11-18, after tracking its activity from January through October 2026. In that window the group compromised dozens of organizations across at least seven countries and territories with confirmed victims in China, Finland, Hong Kong, Italy, the Philippines, Russia, and Senegal - a notably broad, opportunistic spread rather than a single-region focus. Its defining trait is a custom modular framework called **OpsAgent**, first observed on 2026-03-10 in an attack on an organization in Hong Kong, which Kaspersky assesses was likely built with AI assistance.

## Behavioral pattern

- **Extortion dressed up as consulting.** The group's ransom note never mentions encryption directly. Instead it's framed as an "Audit & Consulting fee" invoice, offering the victim a "vulnerability report" in exchange for payment and threatening to publish stolen data otherwise - a deliberate rebranding of double extortion to look like a legitimate, if unwanted, professional service.
- **Modular, multi-language loader chain.** OpsAgent ships with obfuscated loaders written in C, .NET, and Rust, which unpack and inject the implant into legitimate Windows processes such as `msiexec.exe` to blend into normal system activity.
- **BYOVD for mass defense evasion.** A dedicated module drops a digitally signed driver from Beijing Jiangmin Antivirus and abuses it to terminate security, backup, and database processes before encryption begins - a bring-your-own-vulnerable-driver (BYOVD) technique that sidesteps EDR/AV protections regardless of which vendor the victim runs.
- **Privilege escalation via built-in tooling.** Rather than custom exploits, the group leans on built-in Windows privilege-escalation commands and token theft to reach SYSTEM-level access once a foothold is established.
- **Opportunistic, not geographically selective.** Confirmed and claimed victims span Europe, Asia, and Africa, including at least one attack against a Russian organization - notable because many ransomware crews explicitly avoid CIS-region targets, suggesting AuditTeam either lacks that operational constraint or is less concerned with regional law-enforcement exposure.
- **No confirmed nationality attribution.** Unlike many tracked RaaS crews, Kaspersky's public reporting does not attach a language or nation-state attribution to AuditTeam - its tradecraft is being tracked on behavior and tooling alone.

## What this means for defenders

Because OpsAgent's ransom note is framed as a business communication rather than an overt ransomware demand, staff training needs to cover extortion notes that *don't* look like traditional ransomware messaging - "the sender is offering us a security audit/report for a fee" is itself a red flag when it follows unexplained file or service disruption. On the technical side, the BYOVD chain means defenders should alert on new, rarely-seen signed drivers loading on endpoints (regardless of which vendor signed them) rather than trusting driver signatures alone, and should watch for mass, correlated termination of security/backup/database processes as a pre-encryption signal. The multi-language loader strategy (C/.NET/Rust) also means detection shouldn't be tuned to a single binary family - the injection target (`msiexec.exe` and similar legitimate processes) and the behavioral sequence matter more than any one loader's signature.

*See also: [AuditTeam - OpsAgent BYOVD Defense-Evasion Chain](/detections/auditteam-opsagent-ransomware/) for detection logic.*

**Sources:** [Kaspersky press release](https://www.kaspersky.com/about/press-releases/kaspersky-uncovers-auditteam-ransomware-campaign-spanning-europe-asia-and-africa), [Kaspersky Securelist technical report](https://securelist.com/auditteam-opsagent-forced-audit/122031/), [GridinSoft](https://blog.gridinsoft.com/auditteam-opsagent-ransomware-audit-fee/), [Cybersecurity News](https://cybersecuritynews.com/auditteam-ransomware-gang/), [SOCRadar AuditTeam group profile](https://socradar.io/free-tools/ransomware-intelligence/groups/auditteam)

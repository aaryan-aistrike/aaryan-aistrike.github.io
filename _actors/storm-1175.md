---
title: "Storm-1175 - N-Day-to-Ransomware Speed Runner"
layout: default
---

## Who they are

Storm-1175 is a financially motivated, China-linked cybercriminal group Microsoft Threat Intelligence has tracked since at least 2023. Its signature is speed: the group weaponizes N-day vulnerabilities in vulnerable, internet-facing systems during the narrow window between public disclosure and widespread patching - and in some documented cases, exploited flaws up to a week *before* public disclosure. Historically the group deployed Medusa ransomware as an affiliate; in August 2026 it debuted a self-branded payload, StormEncryptor, marking its first observed activity outside the Medusa program.

## Behavioral pattern

- **Exploitation speed over exploit novelty.** Storm-1175 doesn't rely on discovering its own zero-days as a primary strategy - it wins by being fast on N-days, hitting exposed assets in the days immediately after a CVE is disclosed and before organizations finish patching.
- **Broad, opportunistic vulnerability targeting.** Prior intrusions have chained flaws in GoAnywhere MFT, SmarterMail, Microsoft Exchange, Ivanti Connect Secure, and JetBrains TeamCity - the group targets whatever exposed edge software has a fresh, exploitable flaw, not one specific product family.
- **Extremely short dwell time.** Initial access to data exfiltration to ransomware deployment often completes within days, and in some documented intrusions within 24 hours - far faster than the multi-week dwell time typical of many ransomware affiliates.
- **Living-off-the-land post-compromise.** Once inside, the group leans on legitimate remote-management tooling (AnyDesk, SimpleHelp) for persistence, Advanced IP Scanner for discovery, and Mimikatz for LSASS credential dumping - the same commodity toolkit used across much of the ransomware ecosystem.
- **Sector concentration.** Recent campaigns have hit healthcare, education, professional services, and finance organizations concentrated in Australia, the UK, and the US.
- **A self-branded pivot.** The August 2026 shift to StormEncryptor (a C++ payload appending `.encrypted` to files and dropping a `!!!README_FIRST!!!.txt` ransom note) - likely enabled by exploiting an authentication-bypass flaw in N-able's N-central RMM platform (CVE-2026-18577) - suggests the group is moving from Medusa-affiliate status toward operating its own ransomware brand.

## What this means for defenders

Storm-1175's pattern rewards organizations that can patch internet-facing edge software within days, not weeks, of disclosure - the group's entire operating model depends on that gap existing. Because dwell time is so short, detections tuned for slow, methodical intrusions will often fire too late; the highest-value signal is the *speed* of the progression itself (new admin account, then remote-access tooling, then credential dumping, all within hours) rather than any single indicator in isolation.

*See also: [Storm-1175 - Rapid N-Day-to-Ransomware Post-Exploitation Pattern](/detections/storm-1175-ransomware/) for detection logic.*

**Sources:** [The Hacker News](https://thehackernews.com/2026/08/china-linked-hackers-deploy-new.html), [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/04/06/storm-1175-focuses-gaze-on-vulnerable-web-facing-assets-in-high-tempo-medusa-ransomware-operations/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-stormencryptor-ransomware-used-by-former-medusa-affiliate/), [Help Net Security](https://www.helpnetsecurity.com/2026/08/10/cve-2026-18577-n-central-hotfix-2-msps/)

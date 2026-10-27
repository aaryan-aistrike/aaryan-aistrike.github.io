---
title: "Iran's MOIS - CHOSEN BRICK/HEAVYGRAM Spyware Targeting Dissidents, Activists, and Journalists"
layout: default
---

## Who they are

In a joint advisory published 2026-09-15, the UK's National Cyber Security Centre (NCSC), the US FBI, and the Netherlands' AIVD attributed a Windows spyware family to Iran's Ministry of Intelligence and Security (MOIS) - the country's primary civilian intelligence agency. The NCSC tracks the malware as **CHOSEN BRICK**; the FBI's own analysis, which extends an earlier March 2026 FLASH alert, calls the same tooling **HEAVYGRAM**. Some vendor reporting (unconfirmed by the three agencies themselves) assesses the campaign as consistent with APT42/Charming Kitten tradecraft. The operation has been active since at least autumn 2023 and has targeted individuals in the UK, US, and Netherlands "and around the world."

## Behavioral pattern

- **Person-centric, not network-centric targeting.** Unlike most campaigns on this site, CHOSEN BRICK isn't aimed at breaching an organization's network - it's aimed at specific individuals: Iranian dissidents, human-rights activists, journalists covering Iran, and others whose views conflict with the Iranian government. The advisory also warns that Iranian intelligence has separately plotted physical kidnapping or lethal operations against some targeted individuals, underscoring that this is a physical-safety issue, not just a data-theft one.
- **Messaging-app social engineering for delivery.** Operators impersonate known contacts on WhatsApp and Telegram to build trust before sending a malicious payload, often disguised as a legitimate application (Norton Antivirus and Adobe Flash Player installers have both been observed as lures).
- **Telegram as command-and-control, not just a lure.** Once installed, the malware doesn't call home to attacker-registered infrastructure - it connects to `api.telegram.org` and communicates through a Telegram bot. Each victim is assigned a unique Bot ID, which limits cross-victim contamination if one bot is discovered and also lets the operators blend malicious traffic into normal Telegram API traffic.
- **Defense evasion via Microsoft Defender tampering.** The malware adds its own exclusions to Microsoft Defender rather than trying to evade signature detection outright - a direct, low-effort way to guarantee its own files are never scanned (ATT&CK T1562.001).
- **Registry Run key persistence with a staging quirk.** Persistence is maintained through an `HKCU\...\Run` key rather than scheduled tasks or services. Additional payloads the operators push down are commonly staged to a non-standard path containing a stray space (`C:\Windows \SysWOW64`) - a small but useful anomaly for defenders, since legitimate software does not write there.
- **Infrastructure reuse across commodity cloud/CDN and proxy providers.** Beyond Telegram, observed infrastructure includes Backblaze B2, Vultr Object Storage, Storj, and residential-proxy services (IPRoyal, Lightning Proxies) - all legitimate commercial services abused to blend exfiltration and C2 traffic into normal cloud egress.

## What this means for defenders

Most organizations don't think of "a dissident's personal laptop" as part of their threat model, but the individuals targeted by CHOSEN BRICK frequently work for, consult with, or volunteer at NGOs, media outlets, and advocacy organizations that **do** have corporate IT environments - and a compromised personal messaging account is a realistic pivot point into those networks. For any organization whose staff, contractors, or board members have a public profile on Iran policy, human rights, or journalism, this campaign is a relevant inclusion in third-party/BYOD risk modeling, not just a personal-safety advisory to forward along. Detection should focus on the C2 channel (Telegram API traffic from unexpected processes) and the Defender-tampering step, since both are harder for the operators to vary than the social-engineering lure itself.

*See also: [CHOSEN BRICK/HEAVYGRAM - Telegram-Controlled Spyware Detection](/detections/chosen-brick-spyware/) for detection logic.*

**Sources:** [NCSC: UK and allies expose spyware used by Iranian state actors](https://www.ncsc.gov.uk/news/uk-allies-expose-spyware-iranian-state-actors-target-dissidents-activists-journalists), [SecurityWeek](https://www.securityweek.com/us-uk-dutch-agencies-expose-iranian-chosen-brick-surveillance-malware/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/iranian-hackers-use-chosen-brick-windows-malware-to-spy-on-targets/), [The Hacker News](https://thehackernews.com/2026/09/iranian-hackers-use-telegram-controlled.html), [Security Affairs](https://securityaffairs.com/199217/malware/chosen-brick-irans-surveillance-malware.html)

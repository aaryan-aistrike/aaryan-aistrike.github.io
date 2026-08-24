---
title: "CRPx0 - Scam-to-RaaS Cross-Platform Extortion Crew"
layout: default
---

## Who they are

CRPx0 is an emerging ransomware-as-a-service operation that very likely began around March 2026 as a cryptocurrency money-laundering scam before pivoting into a full RaaS affiliate program. Its own ransomware activity was first identified in June 2026 with fewer than 10 victims, but volume jumped sharply in July - 46 claimed victims - making it one of the most active ransomware/data-extortion collectives that month. It launched a clearnet-and-dark-web leak site on 2026-08-07 and, despite its RaaS platform being less than a month old, had already shipped a v2.0 release by early August 2026.

## Behavioral pattern

- **Social-engineering-first delivery.** Initial infection comes from lures like fake "free OnlyFans account" archives and fake FedEx shipping documents, not exploited vulnerabilities - a ZIP contains a disguised shortcut (LNK) that quietly runs hidden commands.
- **Multi-stage, Python-based payload chain.** The disguised shortcut triggers a VBScript loader that prepares the host and installs a Python-based implant, which then connects out to attacker infrastructure for interactive control, updates, and follow-on payload delivery.
- **C2-triggered encryption, not automatic.** Ransomware execution is a deliberate operator action taken after reconnaissance and data exfiltration, not something the implant fires on its own - giving affiliates time inside a network before the destructive stage.
- **Bundled crypto theft.** Alongside ransomware, the implant runs a clipboard hijacker that swaps copied cryptocurrency wallet addresses for attacker-controlled ones, plus a BIP39 seed-phrase scanner to steal wallet recovery phrases directly off disk.
- **Aggressive affiliate economics.** CRPx0 markets a 100%-profit-share model to RaaS buyers (in exchange for a one-time ~$10,000 platform fee) and a parallel Hacking-as-a-Service offering - unusually generous terms that suggest a deliberate push to recruit affiliates fast.
- **Opportunistic, healthcare-heavy targeting.** Early victims skewed toward small U.S. dental practices before expanding into technology and financial services; documented victims concentrate in the United States and Turkey. Ransom notes appear in English, Russian, and Chinese, and observed C2 infrastructure includes Russian (.ru) domains, consistent with Russian-speaking operators - though no formal nation-state attribution has been made.

## What this means for defenders

CRPx0's chain leans entirely on a user opening an archive and running a shortcut - there's no exploited CVE to patch here, which makes user-facing controls (archive/attachment filtering, blocking script-host execution from user-writable paths) and behavioral detection of the LNK-to-VBScript-to-Python chain the highest-leverage controls. Because encryption is operator-triggered rather than automatic, there's typically a window between initial compromise and the destructive stage where clipboard-hijacking and credential-theft activity is visible - catching those earlier, less noisy stages matters as much as catching encryption itself.

*See also: [CRPx0 - OnlyFans-Lure Ransomware Delivery Chain](/detections/crpx0-ransomware/) for detection logic.*

**Sources:** [SecurityWeek](https://www.securityweek.com/free-onlyfans-lure-used-to-spread-cross-platform-crpx0-malware/), [SC Media](https://www.scworld.com/brief/new-crpx0-malware-campaign-uses-onlyfans-lure-for-crypto-theft-and-ransomware), [Aryaka Threat Research Lab](https://www.aryaka.com/blog/crpx0-ransomware-multi-stage-attack/)

---
title: "n0n - Backup-Destruction Double-Extortion Ransomware Group"
layout: default
---

## Who they are

n0n is a ransomware operation first identified by researchers at CyberXTron on 2026-09-18. Within days it stood up a Tor-hosted leak site and had claimed more than a dozen victims by 2026-09-22 - an unusually fast start for a previously untracked group. Financial services organizations are the hardest-hit sector (23% of victims), followed by technology, retail, and education (15% each), with the United States as the primary target but victims claimed globally.

## Behavioral pattern

- **Backup and shadow-copy destruction as core leverage.** Beyond the now-standard double-extortion playbook of stealing data and threatening to leak it, n0n explicitly threatens to encrypt or outright destroy victim backups and shadow copies - an escalation aimed at removing recovery as a fallback option entirely, not just making it slower.
- **Infostealer-sourced initial access.** The group gains its first foothold using credentials harvested by third-party infostealer malware rather than its own custom loaders or exploits, reflecting the broader trend of ransomware affiliates buying access instead of building it.
- **Privilege escalation into administrative tooling.** Once inside, operators escalate privileges and abuse legitimate administrative access to stage and exfiltrate data ahead of extortion demands, rather than relying on bespoke malware for that phase.
- **Financially-motivated, opportunistic targeting.** The victim spread across financial services, technology, retail, and education sectors - with no clear vertical specialization - is consistent with an opportunistic, credential-driven targeting model rather than deliberate sector selection.
- **Rapid leak-site scaling.** Publishing over a dozen victims within four days of first being observed indicates an operation that was already mid-campaign before researchers spotted it, or one intentionally front-loading leak-site activity to establish credibility quickly.

## What this means for defenders

Because n0n's differentiating threat is aimed squarely at recovery infrastructure, backup isolation and immutability matter as much here as encryption prevention - a victim with untouchable offline backups neutralizes the group's core leverage. And because the entry vector is infostealer-sourced credentials rather than novel exploitation, credential hygiene (monitoring for organizational credentials appearing in stealer logs, enforcing MFA, and rotating exposed passwords quickly) is the highest-value control against this specific group.

*See also: [n0n - Shadow Copy and Backup Catalog Destruction](/detections/n0n-ransomware/) for detection logic.*

**Sources:** [SC Media](https://www.scworld.com/brief/new-ransomware-group-n0n-escalates-threats-by-targeting-backups), [Infosecurity Magazine](https://www.infosecurity-magazine.com/news/ransomware-gang-uses-backup/), [Mallory](https://mallory.ai/stories/01a0d404-9482-78ce-953c-062fa47c6c0b)

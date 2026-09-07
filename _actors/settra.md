---
title: "Settra - Fast-Growing Data-Extortion RaaS with AI-Assisted Leak Narratives"
layout: default
---

## Who they are

**Settra** is a ransomware and data-extortion operation first observed in June 2026, with its earliest disclosed victims dating to June 26-28, 2026. It has grown quickly since: as of September 7, 2026, its Tor-hosted leak site had publicly claimed 64 victims across 19 countries, including 16 in the preceding 30 days alone. Known victims cluster in Technology (22%), Professional Services (16%), and Manufacturing (14%). No confirmed link ties Settra to a previously known ransomware family or affiliate program - researchers assess it's either a newly launched independent operation or a rebranded affiliate cluster.

## Behavioral pattern

- **Valid-credential initial access, not custom exploitation.** MoxFive's incident-response tracking found roughly a third of known Settra victim domains associated with prior infostealer log exposure, and observed the group gaining initial access through compromised VPN credentials rather than novel malware or exploits.
- **Long, deliberate dwell time.** Attack timelines show an average of roughly 20 days between initial compromise and public leak-site disclosure - consistent with methodical data staging and reconnaissance rather than smash-and-grab extortion.
- **"Data broker" extortion model.** Researchers describe Settra as prioritizing data theft and reputational pressure over encryption, with encryption present but treated as a secondary lever rather than the primary damage mechanism.
- **AI-assisted, exposé-style leak posts.** Rather than publishing minimal victim metadata and a data link (the industry norm), Settra publishes long-form, investigative-narrative writeups per victim - detailing categories of stolen financial records, employee/customer PII, tax and payroll documentation, and internal correspondence - in a format researchers believe is produced with AI-assisted analysis of the stolen data to maximize legal, regulatory, and reputational pressure.
- **Standard double-extortion infrastructure.** Operates a Tor-hosted leak site (with multiple separate onion file servers for stolen data) and negotiates with victims over Tox, an encrypted messaging protocol favored across several ransomware operations.
- **Exploited by its own affiliates.** GuidePoint Security's GRIT team identified a rogue actor calling itself "Ransom Busters" contacting victims of Settra (alongside DragonForce and Anubis) pre-disclosure, posing as a legitimate data-recovery firm and charging $20,000-$60,000 to "delete" stolen data or hand over decryption keys. Shared tooling, a shared backdoor password, and a shared attacker hostname across incidents point to a single affiliate working across multiple RaaS programs and defrauding its own criminal partners - underscoring that Settra runs on outsourced affiliate labor typical of the RaaS model, with all the operational trust problems that implies.

## What this means for defenders

Because Settra's initial access rides on legitimately-issued VPN credentials rather than a distinctive exploit or malware sample, credential hygiene does more work than signature detection: screening for organizational credentials that surface in infostealer logs and credential-marketplace feeds, and forcing resets before they're used, closes the door before the ~20-day dwell window even opens. That same long dwell time is a defender's advantage - anomalous valid-account authentication and lateral movement following a VPN logon from an unfamiliar source has weeks to be caught before data staging completes, if VPN and internal authentication logs are actually correlated rather than reviewed in isolation. Separately, any post-breach outreach offering to delete stolen data or provide a decryptor outside the primary threat-actor negotiation channel should be treated as a probable secondary-extortion scam, not a legitimate remediation path - GRIT found no confirmed case of "Ransom Busters" actually following through after payment.

*See also: [Settra Ransomware - Valid-Credential VPN Initial Access](/detections/settra-ransomware/) for detection logic.*

**Sources:** [MoxFive - Settra Ransomware: TTPs, Victims, and Defense Guide](https://www.moxfive.com/blog/settra-ransomware-ttps-victims-and-defense-guide), [ProvenData - SETTRA Ransomware: Emerging Double-Extortion Threat](https://www.provendata.com/blog/settra-ransomware), [The Hacker News - Ransom Busters Claims It Hacked Ransomware Servers, Asks Victims for Up to $60,000](https://thehackernews.com/2026/08/ransom-busters-claims-it-hacked.html), [BleepingComputer - Rogue ransomware affiliate poses as recovery firm to steal payments](https://www.bleepingcomputer.com/news/security/rogue-ransomware-affiliate-ransom-busters-poses-as-recovery-firm/)

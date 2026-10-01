---
title: "KryBit - Babuk-Derived RaaS Caught in a Rival-Gang Hack-Back War"
layout: default
---

## Who they are

KryBit is a financially motivated ransomware-as-a-service operation first observed in March 2026, built on leaked Babuk source code rather than a custom encryptor - captured samples are flagged by antivirus engines as Babuk derivatives (ESET: `Filecoder.Babyk.A`, Microsoft: `Babuk!ic`). Despite the recycled codebase, the operation scaled quickly: within weeks it had posted 20+ victims to its Tor-based data leak site across consumer services, business services, education, technology, and manufacturing, with confirmed listings spanning Germany, Mexico, Turkiye, Japan, Austria, Taiwan, Canada, New Zealand, Argentina, and India. No confirmed ties to an established ransomware gang or nation-state have been identified, and unlike many Russian-speaking RaaS brands, no internal rule barring CIS-region targeting has been documented for the group.

## Behavioral pattern

- **Babuk-derived, not custom-built.** The encryptor is built on the 2021 leaked Babuk source rather than original engineering, placing KryBit among a large population of RaaS strains reusing that codebase - a lower barrier to entry than groups that invest in proprietary lockers.
- **Full RaaS kit with cross-platform builders.** The operator supplies encryptor builders for Windows, Linux, ESXi, and NAS plus 24/7 technical support, retaining roughly 20% of ransom proceeds while affiliates keep the rest (an 80/20 split) and supply their own initial access.
- **No single initial-access signature.** Because affiliates bring their own entry method, tracked intrusions map to Valid Accounts (T1078) and RDP/Remote Services (T1021/T1021.001) rather than a consistent exploited CVE - no vulnerability exploitation has been attributed to the group as a whole.
- **Heavy double-extortion staging.** Affiliates exfiltrate between 10GB and 250GB per victim - employee data, credentials, financial records, technical design files - before encryption, then demand $40,000-$100,000 and threaten publication via a Tor-based leak site and onion chat portal.
- **Standard Babuk-lineage defense evasion.** Pre-encryption tradecraft includes shadow copy deletion (`vssadmin.exe delete shadows /all /quiet`), process injection, and WMI/PsExec-driven lateral movement - some affiliates have also been tied to RMM tooling and Cobalt Strike staging ahead of mass encryption.
- **Got hacked by a rival gang - and hacked back.** Between late March and mid-April 2026, a rival extortion crew calling itself 0APT breached and leaked data from three ransomware operations including KryBit. KryBit retaliated by compromising 0APT's own infrastructure and defacing its leak site, giving researchers an unusually public look at infighting between active RaaS brands.

## What this means for defenders

Because KryBit's affiliates bring heterogeneous initial-access methods, there is no single IOC or exploited CVE to block upstream - detection has to anchor on the choke point every affiliate passes through regardless of entry vector: the pre-encryption shadow-copy-deletion command, typically paired with WMI/PsExec lateral movement in the hours beforehand. Since the encryptor targets Windows, Linux, ESXi, and NAS alike, backup and recovery posture for the hypervisor and storage layer matters as much as endpoint detection on Windows hosts.

*See also: [KryBit - Pre-Encryption Shadow Copy Deletion and Lateral Movement](/detections/krybit-ransomware/) for detection logic.*

**Sources:** [Halcyon - KryBit Threat Group Profile](https://www.halcyon.ai/threat-group/krybit), [Cyble - KryBit Ransomware Threat Actor Profile](https://cyble.com/threat-actor-profiles/krybit-ransomware-threat-actor/), [Infosecurity Magazine - Ransomware Turf War as 0APT and KryBit Groups Trade Blows](https://www.infosecurity-magazine.com/news/ransomware-turf-war-0apt-krybit/), [SOCRadar - Dark Web Profile: Krybit Ransomware](https://socradar.io/blog/dark-web-profile-krybit-ransomware/), [Picus Security - How KryBit Ransomware Works and How to Test Your Defenses](https://www.picussecurity.com/resource/blog/how-krybit-ransomware-works-and-how-to-test-your-defenses)

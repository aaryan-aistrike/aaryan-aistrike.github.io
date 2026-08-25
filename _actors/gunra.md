---
title: "Gunra / Golden Community - Conti-Derived RaaS Targeting Critical Infrastructure"
layout: default
---

## Who they are

Gunra is a double-extortion ransomware operation first observed in April 2025, built on ransomware source code leaked from the Conti gang in March 2022. What began as a single Conti-derived strain matured by January 2026 into a full ransomware-as-a-service platform - complete with a management panel, a configurable builder, cross-platform locker payloads, and an affiliate program advertising an 80% cut of extortion proceeds - operating under the additional branding "Golden Community." On 2026-08-10, CISA, the FBI, DC3, NSA, the U.S. Secret Service, and South Korea's National Police Agency issued a joint #StopRansomware advisory (AA26-222A) after a sharp rise in Gunra activity against healthcare, financial services, government, and nonprofit organizations worldwide.

## Behavioral pattern

- **Firewall auth-bypass as the primary entry point.** Affiliates exploit CVE-2024-55591 and CVE-2025-24472 - two FortiOS/FortiProxy authentication-bypass flaws - to obtain super-admin access on internet-facing Fortinet devices, then abuse a scheduled task on the compromised device to forge a new persistent superuser account with a hard-coded password.
- **Deliberate MFA neutralization.** In at least one documented intrusion, actors compromised an SSL-VPN admin account still using default credentials with no lockout policy, then modified authentication files on a corporate VDI portal so that a single Gunra-chosen one-time-password value would always authenticate successfully - defeating MFA outright rather than phishing around it.
- **Impacket-driven lateral movement.** Once inside, affiliates rely on Impacket's `psexec.py` and `smbclient.py` over SMB, RDP sessions built from harvested credentials, and pass-the-hash/pass-the-ticket techniques to pivot toward privileged systems - all built on legitimate protocols rather than custom implants.
- **Archive-then-exfiltrate tooling.** Data theft follows a consistent chain: stage and compress with 7-Zip or WinRAR, then move the archive out via RClone, FileZilla, or OpenSSH to Mega or an attacker-controlled FTP server - before encryption ever runs.
- **Recognizable encryption artifacts.** Encrypted files carry `.ENCRT`, `.CRYPT`, or `.GNRA` extensions, with a `R3ADM3.txt` ransom note dropped across shares and NAS volumes; victims are given 5-7 days to pay via a Tor negotiation portal before data is published on Gunra's leak site.
- **Possible North Korean tooling overlap.** South Korean researchers (AhnLab) identified shared SSH key fingerprints, tunneling infrastructure, and file-distribution domains between some Gunra incidents and a separate campaign using tooling associated with the Lazarus Group - though they explicitly stopped short of concluding a shared command structure, and Gunra's operating model remains that of a financially motivated criminal RaaS rather than confirmed state-directed activity.

## What this means for defenders

Gunra's entire initial-access strategy runs through two specific, patchable Fortinet CVEs rather than novel exploitation - which makes patch currency and internet-facing device inventory the single highest-leverage control against this actor. Once inside, the group's reliance on Impacket and legitimate remote-access tools means detection again has to focus on sequence and context (an Impacket-signature service installation, or an archive tool followed shortly by RClone/FileZilla execution) rather than any single indicator, since every individual tool in the chain has legitimate uses.

*See also: [Gunra Ransomware - Fortinet Auth-Bypass Initial Access](/detections/gunra-ransomware/) for detection logic.*

**Sources:** [CISA AA26-222A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-222a), [The Record](https://therecord.media/ransomware-south-korea-fbi-gunra), [The Hacker News](https://thehackernews.com/2026/08/gunra-ransomware-exploits-fortinet-and.html), [BleepingComputer](https://www.bleepingcomputer.com/news/security/us-warns-of-gunra-ransomware-attacks-against-government-critical-infrastructure/)

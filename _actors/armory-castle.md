---
title: "ARMORY CASTLE / UNC5221 - PRC-Nexus Espionage Actor Behind the BeyondTrust Remote Support Zero-Day"
layout: default
---

## Who they are

**ARMORY CASTLE** is a suspected PRC-nexus espionage actor that Google's Threat Intelligence Group (GTIG) and Mandiant have tracked since at least October 2023, previously under the designation **UNC5221**. CrowdStrike tracks the same cluster as **WARP PANDA**. The group has a sustained track record of exploiting edge-appliance vulnerabilities - most notably a string of Ivanti product flaws - rather than relying on phishing or commodity malware for initial access.

In its latest campaign, ARMORY CASTLE exploited **CVE-2026-102764**, a critical (CVSS 9.3) unauthenticated arbitrary-file-upload flaw in **BeyondTrust Remote Support** (formerly Bomgar), as a zero-day starting in late August 2026. BeyondTrust patched SaaS tenants on October 9 and shipped BT26-05 for self-hosted customers shortly after; GTIG and BeyondTrust jointly disclosed the campaign on October 15, 2026. BeyondTrust assesses the ARMORY CASTLE attribution with moderate-to-high confidence based on tooling and TTP overlap with prior tracked activity.

## Behavioral pattern

- **Edge-appliance zero-day specialization.** The group's operating model is built around finding and burning zero-days in internet-facing remote-access and privileged-access appliances - first Ivanti, now BeyondTrust - rather than phishing end users directly.
- **Minimal, evasive webshells.** The **SAWFLY** webshell (`mangoapi.php`) is a small obfuscated PHP implant that requires a specific POST parameter (`_c94mfe`) to respond at all; without it, the script returns a plain 404, which defeats generic webshell scanners. Traffic in both directions is Base32-encoded and RC4-encrypted with a hardcoded key.
- **Appliance-specific privilege escalation.** Rather than a generic Linux privilege-escalation exploit, the actor copied `/bin/sh` to a disguised path (`/usr/bin/dbus-authd`), set it root-owned with the SUID bit, and used it as a reusable root shell - a technique tailored to this specific appliance's filesystem layout.
- **Config-level persistence that survives resets.** Persistence was written directly into the appliance's own configuration templates (`/ns/config/sudoers.template` for passwordless sudo, `/ns/config/haproxy.conf` to route a disguised URI to a hidden tunneler) so it survives the kind of reboot or config-reset an administrator might use to "clean" the box.
- **Covert tunneling disguised as legitimate paths.** The **BARECLAW** tunneler is a C-based SOCKS5-over-WebSocket proxy, launched with logging disabled, and reached through a reverse-proxy ACL rule that makes its listener indistinguishable from normal support-portal traffic.
- **Proprietary credential-vault harvesting.** The actor used the appliance's own built-in CLI (`bt-secrets`) to dump both site-scoped and global password vaults, then deleted the CLI's own log files to cover the extraction.
- **Aggressive, continuous anti-forensics.** Rather than a single cleanup step, the actor repeatedly deleted auth, access, and error logs throughout the intrusion using sudo access obtained from the webshell - GTIG notes on-appliance logs from this campaign are broadly unreliable as a result.
- **Abuse of legitimate admin functionality for lateral movement.** Using a compromised Administrator account, the actor escalated a Jump Item/Team role from No Access to Administrator, then used built-in remote-support sessions and the file-transfer feature to reach internal endpoints and exfiltrate documents - no custom lateral-movement tooling required.

## What this means for defenders

ARMORY CASTLE's pattern - burn a zero-day in an edge appliance, escalate using the appliance's own binaries and config system, persist at the configuration-template layer rather than the OS layer, and scrub logs continuously - means that patching alone is not remediation once an appliance has been internet-reachable on a vulnerable version. GTIG's own guidance is to treat any exposed vulnerable instance as potentially compromised, rebuild from a clean image rather than clean in place, and rotate every credential type the appliance stores or brokers only *after* rebuilding. Given the group's history of broad, opportunistic follow-on exploitation once a vulnerability is public, organizations running BeyondTrust Remote Support (or any similar PAM/remote-access appliance) should assume scanning and exploitation attempts will continue well past the initial disclosure window.

*See also: [CVE-2026-102764 - ARMORY CASTLE Exploits BeyondTrust Remote Support Zero-Day](/detections/armory-castle-beyondtrust-zeroday/) for detection logic.*

**Sources:** [Google Cloud / Mandiant GTIG](https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-beyondtrust), [BleepingComputer](https://www.bleepingcomputer.com/news/security/beyondtrust-patches-zero-day-exploited-in-attacks-since-august/), [SC World](https://www.scworld.com/news/beyondtrust-zero-day-exploited-by-china-linked-group-armory-castle)

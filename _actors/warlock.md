---
title: "Warlock / Longlegs / Storm-2603 - China-Nexus Ransomware Exploiting SharePoint ToolShell Flaws"
layout: default
---

## Who they are

**Warlock** is the ransomware payload of a China-nexus intrusion set that Symantec tracks as **Longlegs** and Microsoft tracks as **Storm-2603**. The group first drew attention exploiting the Microsoft SharePoint "ToolShell" vulnerability chain (CVE-2025-49704, CVE-2025-49706, CVE-2025-53770, CVE-2025-53771) for mass opportunistic initial access in mid-2025. Reporting from late September and early October 2026 shows a deliberate pivot: rather than scanning broadly, the group is now hitting a small number of high-value critical-infrastructure targets - a water utility, a telecommunications provider, a regional government body, and a university - concentrated in Spanish- and Portuguese-speaking countries across Europe, Africa, and Latin America.

## Behavioral pattern

- **SharePoint exploitation for initial access.** Entry continues to run through the ToolShell SharePoint vulnerability chain, giving the group a foothold on internet-facing collaboration servers without needing phishing or credential theft.
- **BYOVD EDR killing at scale.** Abuses a vulnerable, signed driver (**K7RKScan**) to disable security tooling - in one documented intrusion, the group pushed the EDR-killing driver to at least 40 hosts within roughly two hours.
- **DLL sideloading.** Uses DLL sideloading against legitimate, signed binaries to execute and persist while evading detections tuned to flag unsigned or unknown executables.
- **Living-off-the-land remote access.** Abuses Visual Studio Code's built-in remote tunneling feature (`code tunnel`) as a covert C2/remote-access channel that blends into legitimate developer network traffic.
- **Active Directory as a distribution mechanism.** Stages the Warlock ransomware binary directly in the domain's SYSVOL share, letting ordinary Distributed File System Replication (DFSR) carry the payload to every domain controller and, from there, to member hosts - the same intrusion above deployed Warlock on at least 33 hosts this way.
- **Narrowing, deliberate targeting.** Recent victim selection favors critical infrastructure and public-sector organizations in Spanish/Portuguese-speaking regions over the indiscriminate ToolShell scanning waves seen in 2025, suggesting a shift toward fewer, more carefully chosen, higher-leverage targets.

## What this means for defenders

Because Warlock's distribution path abuses Active Directory's own replication mechanics, SYSVOL has to be monitored as a payload-delivery surface, not just a policy store - an unexpected executable or DLL appearing under `\SYSVOL\<domain>\scripts` or `\policies` is a strong signal regardless of which account or process wrote it. Driver-load events should be checked against a known-vulnerable-driver blocklist (Microsoft's own vulnerable driver blocklist policy, kept current, would have stopped the K7RKScan abuse outright), and VS Code tunnel usage from server infrastructure that has no business running developer tooling deserves scrutiny. Patching SharePoint against the ToolShell chain remains the cheapest control, since every observed intrusion still starts there.

*See also: [Warlock Ransomware - SYSVOL-Staged Deployment via Active Directory Replication](/detections/warlock-ransomware/) for detection logic.*

**Sources:** [The Hacker News](https://thehackernews.com/2026/10/warlock-exploits-sharepoint-flaws-to.html), [The Record](https://therecord.media/warlock-ransomware-used-in-critical-infrastructure-attacks), [Industrial Cyber (Symantec)](https://industrialcyber.co/ransomware/symantec-reports-warlock-ransomware-group-targets-water-telecom-government-organizations-through-sharepoint-flaws/), [SC World](https://www.scworld.com/brief/chinese-ransomware-group-warlock-targets-spanish-and-portuguese-speaking-countries)

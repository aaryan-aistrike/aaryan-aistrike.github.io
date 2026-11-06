---
title: "DeadLock - Blockchain-Concealed C2 Ransomware Operation"
layout: default
---

## Who they are

DeadLock is a financially motivated, Windows-focused ransomware operation first observed around July 2025 that went largely quiet for roughly 11 months before resurfacing and scaling sharply through mid-2026. Its defining trait is concealing parts of its victim-communication and recovery infrastructure inside **Polygon blockchain smart contracts** - a technique known as EtherHiding that researchers had previously documented mainly in North Korea-linked operations, not purely financially motivated ransomware. Microsoft's August 2026 analysis counted 80+ claimed victims; SOCRadar's October 2026 tracking put cumulative leak-site claims above 120, with over half concentrated in Europe (Spain, Italy, Poland, Türkiye, and the UK feature repeatedly across vendor reporting).

## Behavioral pattern

- **BYOVD EDR kill.** Cisco Talos documented a previously undocumented loader, tracked as EDRGay.exe, that drops a vulnerable signed Baidu Antivirus kernel driver (BdApiUtil.sys, disguised on disk as DriverGay.sys, CVE-2024-51324) and issues a DeviceIOControl call (IOCTL 0x800024b4) that the driver fails to privilege-check, letting it call ZwTerminateProcess against EDR/AV processes from kernel mode.
- **Compromised valid accounts, patient dwell time.** Talos assesses initial access comes through compromised valid accounts rather than exploitation, with roughly five days of dwell time between network access and ransomware deployment; AnyDesk is installed for persistent remote access, and lateral movement is conducted interactively via RDP/MMC rather than through scripted, wormable propagation.
- **Deliberately throttled Rust encryptor.** The encryptor is written in Rust and uses a custom stream cipher with process injection and a resource-aware dispatcher that paces itself to keep the host responsive during encryption - the opposite of the disk-I/O-saturating behavior most ransomware exhibits, which undercuts purely performance-anomaly-based detection. It also disables Windows Defender and backup services and clears event logs before encrypting; files get a per-victim suffix (e.g., `1.jpg.F8C6A8.dlock`) alongside a `HOW_RECOVER_<id>` note.
- **Blockchain-backed, takedown-resistant recovery infrastructure.** Victims are pointed to an HTML wrapper around the decentralized Session messenger. The wrapper resolves its current chat-proxy address via a read-only `eth_call` against a Polygon smart contract, and operators can fail over across six public Polygon RPC endpoints if one is seized or blocked - a deliberate design choice to blunt conventional infrastructure-takedown efforts (Microsoft notes it isn't fully takedown-proof, since the custom proxy and file hosting can still be disrupted).
- **Partial RaaS / affiliate overlap.** Microsoft observed at least one affiliate with prior ties to the Lynx and INC ransomware ecosystems, suggesting an affiliate-driven model rather than a single closed crew.
- **Low-confidence regional self-exclusion.** Samples reportedly self-delete on systems configured for Russian, Ukrainian, Belarusian, and several other CIS/Middle Eastern locales - consistent with, but not confirmation of, Russian-speaking operators; researchers (ProvenData, among others) explicitly flag attribution as low confidence.

## What this means for defenders

Standard ransomware defenses still apply, but DeadLock specifically targets two assumptions defenders often rely on: that EDR can't be killed from kernel mode by an unknown driver, and that seizing C2/leak infrastructure meaningfully disrupts an operation. Enforcing Microsoft's vulnerable-driver blocklist via WDAC with HVCI directly closes the BYOVD path, and the specific BdApiUtil.sys/CVE-2024-51324 driver-load event is a high-value, reusable detection even outside this group - BYOVD loaders get recycled across unrelated campaigns. Because the encryptor deliberately throttles itself to stay quiet, behavioral detections tuned purely to I/O-volume spikes may miss it; pair them with kernel-driver-load and AnyDesk-installation-after-valid-authentication signals instead.

*See also: [DeadLock - BYOVD EDR Kill Chain and Polygon Blockchain C2](/detections/deadlock-ransomware/) for detection logic.*

**Sources:** [Cisco Talos](https://blog.talosintelligence.com/byovd-loader-deadlock-ransomware/), [Group-IB](https://www.group-ib.com/blog/deadlock-ransomware-polygon-smart-contracts), [The Hacker News](https://thehackernews.com/2026/08/deadlock-ransomware-uses-polygon-smart.html), [Cyble](https://cyble.com/threat-actor-profiles/deadlock-ransomware/)

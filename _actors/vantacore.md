---
title: "VantaCore - Pro-Ukraine Ransomware Rebrand Targeting Russian Enterprises"
layout: default
---

## Who they are

**VantaCore** is a ransomware-as-a-service operation first observed conducting attacks in August 2026, though its data-leak site infrastructure appears to have been stood up as early as June 2026. Russian cybersecurity firm F6, which first documented the group, assesses with moderate confidence that VantaCore is a rebrand of **Thor**, a pro-Ukrainian hacktivist-ransomware operation that was among the more active groups targeting Russian organizations throughout 2025. Part of the attribution basis is unusually concrete: VantaCore's leak-site favicon renders the word "THOR" in runic lettering, alongside broader TTP and infrastructure overlap with the earlier group. So far, F6 has confirmed at least seven Russian corporate victims, with ransom demands reaching into the millions of dollars.

## Behavioral pattern

- **Motive shift from hacktivism to profit.** Where Thor mixed destructive/hacktivist intent with extortion against Russian targets, VantaCore runs as a straightforward, profit-driven affiliate-style RaaS - negotiating with victims over a Tor-based chat service and maintaining a leak site for double-extortion pressure.
- **Commodity initial access.** Entry is gained through poorly secured VPNs and remote-access tooling, vulnerabilities in internet-facing applications, and login credentials stolen from business partners - a third-party/supply-chain credential abuse path rather than novel exploitation.
- **Custom, purpose-built tooling.** Unlike many RaaS affiliates that lean on leaked builders (LockBit, Babuk, Conti), VantaCore uses an in-house toolset: **VantaCoreLoader** for at-scale payload distribution across a compromised network (propagation behavior resembling PsExec/WinExec and techniques associated with LockBit 3.0 Black), a **Go-based VantaCoreRAT** backdoor supporting recon, command execution, reverse shell, file transfer, and SOCKS5 proxying, and **SnowKiller**, a dedicated security-software-disabling tool.
- **Espionage-adjacent destructive sequence.** Documented behavior combines data theft before encryption, deliberate destruction or sabotage of backup infrastructure, encryption via a C++ payload using ChaCha20 + X25519, and post-encryption evidence cleanup - a sequence closer to a destructive intrusion than a pure smash-and-grab.
- **SMB/RDP lateral movement on legitimate accounts.** The group favors moving through victim networks using compromised, legitimate credentials over SMB and RDP rather than deploying additional malware for internal spread, which helps it blend into normal administrative traffic.

## What this means for defenders

VantaCore's profile is a reminder that "hacktivist" and "financially motivated" are not permanent labels - the same infrastructure and operators can pivot to a purely profit-driven RaaS model while keeping the destructive tradecraft (backup sabotage, evidence cleanup) that hacktivist campaigns tend to favor. Because the group deliberately targets backup infrastructure before encrypting, the detection window that matters most is the gap between security-tooling interference (SnowKiller execution) and backup/shadow-copy destruction commands - by the time encryption starts, recovery options have often already been removed. Organizations with any exposure to VantaCore's targeting profile (currently Russian enterprises, via VPN/remote-access exposure and third-party credential abuse) should treat AV/EDR tampering followed by backup-deletion activity as a near-certain ransomware precursor, not routine noise.

*See also: [VantaCore - Security-Tooling Interference Preceding Backup Destruction](/detections/vantacore-ransomware/) for detection logic.*

**Sources:** [The Record / Recorded Future News](https://therecord.media/new-pro-ukraine-hacker-group-custom-ransomware-russia), [mirror via hendryadrian.com](https://www.hendryadrian.com/new-pro-ukraine-hacker-group-targets-russian-companies-with-custom-ransomware/)

---
title: "Storm-2945 / Midnight Blizzard - CaptiveCrunch Hotel Wi-Fi Hijack Operators"
layout: default
---

## Who they are

Storm-2945 is a Russian threat cluster that Microsoft assesses operates as a sub-cluster of Midnight Blizzard (APT29 / Cozy Bear / NOBELIUM), the group publicly attributed by US and UK governments to Russia's SVR foreign intelligence service. Since May 2026, Storm-2945 has run a campaign Microsoft named **CaptiveCrunch**, which manipulates DNS and HTTP traffic on the shared captive-portal Wi-Fi services used by hotels and conference venues worldwide - rather than compromising each property individually. Manipulated sign-in pages redirect travelers, primarily corporate travelers whose accounts hold espionage value, to attacker infrastructure that mimics Microsoft 365 login flows for credential theft and malware delivery. Microsoft disclosed the campaign publicly on 2026-07-31.

## Behavioral pattern

- **Shared-infrastructure compromise over single-venue hits.** Rather than breaching individual hotels one at a time, Storm-2945 appears to have gained access to shared services within portions of the captive-portal ecosystem itself, letting a single compromise manipulate sign-in traffic across many venues at once.
- **Abuse of legitimate connectivity-check traffic.** The group exploits network-connectivity-status-indicator (NCSI) requests that Windows and browsers generate automatically on joining a new Wi-Fi network (e.g. to msftconnecttest.com) to trigger fake browser/OS update prompts and malware downloads - requiring no user action beyond connecting to the network.
- **Device-code and AiTM phishing for Microsoft 365.** Alongside malware delivery, victims are redirected to attacker domains spoofing Microsoft 365 (e.g. ms365-device[.]com, m365-owa[.]com) to harvest credentials via OAuth device-code flows and adversary-in-the-middle token theft - tradecraft consistent with other Midnight Blizzard sub-clusters' prior device-code phishing.
- **Custom, purpose-built malware.** Deploys **CornFlake**, a Go-based RAT with keylogging, clipboard/screenshot/audio/video capture, USB-drive monitoring, and ChromeKatz-derived Chrome App-Bound Encryption bypass for credential theft, alongside **ChocoShell**, an in-memory PowerShell infostealer that chains a three-layer UAC bypass (SilentCleanup task hijack, wsreset.exe COM hijack, sdclt.exe folder hijack) and beacons to C2 disguised as pixel-tracking requests.
- **Operator tooling with a legitimate-looking front.** Campaign infrastructure includes a web-based C2 panel ("FruitStone") branded as a "CloudSync Console" from a fictitious "Acuity Systems, Inc.," built for agent management, geographic victim mapping, and campaign configuration - notably professionalized tradecraft for tooling that never faces a victim directly.
- **Targets corporate travelers specifically.** Microsoft states the objective is gaining access to the accounts of corporate travelers, consistent with an espionage-motivated actor rather than a financially motivated one.

## What this means for defenders

Because the compromise sits at the network layer - the captive portal itself - individual travelers have no way to visually distinguish a manipulated hotel Wi-Fi sign-in page from a legitimate one, which makes this a policy and architecture problem more than a user-awareness one. Block device-code authentication flows via Conditional Access, require enterprise travelers to use mobile hotspots or MDM-issued travel routers instead of venue Wi-Fi, and route any unavoidable guest-network access through a Security Service Edge / Global Secure Access proxy so DNS and HTTP responses can't be silently rewritten in transit. On the endpoint side, the group's reliance on NCSI-triggered downloads and a specific UAC-bypass chain gives defenders concrete, non-network signals to hunt for even when the network-layer compromise itself is invisible.

*See also: [CaptiveCrunch - Hotel Wi-Fi Captive Portal Hijack](/detections/captivecrunch-hotel-wifi/) for detection logic.*

**Sources:** [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/), [The Hacker News](https://thehackernews.com/2026/08/hijacked-hotel-wi-fi-pushes-fake.html), [Zscaler ThreatLabz](https://www.zscaler.com/blogs/security-research/captivecrunch-midnight-blizzard-weaponizes-hotel-wi-fi-captive-portals)

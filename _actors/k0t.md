---
title: "k0t / CryptoFeel - Edge-Device Initial Access Broker Behind a 70,000-Credential FortiGate/GlobalProtect Campaign"
layout: default
---

## Who they are

**k0t** (also tracked under the handles CryptoFeel, Member19, and QazWsxShop) is an initial access broker first observed on 2025-10-22 and profiled in detail by Group-IB and NyxLab in a joint investigation published in October 2026, titled "Stray Cat, Open Doors: How k0t Wanders Through the Network Edge." Between February and June 2026, the actor ran a large-scale credential-harvesting campaign against internet-exposed FortiGate, FortiWeb, and Palo Alto GlobalProtect appliances, exposing more than 70,000 credentials tied to network devices, LDAP dumps, and related data. A number of victims subsequently appeared on the leak sites of the Qilin and The Gentlemen ransomware operations, though Group-IB is explicit that the relationship between k0t and those downstream operators remains unconfirmed - consistent with a broker model where access is harvested once and monetized by separate affiliate ecosystems rather than operated end-to-end by the same group.

## Behavioral pattern

- **Edge-device exploitation over endpoint malware.** Initial access came from exploiting CVE-2025-64446 (FortiWeb) and CVE-2026-0257 (Palo Alto GlobalProtect auth-bypass cookie forgery, also documented on this site as exploited by Qilin and INC Ransom), plus brute-forcing FortiGate SSL VPN logins - no phishing or custom loader was required to get a foothold.
- **Dual RMM/C2 infrastructure.** A self-hosted MeshCentral server at `mesh[.]buttruyen[.]com` managed roughly 84 compromised endpoints across 28 device groups, with agent binaries hosted separately at `agent[.]afahimsa[.]top`. AdaptixC2 ran alongside it as a second command-and-control channel.
- **Deliberately permissive agent onboarding.** The MeshCentral deployment was configured with `agentAutoApprove`, `agentAutoCreateDevice`, `IgnoreAgentHashCheck`, and `agentInviteCodes` enabled - minimizing the manual review step normally required to add a new victim device to the C2 fleet.
- **Commercial RMM abuse for persistence.** Atera, AnyDesk, Teramind, and ngrok were layered on top of the actor's own infrastructure, letting access blend into traffic patterns that look like legitimate remote support or monitoring tooling.
- **Cloud-hosted exfiltration.** Data was moved out with Rclone to commercial cloud storage - Wasabi and MEGA - rather than actor-controlled infrastructure, complicating both network-based blocking and takedown response.
- **Broker posture, not a confirmed ransomware operator.** Victims surfaced on both the Qilin and The Gentlemen leak sites, but Group-IB found only negligible credential overlap between the k0t dataset and the separate FortiBleed credential-harvesting campaign - a reminder not to collapse every Fortinet-targeting campaign in this window into a single actor.

## What this means for defenders

Because k0t's persistence layer is built almost entirely from legitimate RMM products and cloud storage services, detection has to focus on **the combination and sequence** of tools rather than any single indicator: MeshCentral agent, AdaptixC2, Atera, AnyDesk, Teramind, or ngrok installation on a host shortly before Rclone traffic to Wasabi or MEGA is a far stronger signal than any one of those tools appearing alone. Organizations running FortiGate, FortiWeb, or GlobalProtect at the network edge should treat unpatched or brute-forceable exposure on those appliances as a precursor not to one named ransomware brand, but to whichever affiliate ecosystem buys the resulting access.

*See also: [k0t Edge-Device Campaign - Credential Harvesting via FortiWeb and GlobalProtect Exploitation](/detections/k0t-edge-device-credential-theft/) for detection logic.*

**Sources:** [Group-IB - "Stray Cat, Open Doors: How k0t Wanders Through the Network Edge"](https://www.group-ib.com/blog/stray-cat-network-edge/), [GBHackers](https://gbhackers.com/k0t-credential-theft/), [SecurityOnline](https://securityonline.info/k0t-fortigate-globalprotect-attacks/)

---
title: "Turla / Secret Blizzard - Russian FSB-Linked Espionage Actor Behind the Cereal Exchange Mail-Interception Toolset"
layout: default
---

## Who they are

Turla - also tracked as Secret Blizzard (Microsoft), Snake, Uroburos, Venomous Bear, Waterbug, and Pensive Ursa - is one of the longest-running Russian state cyberespionage operations, active since at least the early 2000s. The US and Australian governments attribute the group to a unit within Center 16 of Russia's FSB, with daily operations historically traced to FSB facilities in Moscow and Ryazan. In November 2026, ESET researchers disclosed a previously undocumented Exchange-targeting toolset called **Cereal**, found on government mail servers in Kazakhstan (first observed 2025-11-28) and Romania, where operators used it to selectively collect email exchanged with NATO and EU representatives.

## Behavioral pattern

- **Decades of targeting Exchange mail infrastructure.** Cereal is the latest in a lineage that includes LightNeuron (an Exchange backdoor active since 2014 that hid commands in PDF/JPEG attachments) and Capibar/DeliveryCheck (deployed against Ukrainian defense targets via Exchange MOF files). Mail servers are a standing priority target, not an opportunistic one-off.
- **Novel in-memory transport-agent hijack.** The toolset's email-harvesting component, CerealBox, injects into `EdgeTransport.exe` - the process that moves mail through Exchange - and wraps the handlers of transport agents already loaded in memory, rather than registering a new agent. Exchange's agent configuration therefore looks unchanged even while mail is being intercepted; ESET states this specific technique has not been documented in any other malware family.
- **No reliance on external C2 for collection.** ESET found no dedicated outbound command-and-control infrastructure tied to CerealBox - the component operates and is tasked largely from within the compromised server itself, removing a common detection surface (anomalous outbound beaconing).
- **Selective, intelligence-driven harvesting.** Rather than bulk exfiltration, operators configured the malware to collect messages carrying document attachments (`.doc`, `.docx`, `.pdf`) and, in the Romanian intrusion, specifically messages exchanged with NATO and EU contacts - behavior consistent with targeted diplomatic intelligence collection rather than financially motivated theft.
- **Disguised on-demand tasking channel.** A companion component, CerealNeuron, listens for incoming encrypted web requests on URL paths crafted to resemble legitimate Exchange service endpoints, giving operators a command channel that blends into normal webmail/OWA-adjacent traffic.
- **Long-standing use of hijacked third-party infrastructure.** Turla has a documented history of relaying through compromised websites, WordPress instances, peer-to-peer networks, and even satellite links to obscure operator origin - consistent with a mature state intelligence service protecting its own attribution.

## What this means for defenders

Because CerealBox hides by wrapping existing, already-trusted transport-agent handlers instead of registering a new one, **configuration-based auditing of Exchange transport agents will not catch it** - defenders need process- and module-level visibility into `EdgeTransport.exe` itself (unexpected module loads, unsigned or unexpected assemblies, anomalous injected threads) rather than relying on `Get-TransportAgent` output looking clean. The absence of conventional C2 traffic also means network-centric detection will miss this family; the signal has to come from the host.

*See also: [Cereal / CerealBox - Turla's In-Memory Exchange Transport-Agent Hijack for Email Espionage](/detections/turla-cereal-exchange/) for detection logic.*

**Sources:** [ESET Research](https://www.welivesecurity.com/en/eset-research/exchange-for-breakfast-turlas-cereal-tricks-are-not-for-kids/), [BleepingComputer](https://bleepingcomputer.com/news/security/turla-hackers-use-new-ceral-malware-to-spy-on-govt-exchange-servers), [Security Affairs](https://securityaffairs.com/202800/apt/russia-linked-apt-turla-turned-exchange-servers-into-their-own-control-room.html), [Help Net Security](https://www.helpnetsecurity.com/?p=390766)

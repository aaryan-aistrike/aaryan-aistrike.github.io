---
title: "Exilware - Brazilian Initial Access Broker Behind the BraZetsu Marketplace"
layout: default
---

## Who they are

Exilware is a Brazilian-nexus initial access broker (IAB) operation that has run an underground service since February 2026, selling remote access to compromised Windows hosts to other criminals through a marketplace known as the "Infected Marketplace" (also called "Banco de Infects"), with entry deposits as low as $5.80. Its primary technical engine is BraZetsu, a modular Python-based malware framework first observed in early May 2026 and attributed to Exilware with high confidence by Group-IB, based on shared codebase, infrastructure, and tradecraft overlap with a related tool tracked as AgenteV2.

## Behavioral pattern

- **Access-as-a-service, not data theft.** Rather than monetizing stolen data directly, Exilware turns compromised hosts into tradable inventory - buyers purchase remote execution rights on machines they never had to compromise themselves.
- **AI-assisted victim triage.** BraZetsu profiles each infected host's hardware, software inventory, and network footprint, then uses generative AI to automatically score and price the machine's commercial value for the marketplace.
- **LATAM social-engineering tradecraft.** Delivery relies on a loader masquerading as Microsoft Edge, distributed from lookalike domains (e.g. `caixaentradas1inboxshop[.]site` - Portuguese for "inbox"), with VBScript files fetching the next stage.
- **Real-time banking fraud support.** The malware streams the victim's screen to the operator live whenever a banking portal is detected open, enabling active fraud rather than just offline credential harvesting.
- **Broad, sector-agnostic reconnaissance.** BraZetsu enumerates 20+ target categories - financial/banking systems, ERP platforms (TOTVS, SAP, Sankhya, Senior), SCADA, government, cryptocurrency, and healthcare - reflecting a strategy of casting a wide net and letting marketplace buyers pick their own targets.
- **Low-friction, resilient C2.** Configuration is fetched from Pastebin and decoded with Base64/XOR obfuscation (v1) or a hardcoded secret key (v2), with communication running over a persistent WebSocket rather than a bespoke protocol.
- **Regional focus with deliberate reach.** Primary targeting spans Brazil, Argentina, and Paraguay alongside Iberian-language targets in Portugal and Spain - following linguistic and cultural affinity rather than pure geographic proximity.

## What this means for defenders

Because BraZetsu functions as an access broker's toolkit rather than a single-purpose stealer, a successful infection is the start of an auction, not an end state - the actual payload a given host ends up with depends on whichever buyer purchases access, and that varies case to case. Detection has to focus on the initial-access chain itself (fake-Edge loaders from lookalike domains, VBScript-launched script interpreters, and the WebSocket/Pastebin config-fetch pattern) rather than waiting for a predictable second-stage payload. Organizations running Brazilian/LATAM-market ERP software (TOTVS, Sankhya, Senior) should also treat unexplained process access to those install directories as high-signal, since BraZetsu specifically enumerates them during its victim-value scoring.

*See also: [BraZetsu - AI-Enhanced Initial Access Broker Framework](/detections/brazetsu-malware/) for detection logic.*

**Sources:** [Group-IB](https://www.group-ib.com/blog/brazetsu-ai-enhanced-iab-marketplace/), [The Hacker News](https://thehackernews.com/2026/09/brazetsu-malware-turns-compromised.html), [Cybersecurity News](https://cybersecuritynews.com/hackers-use-ai-malware/), [GBHackers](https://gbhackers.com/ai-enhanced-brazetsu-malware/)

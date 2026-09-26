---
title: "Storm-2992 - Developer and Operator of the EvilTokens Device-Code Phishing-as-a-Service Kit"
layout: default
---

## Who they are

Storm-2992 is the Microsoft-tracked cluster behind **EvilTokens**, an AI-powered phishing-as-a-service (PhaaS) platform that emerged in February 2026 and rapidly became one of the most widely used kits for OAuth device-code phishing. Rather than running intrusions itself, Storm-2992 built and sold the tooling - a subscription product priced at roughly $1,500 up front plus $500/month, with paid add-ons (an "Antibot" redirector, a "B2B Sender" module, and an "Office 365 Capture Link" tool) - and marketed it to other criminals over public and private Telegram channels. Customers used it to run business email compromise (BEC) campaigns that Microsoft says compromised more than 12,000 inboxes across over 10,000 organizations worldwide before a September 2026 disruption.

## Behavioral pattern

- **Toolmaker, not operator.** Storm-2992's business is building and maintaining the phishing kit and infrastructure; the actual intrusions and follow-on BEC fraud are carried out by whichever customer purchases access, spreading real-world impact across a wide, decentralized customer base.
- **Subscription commercialization with upsells.** A tiered pricing model (base subscription plus paid add-ons for antibot evasion, bulk sending, and specific cloud-capture targeting) mirrors legitimate SaaS go-to-market rather than a one-off malware sale.
- **AI-assisted lure generation.** The platform includes a built-in AI assistant that helps affiliates draft target-specific phishing emails (invoice, RFP, and shared-file themes), lowering the skill bar for convincing lures.
- **Anti-detection infrastructure engineering.** A April 2026 campaign observed by Microsoft used thousands of unique, short-lived polling nodes running Node.js backend logic specifically to defeat signature- and pattern-based detection of the kit's device-code polling traffic.
- **OAuth abuse over credential theft.** The kit's core technique - hijacking the OAuth 2.0 device authorization grant flow - lets affiliates gain full account access without ever needing the victim to type a password, sidestepping classic phishing-page credential capture entirely.
- **Global, opportunistic customer base.** Because targeting decisions are made by individual paying customers rather than centrally, victims span a wide range of industries (wholesale distribution, construction, financial services, real estate, higher education, healthcare) and countries (heaviest in the US, Canada, UK, Australia, India, and France).

## What this means for defenders

Because EvilTokens is a toolkit used by many independent customers rather than a single actor's campaign, IOC-based blocking (specific domains, senders, or lure text) will always lag behind the next affiliate's infrastructure. The durable detection surface is the *technique* - OAuth device-code authentication itself is rare in most corporate environments outside specific headless-device scenarios, so any device-code sign-in followed by suspicious follow-on activity (new device registration, inbox rule creation, high-volume Graph API calls) is high-value signal regardless of which customer or campaign generated it. Microsoft's September 2026 legal takedown disrupted this specific operator's infrastructure, but the device-code-flow abuse technique itself will keep resurfacing in other kits.

*See also: [EvilTokens - AI-Powered Device-Code Phishing-as-a-Service](/detections/eviltokens-device-code-phishing/) for detection logic.*

**Sources:** [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/), [The Hacker News](https://thehackernews.com/2026/09/microsoft-takes-down-eviltokens-device.html), [Sekoia](https://blog.sekoia.io/new-widespread-eviltokens-kit-device-code-phishing-as-a-service-part-1/)

---
title: "Storm-3075 - AI-Brand Malvertising Initial Access Broker"
layout: default
---

## Who they are

**Storm-3075** is a financially motivated initial access broker (IAB) tracked by Microsoft that has run large-scale malvertising and SEO-poisoning campaigns since at least March 2026, weaponizing the trust and hype around generative-AI brands - ChatGPT, Microsoft Copilot, Claude, and DeepSeek - to push fake "AI plugin" and "AI installer" downloads. Rather than operating stolen access itself, Storm-3075 sells or hands off the resulting infections to multiple downstream actors, functioning as a payload-delivery layer for the broader cybercrime ecosystem.

## Behavioral pattern

- **AI-brand impersonation at scale.** Uses fictitious product names such as "Awesome AI Windows Plugin" and "Flux Pro AI," plus installers spoofing DeepSeek, ChatGPT, and Claude branding, to make malicious downloads look like legitimate AI tooling.
- **Malvertising + SEO poisoning.** Places malicious ads on free movie-streaming sites and poisons search results/GitHub so poisoned download pages and repos surface ahead of legitimate sources.
- **Exploiting AI news cycles in near-real-time.** Within roughly 45 minutes of DeepSeek publicly previewing its V4 model in April 2026, Storm-3075 had already stood up a fake "DeepSeek-V4" GitHub organization loaded with stolen branding to distribute a trojanized "release."
- **Code-signing-as-a-service.** Final payloads are signed using certificates obtained through Fox Tempest's malware-signing operation, letting the binaries pass signature-based trust checks that many endpoint controls rely on.
- **Broker, not operator.** Distributes final payloads - Vidar Stealer, Lumma Stealer, Hijack Loader, Oyster, and SilabRAT - on behalf of multiple downstream actors rather than monetizing the access itself.
- **Real scale.** A single campaign wave (2026-03-10 to 2026-03-14) built around the "Awesome AI Windows Plugin" lure reached over 66,000 devices globally, with Japan, South Africa, the United States, and France hit hardest.

## What this means for defenders

Storm-3075's entire model depends on the assumption that "AI-branded" and "signed" both read as trustworthy. Neither holds here: the payloads are code-signed through a paid signing-as-a-service pipeline specifically to defeat that trust signal, and legitimate AI vendors (OpenAI, Anthropic, Microsoft, DeepSeek) do not distribute their consumer products as third-party "Windows plugin" installers found via search ads or GitHub side-projects. Because Storm-3075 is a pure distribution layer, the payload family a given victim receives varies by rotation - defenses tuned to one specific stealer or loader will miss the next wave. The durable signal is the delivery pattern itself: a browser-downloaded, AI-branded installer executed from a Downloads/Temp path, shortly followed by outbound connections to newly registered infrastructure.

*See also: [Storm-3075 - AI-Brand Malvertising Payload Delivery](/detections/storm-3075-ai-malvertising/) for detection logic.*

**Sources:** [Microsoft Security Blog - Detect and disrupt AI-themed attacks with Microsoft Defender (Sept 2026)](https://www.microsoft.com/en-us/security/blog/2026/09/10/detect-and-disrupt-ai-themed-attacks-with-microsoft-defender/), [Microsoft Security Blog - AI brands as bait (June 2026)](https://www.microsoft.com/en-us/security/blog/2026/06/08/ai-brands-as-bait-how-threat-actors-are-using-the-ai-hype-in-social-engineering/), [CyberPress - Cybercriminals Abuse AI Brand Trust](https://cyberpress.org/ai-brands-fuel-phishing/)

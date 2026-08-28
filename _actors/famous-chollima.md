---
title: "Famous Chollima / Jasper Sleet - DPRK Fraudulent Remote IT Worker Scheme"
layout: default
---

## Who they are

Famous Chollima (CrowdStrike's name; tracked by Microsoft as **Jasper Sleet**, formerly Storm-0287) is a North Korean state-sponsored operation, linked to the broader Lazarus Group ecosystem, in which DPRK-trained IT workers use stolen and fabricated identities to get hired as remote developers, IT staff, and contractors at Western companies. The scheme has run since at least 2020 and generates hard-currency revenue for the regime - UN estimates put it at up to $600 million a year - while simultaneously creating a long-term insider-access foothold inside victim companies' networks. CrowdStrike attributes 47% of all state-backed activity targeting the tech sector between April 2025 and May 2026 to this cluster, tracking 320+ incidents in the trailing 12 months (+220% year-over-year) across 100+ infiltrated companies, most of them US-based technology firms. US DOJ cases describe domestic "laptop farm" facilitators enabling fraudulent hires at 100+ companies using roughly 80 stolen American identities, netting over $5 million.

## Behavioral pattern

- **AI-assisted identity fabrication.** Real-time deepfake face-swapping tools (e.g., Faceswap) during video interviews, paired with forged or stolen identity documents and AI-generated resume photos, to pass as a legitimate US-based applicant.
- **Interview-cheating tooling.** Browser extensions such as Simplify Copilot, AiApply, and Final Round AI auto-fill job applications and feed real-time answers during live technical interviews.
- **Laptop farms.** US-based facilitators physically host company-issued laptops so the fraudulent "employee" can appear to log in domestically, while the actual operator connects from DPRK-controlled infrastructure abroad, typically routed through residential proxies to match the expected US geolocation.
- **Layered, unattended remote access.** Operators deploy Google/Chrome Remote Desktop via PowerShell or command line with a fixed, often trivial PIN (observed as "123456" in one documented case) and layer it on top of AnyDesk - giving concurrent, persistent, low-friction control of the "employee" endpoint in a way that's hard to distinguish from ordinary remote-work tooling.
- **OTP interception.** Browser extensions such as OTP.ee and Authenticator.cc capture and replay one-time passcodes tied to the rented or stolen identity, defeating MFA on corporate accounts.
- **Multi-employment at scale.** Individual operators simultaneously hold several remote positions across different companies to maximize both revenue and network access per stolen identity.
- **Independently verified via honeypot.** In a five-week operation running June-July 2026, researchers Mauro Eldritch and Heiner García stood up a fake crypto startup ("Ballena Azul") and knowingly hired three suspected Famous Chollima-linked developers into monitored virtual desktops, directly observing this tradecraft live rather than reconstructing it after the fact.

## What this means for defenders

Because the entry vector is the hiring pipeline rather than a technical exploit, detection has to extend past the SOC into Day-1 endpoint behavior and identity verification, not just network telemetry. A newly provisioned remote employee's endpoint running two independent remote-access tools concurrently (e.g., AnyDesk alongside Chrome Remote Desktop), or Chrome Remote Desktop being set up via unattended PowerShell/CLI rather than its normal interactive install flow, is a strong anomaly specific to this tradecraft rather than routine IT behavior. HR and IT onboarding should also flag conflicting shipping/banking/timezone details, refusal of live video verification, and VPN/proxy usage inconsistent with the claimed location as pre-hire signals - by the time technical controls catch the intrusion, the identity is often already inside payroll systems and VPN groups.

*See also: [Famous Chollima / Jasper Sleet - Concurrent Remote-Access Tooling on Newly Onboarded Endpoints](/detections/famous-chollima-it-worker-fraud/) for detection logic.*

**Sources:** [CrowdStrike - Famous Chollima Adversary Profile](https://www.crowdstrike.com/en-us/adversaries/famous-chollima/), [Microsoft Security Blog - Jasper Sleet](https://www.microsoft.com/en-us/security/blog/2025/06/30/jasper-sleet-north-korean-remote-it-workers-evolving-tactics-to-infiltrate-organizations/), [The Hacker News - Ballena Azul fake crypto startup](https://thehackernews.com/2026/08/researchers-built-fake-crypto-startup.html), [CSO Online](https://www.csoonline.com/article/3481659/north-korean-group-infiltrated-100-plus-companies-with-imposter-it-pros.html), [TechCrunch](https://techcrunch.com/2026/06/10/north-koreans-behind-nearly-half-of-us-tech-industry-hacks-says-crowdstrike/)

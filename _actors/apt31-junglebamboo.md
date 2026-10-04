---
title: "APT31 / JungleBamboo - Chinese MSS-Linked IP Theft Actor Behind the LONGTALE Browser Implant"
layout: default
---

## Who they are

APT31 (also tracked as JungleBamboo, Violet Typhoon, TA412, Judgement Panda, Zirconium, Bronze Vinewood, and RedBravo) is a Chinese state-sponsored espionage group assessed to have been active since at least 2010. In March 2024 the US Department of Justice unsealed an indictment charging seven PRC nationals linked to the group, alleging a 14-year campaign of computer intrusions tied to Wuhan Xiaoruizhi Science & Technology, a company prosecutors describe as a front for China's Ministry of State Security. The group's long-standing focus is intellectual-property theft and political intelligence collection - targeting government, aerospace and defense, telecommunications, and critics of the Chinese government - rather than financially motivated crime. In a campaign first documented by Volexity on 2026-09-09, APT31/JungleBamboo was one of (at least) four China-nexus clusters observed independently weaponizing a shared Chrome/Windows zero-day exploit chain ("BlueMoon") since around 2026-08-28, this time to deploy a credential-stealing malicious browser extension against NGOs, mining companies, and US commodity trading firms.

## Behavioral pattern

- **Decade-plus persistence with a broad identity list.** The group is tracked under at least seven different vendor-assigned names, reflecting over ten years of continuous, multi-vendor-observed activity - a hallmark of a mature, well-resourced state-sponsored operation rather than an emerging crew.
- **IP and economic-intelligence targeting.** Historically focused on sectors - aerospace, high-tech, construction/engineering, telecommunications - and victims whose data provides Beijing and Chinese state-owned enterprises a political, economic, or military edge, consistent with its DOJ-alleged mandate.
- **Opportunistic adoption of shared exploit infrastructure.** Rather than developing or exclusively holding the BlueMoon Chrome/Windows zero-day chain, APT31/JungleBamboo adopted the same shared exploit code used by at least three other China-nexus clusters within days of its public emergence - prioritizing speed of adoption over operational exclusivity.
- **Browser-native implant over classic backdoor.** Where other clusters using the same exploit chain dropped a traditional in-memory JScript backdoor, APT31/JungleBamboo's payload - delivered via a loader dubbed SUPERSTOMP - is a malicious Chrome extension (tracked as LONGTALE/GemStone) that masquerades as a "Google Gemini" assistant extension.
- **Integrity-check forgery, not developer-mode abuse.** SUPERSTOMP installs the malicious extension by tampering with Chrome's `Secure Preferences` file directly: it strips existing integrity hashes, registers the rogue extension, forges valid legacy HMAC values for the modified state, and lets Chrome's own migration logic re-encrypt the tampered preferences under the current integrity scheme - silently authenticating the extension without triggering Chrome's "disabled extension" warning or requiring Developer Mode.
- **Full browser-session surveillance.** Once installed, LONGTALE logs every keystroke, captures form data, steals cookies and session-storage tokens, and takes screenshots when attacker-supplied keywords appear on screen - giving the operator session-hijacking-grade access to whatever accounts the victim is logged into, not just standalone credential theft.

## What this means for defenders

Because LONGTALE rides in as a seemingly legitimate, Chrome-Web-Store-styled extension rather than a standalone executable, endpoint controls that only watch for new processes or files on disk will miss it entirely - the detectable moment is the anomalous write to the browser profile's `Secure Preferences` state file by a process other than Chrome's own update mechanism, and the appearance of a newly enabled extension ID the organization did not deploy via policy. Treat any AI-assistant-branded browser extension with broad `cookies`, `webRequest`, or `<all_urls>` permissions as worth verifying against an enterprise extension allowlist, especially in the weeks following disclosure of a patch-gap browser zero-day.

*See also: [SUPERSTOMP/LONGTALE - Malicious Chrome Extension Sideloaded via Secure Preferences Tampering](/detections/apt31-longtale-chrome-extension/) for detection logic.*

**Sources:** [Volexity](https://www.volexity.com/blog/2026/09/09/mind-the-patch-gap-multiple-chinese-threat-actors-chain-0-day-exploits-in-chrome-windows/), [The Hacker News](https://thehackernews.com/2026/09/china-linked-hackers-exploit-chrome.html), [Security Affairs](https://securityaffairs.com/199104/apt/one-exploit-chain-two-espionage-campaigns-chrome-and-windows-under-fire.html), [GBHackers](https://gbhackers.com/china-linked-hackers-chain-chrome-zero-day/)

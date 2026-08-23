---
title: "Sapphire Sleet - Supply Chain & Credential Theft Tradecraft"
layout: default
---

## Who they are

Sapphire Sleet is a Microsoft-tracked threat actor associated with the June 2026 Mastra npm supply chain compromise, in which 141+ packages in the `@mastra` scope were republished with a malicious injected dependency after a maintainer account takeover. The group's observed tradecraft centers on **software supply chain access as an initial-access vector**, followed by broad credential and cryptocurrency-wallet theft rather than immediate destructive action.

## Behavioral pattern

- **Access acquisition over exploitation.** Rather than finding a new vulnerability, the group took over a legitimate, trusted publisher account whose access had never been revoked after an earlier compromise - the path of least resistance into a high-trust distribution channel.
- **Indirection through dependencies.** The compromised packages themselves were left unmodified; the payload arrived through a single typosquatted dependency (`easy-day-js` mimicking `dayjs`) injected into each package's manifest. This keeps the "primary" package clean under casual review while still executing on every install.
- **Install-time execution.** The payload ran from a `postinstall` lifecycle hook, executing automatically before a developer ever imported or ran the package - maximizing blast radius with minimal attacker effort per victim.
- **Broad, opportunistic collection.** Once running, the payload harvested browser data across three browser families and credentials from 166 distinct cryptocurrency wallet extensions - a wide net rather than a targeted objective, consistent with monetization-driven rather than espionage-driven motives.
- **Speed and automation.** The entire republish campaign across 140+ packages executed in roughly 88 minutes, indicating tooling built for scale rather than manual, package-by-package operation.

## What this means for defenders

Sapphire Sleet's pattern rewards organizations that treat the **dependency graph itself as untrusted input** - diffing lockfiles in code review, restricting lifecycle script execution in CI, and monitoring for unexpected network/credential-store access originating from package manager processes during install (not just at application runtime). Revoking stale publish access after any account-security event is the specific control that would have prevented this campaign's initial foothold.

*See also: [Mastra npm Supply Chain Compromise](/detections/mastra-npm-supply-chain/) for detection logic.*

**Sources:** [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/06/17/postinstall-payload-inside-mastra-npm-supply-chain-compromise/), [Socket.dev](https://socket.dev/blog/mastra-npm-packages-compromised), [The Hacker News](https://thehackernews.com/2026/06/144-mastra-npm-packages-compromised-via.html)

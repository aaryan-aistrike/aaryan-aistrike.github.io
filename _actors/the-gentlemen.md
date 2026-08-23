---
title: "The Gentlemen - Fast-Scaling RaaS Affiliate Tradecraft"
layout: default
---

## Who they are

The Gentlemen is a ransomware-as-a-service operation that emerged around mid-2025 and became the single most active ransomware threat actor in Q2 2026 - claiming 328+ victims in the first five months of the year (~10% of all global ransomware claims in that window) and 580 victims across 77 countries by early July. Its growth rate - nearly doubling attack volume month-over-month early in 2026 - outpaced every previously tracked group.

## Behavioral pattern

- **Living-off-the-land lateral movement.** Rather than deploying custom malware for internal spread, affiliates use legitimate administrative tools - AnyDesk and PsExec - which blend into normal admin activity and evade tooling tuned to catch custom binaries.
- **Commodity initial access.** Entry is gained through internet-facing RDP, SSL VPN endpoints, and remote management tools - exposure categories that are common, well-understood, and preventable, rather than novel exploitation.
- **Deliberate cross-platform reach.** The group maintains separate lockers for Windows, Linux, NAS, BSD, and ESXi, letting a single intrusion encrypt an organization's entire infrastructure footprint - not just Windows endpoints - in one operation. This is a meaningful investment in tooling breadth relative to most RaaS operations.
- **Double extortion at volume.** Aggressive, high-volume double-extortion campaigns (encrypt + leak-site pressure) across a broad range of sectors and regions, prioritizing throughput over selective, high-value targeting.
- **Geographic self-restriction.** An internal prohibition against targeting CIS-region organizations, consistent with affiliates operating out of Russian-speaking regions and avoiding local law-enforcement attention.
- **Operational exposure.** A May 2026 breach of the group's own backend infrastructure gave researchers an unusually detailed, verified look at how the affiliate program and tooling actually function - a rare window into RaaS internals.

## What this means for defenders

Because the group's core lateral-movement tools are legitimate and ubiquitous, detection has to focus on **sequence and context** rather than tool presence: AnyDesk or PsExec execution shortly after an external RDP/VPN authentication event is a far stronger signal than either indicator alone. The group's deliberate multi-OS locker strategy also means Linux, NAS, and ESXi telemetry need the same detection investment as Windows - a Windows-only posture leaves exactly the infrastructure layer this group targets uncovered.

*See also: [The Gentlemen - Fast-Scaling Cross-Platform RaaS](/detections/the-gentlemen-ransomware/) for detection logic.*

**Sources:** [Check Point Research](https://research.checkpoint.com/2026/thus-spoke-the-gentlemen/), [Halcyon](https://www.halcyon.ai/ransomware-research-reports/threat-assessment-the-gentlemen-ransomware-group), [The Cyber Express](https://thecyberexpress.com/the-gentlemen-ransomware-group/)

---
title: "Lazarus Group / Operation Dream Job - DPRK Zero-Day Recruitment-Lure Intrusions"
layout: default
---

## Who they are

**Lazarus Group**, North Korea's long-running state-sponsored threat actor, runs "Operation Dream Job" - a years-long campaign umbrella built on fake recruiter personas rather than a single one-off lure. In a wave Check Point Research observed since at least early July 2026, the group impersonated recruiters from **Enveil**, a real US privacy-enhancing-technology company, to approach employees at defense, aerospace, and aviation organizations across Europe and India - then paired that social-engineering trust with a genuine Windows zero-day rather than a commodity exploit.

## Behavioral pattern

- **Recruiter-lure social engineering impersonating a real, named company.** Posing as Enveil recruiters lends outreach a credibility that generic front companies don't have, since a target can (and often does) verify the company is real - just not that the specific contact is.
- **Trojanized PDF viewer as the delivery vehicle.** Targets are led to install "SecurityPDF," a modified PDF viewer that opens attacker-crafted documents and executes a previously undocumented backdoor Check Point named **Troy**.
- **A genuine unpatched kernel vulnerability, not Bring-Your-Own-Vulnerable-Driver.** Troy exploits **CVE-2026-68820**, a use-after-free race condition in `AFD.sys` (the Ancillary Function Driver for Winsock), to escalate from limited user access to SYSTEM - notable because Lazarus' earlier FudModule campaigns typically dropped a vulnerable third-party driver to abuse; here they used a real, previously unknown flaw in a built-in Windows driver.
- **FudModule v3.1 for defender-blinding, not data theft.** Post-exploitation, the group deploys the latest version of its kernel-mode rootkit to tear down telemetry callbacks, kill roughly 94 ETW providers, suppress crash dumps, and disable security products generically - prioritizing staying invisible over immediate objectives.
- **Fast, disclosed timeline.** Check Point reported the vulnerability to Microsoft on 2026-07-28; Microsoft confirmed it three days later and shipped a fix on 2026-08-11 as part of that month's Patch Tuesday - meaning the flaw was exploited in the wild for roughly six weeks before any patch existed.
- **Consistent sector focus.** Defense, aerospace, and aviation organizations in Europe and India - continuing Lazarus' long-standing interest in the defense-industrial base via fabricated recruitment.

## What this means for defenders

Because CVE-2026-68820 is now patched, the single highest-leverage action is confirming that patch (2026-08-11 Patch Tuesday) is actually deployed - any Windows 11 24H2/25H2 host still missing it remains exposed to a now publicly detailed exploitation chain. Beyond patching, the campaign has two independently detectable stages regardless of patch status: the trojanized-PDF-viewer delivery, which unsolicited-recruiter-contact awareness and installer-source restrictions can catch before execution, and the post-exploitation EDR-blinding stage, where the *absence* of expected telemetry (mass ETW provider shutdowns, crash-dump suppression) is itself a strong signal even when the initial compromise slips past prevention.

*See also: [Lazarus Group - AFD.sys Zero-Day & FudModule Deployment](/detections/lazarus-fudmodule-afdsys-zeroday/) for detection logic.*

**Sources:** [Check Point Research](https://research.checkpoint.com/2026/shattering-the-dream-when-a-job-offer-becomes-a-zero-day-attack/), [The Hacker News](https://thehackernews.com/2026/08/lazarus-exploits-windows-zero-day-to.html), [BleepingComputer](https://www.bleepingcomputer.com/news/security/lazarus-hackers-exploited-windows-zero-day-to-target-defense-firms/)

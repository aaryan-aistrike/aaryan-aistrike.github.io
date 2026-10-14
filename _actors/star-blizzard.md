---
title: "Star Blizzard / SEABORGIUM - Russian FSB-Linked Credential Phishing and Espionage Actor"
layout: default
---

## Who they are

**Star Blizzard** (also tracked as SEABORGIUM) is a Russian state threat actor that CISA attributes as subordinate to the FSB's Centre 18. The group has run sustained cyberespionage against Ukrainian individuals and institutions, plus international NGOs, Western think tanks, governments, policy organizations, and financial institutions that support Ukraine. It is one of the more persistent credential-phishing actors publicly tracked, and it regularly overhauls its tradecraft the moment a prior chain gets burned by public disclosure - most recently replacing its ClickFix-style delivery chain with a new technique Microsoft calls **RedFlick**, detailed in a September 29, 2026 report.

## Behavioral pattern

- **Rapid tradecraft churn.** The group has run at least 13 distinct large-scale campaigns since January 2026, each with a materially different lure and delivery chain - tax-audit notices, fine-payment demands, fake conference invitations (IISS, Chatham House, Atlantic Council), M&A session lures, and a forged Kyiv water-shutdown notice targeting hotels.
- **Shift to mass-mailing.** Moved from narrowly targeted spear-phishing to large-scale initial-contact campaigns of tens to hundreds of emails per wave, likely via a mass-mailing platform, trading precision for reach.
- **Compromised-site phishing infrastructure.** Since March 2026 (high confidence), the group sends phishing from accounts on compromised cPanel and WordPress sites rather than free email providers, reducing reliance on infrastructure that gets blocklisted quickly.
- **RedFlick delivery chain.** Reduced victim interaction from a multi-step ClickFix chain down to a single click, using scheduled tasks (observed names include *Internet Quality Test Connection*, *Network Configuration Manager*, and *System Health Monitor*) to stage and launch a Control Panel applet (CPL) downloader - tracked as NOROBOT/BAITSWITCH - which in turn deploys the **CosmicPulse** (aka YESROBOT) Python backdoor.
- **Steganographic and living-off-the-land tricks.** A mid-August 2026 campaign hid identifiers via steganography; other chains abuse `ssh.exe` with `PermitLocalCommand`, `curl` from LNK files, and `control.exe` to launch the CPL downloader - all legitimate Windows binaries repurposed for delivery.
- **Broad but concentrated victimology.** Microsoft observed the activity affecting over 100 organizations, concentrated in the United States and United Kingdom, consistent with the group's focus on Ukraine-supporting institutions in those countries.

## What this means for defenders

Star Blizzard's defining trait for defenders isn't a single stable IOC set - it's the speed at which the group replaces its entire delivery chain after exposure. Static indicator lists age out quickly; the durable detection surface is the **behavioral pattern underneath the churn**: scheduled tasks with innocuous-sounding names created shortly after a user opens an email attachment or clicks a link, followed by `control.exe` or `msiexec.exe` reaching out to download further stages. Organizations in the NGO, think-tank, government, and financial sectors - particularly those with any Ukraine-related mission - should treat unexpected scheduled task creation tied to recent mail activity as a high-priority signal, independent of which specific malware family is active that month.

*See also: [Star Blizzard RedFlick - Scheduled-Task Delivery of the CosmicPulse Backdoor](/detections/star-blizzard-redflick/) for detection logic.*

**Sources:** [Microsoft Threat Intelligence - Star Blizzard refines phishing and malware delivery with the RedFlick technique](https://microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/)

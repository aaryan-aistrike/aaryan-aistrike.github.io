---
title: "UNC6508 - INFINITERED Backdoor Abuses REDCap Files and Workspace Mail Rules (Threat Brief)"
layout: default
---

## Overview

**INFINITERED** is custom malware deployed by **UNC6508**, a PRC-nexus espionage actor Google's Threat Intelligence Group (GTIG) tied to a multi-year intrusion campaign against North American medical, military, and academic research institutions (disclosed 2026-06-15). Rather than dropping a standalone implant, INFINITERED trojanizes three legitimate files inside compromised REDCap (Research Electronic Data Capture) servers: it hooks `Upgrade.php` so the backdoor survives version upgrades, injects a credential harvester into the authentication module that captures plaintext logins from POST requests, and plants a page-load-triggered backdoor in the custom hooks file that reads attacker commands from a `REDCAP-TOKEN` cookie. More than a year after initial compromise, the actor escalated to a domain administrator account and - using stolen Google Workspace credentials - created a content compliance rule that silently BCC-forwarded mail matching sensitive keywords (defense, AI, uncrewed-systems, and medical-research terms including the pathogen Chikungunya) to an attacker-controlled Gmail account.

## Why this matters for detection

INFINITERED never touches the endpoint as a standalone binary - it is code injected into an existing web application, so the usual process-creation and binary-reputation telemetry that catches most backdoors has nothing to alert on here. The REDCap-side trojanization (modified `Upgrade.php`, auth module, or hooks file) is only visible to whoever is actively diffing application files against known-good checksums, which most organizations don't do for every internal web app. The far more durable detection point is the cloud administration layer: creating or editing a Gmail content compliance rule that attaches a silent BCC or forwarding action is a rare, high-privilege admin-console action in nearly every Workspace tenant, and it is captured in Workspace admin audit logs no matter what initial-access technique a future actor uses to reach that privilege level - making it a detection signal that outlives this specific campaign's REDCap angle.

## Detection Guidance

```yaml
title: Google Workspace Content Compliance Rule Created With Silent BCC or Forwarding Action
status: experimental
description: >-
  Detects creation or modification of a Gmail content compliance rule
  that adds a silent BCC, forwarding, or header-modification action,
  consistent with UNC6508's abuse of this legitimate Workspace admin
  feature for mail-based exfiltration following compromise of an
  on-premises application server (as seen in the INFINITERED/REDCap
  campaign).
references:
  - https://cloud.google.com/blog/topics/threat-intelligence/prc-targets-us-medical-research
  - https://www.helpnetsecurity.com/2026/06/15/chinese-hackers-redcap-medical-research-institutions-breach/
  - https://www.securityweek.com/chinese-hackers-target-medical-military-and-ai-research-in-north-america/
author: Aryan
date: 2026-10-09
tags:
  - attack.initial_access
  - attack.t1190
  - attack.persistence
  - attack.t1505.003
  - attack.collection
  - attack.t1114.003
  - attack.exfiltration
  - attack.t1567
logsource:
  category: application
  product: google_workspace
  service: admin_audit
  definition: 'Requires Google Workspace Admin Audit log export (Email Settings events) forwarded to a SIEM'
detection:
  selection_rule_change:
    event_name:
      - 'CREATE_EMAIL_SETTING'
      - 'CHANGE_EMAIL_SETTING'
    setting_type: 'CONTENT_COMPLIANCE'
  selection_silent_action:
    action_type:
      - 'ADD_BCC'
      - 'ADD_X_HEADER'
      - 'MODIFY_MESSAGE'
  condition: selection_rule_change and selection_silent_action
  # Correlate: the admin account making the change should also be checked
  # against recent anomalous sign-in activity (new device, new IP, or a
  # just-escalated domain admin grant) rather than treated as a standalone signal
falsepositives:
  - Legitimate DLP/compliance or legal-hold teams configuring content compliance rules for e-discovery or regulatory archiving
  - Approved third-party email-archiving or security integrations that add a BCC action during initial setup
level: high
```

## Prevention

- Treat Workspace content compliance / mail-rule creation and modification as a privileged, always-audited action - alert on every occurrence rather than assuming it's rare enough to ignore.
- Patch REDCap promptly and fully remove legacy versions left installed alongside current ones; this actor specifically probed for exactly that configuration.
- Periodically diff REDCap's `Upgrade.php`, authentication module, and hooks files against known-good checksums or GTIG's published YARA rule (`G_Backdoor_INFINITERED_1`), since the backdoor's whole design assumes nobody is watching those files.
- Enforce phishing-resistant 2-step verification and Device Bound Session Credentials on Workspace admin and service accounts, since the mail-rule abuse here required a domain-admin-level credential to execute.

*See also: [UNC6508 - PRC-Nexus Espionage Actor Behind the INFINITERED REDCap Backdoor](/actors/unc6508/) for the actor's broader behavioral pattern.*

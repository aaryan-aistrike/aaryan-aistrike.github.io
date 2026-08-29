---
title: "UNC6671 - Vishing-to-AiTM Extortion Chain (Threat Brief)"
layout: default
---

## Overview

Google's Threat Intelligence Group (GTIG) disclosed on 2026-08-06 that **UNC6671** - the financially motivated group formerly operating as "BlackFile" - has continued its core intrusion activity uninterrupted since a false May 2026 shutdown, now spread across four rebranded extortion fronts (Redact, Pink, Helix, Falcon). The intrusion chain doesn't touch traditional endpoint or email defenses at all: operators call employees on personal mobile phones, impersonate IT helpdesk staff, and walk the victim through a fake mandatory FIDO2 passkey or MFA enrollment on a lookalike domain (`[company].createssopasskey[.]com`, `passkeyhelpdesk[.]com`, and similar). An adversary-in-the-middle (AiTM) proxy behind that page captures the real password and MFA/passkey response in real time, giving the attacker a live authenticated session with no malware and no phishing email involved.

From that session, automated scripts pull data directly out of Microsoft 365, Okta, and other SaaS platforms, and operators delete password-reset and MFA-change notification emails from the mailbox to delay detection. Targeting shifted sharply in July 2026 toward private equity firms, hedge funds, major law firms, and financial rating agencies, with tracked ransom collections of roughly $10.69M between January and May 2026 alone.

## Why this matters for detection

This chain is specifically engineered to route around the controls most organizations rely on: there's no phishing email for a secure email gateway to catch, no malware for EDR to flag, and the initial social-engineering call happens on a device and channel (personal cellphone) the security team has zero visibility into. The one place this campaign is forced to leave a trace inside monitored infrastructure is the identity provider itself - an MFA/passkey re-enrollment event is the pivot point where "employee legitimately updating their security info" and "attacker completing an AiTM takeover" produce the exact same log entry, and the only way to tell them apart is by correlating it with what happens immediately after (DNS/proxy traffic to a newly-seen passkey-themed domain, followed by bulk mailbox or SaaS data access from the same account).

## Detection Guidance

```yaml
title: Passkey/SSO-Themed Domain Query Followed by Security-Info Registration
status: experimental
description: >-
  Detects DNS or proxy queries to newly-observed domains combining
  passkey/SSO/MFA branding with helpdesk-style verbs (enroll, deploy,
  setup, sync), consistent with UNC6671-style AiTM vishing infrastructure,
  and flags when a security-info/MFA registration event for the same user
  follows shortly after.
references:
  - https://cloud.google.com/blog/topics/threat-intelligence/unc6671-targets-financial-services-and-enterprise-cloud-environments
  - https://thehackernews.com/2026/08/unc6671-vishing-attacks-target-personal.html
  - https://www.bleepingcomputer.com/news/security/hedge-fund-cyberattacks-tied-to-blackfile-linked-unc6671-extortion-group/
author: Aryan
date: 2026-08-29T00:00:00.000Z
tags:
  - attack.initial_access
  - attack.t1566.004
  - attack.credential_access
  - attack.t1557
  - attack.defense_evasion
  - attack.t1070.008
logsource:
  category: dns_query
  product: zeek
detection:
  selection_domain_theme:
    query|contains:
      - 'passkey'
      - 'ssopasskey'
      - 'mfaenroll'
  selection_verb_theme:
    query|contains:
      - 'helpdesk'
      - 'deploy'
      - 'setup'
      - 'enroll'
      - 'sync'
  condition: selection_domain_theme and selection_verb_theme
  # Correlate: the DNS hit above followed within 1h by an Entra ID/Okta
  # "register security info" or passkey-enrollment event for the same
  # user is the actual AiTM-vishing signature - either alone is weak
falsepositives:
  - Legitimate internal SSO/passkey rollout communications using similar naming, hosted on a company-owned domain
  - Security-awareness phishing simulation platforms deliberately using passkey-themed lookalike domains
level: high
```

## Prevention

- Treat any unscheduled MFA-method or passkey re-enrollment event as requiring out-of-band verification with the employee before it's trusted, not just logged - this is the one step of the chain every victim organization's identity provider actually recorded.
- Formalize and repeat the rule that IT/helpdesk never initiates unsolicited calls to personal mobile numbers about "urgent" security migrations - this campaign's entire initial-access vector depends on employees not knowing that.
- Enforce phishing-resistant MFA (FIDO2 hardware keys bound to a specific origin) rather than push/OTP-based MFA, which is what AiTM proxies are built to relay through.
- Monitor mailbox rule changes and deletion of security-notification emails (password-reset confirmations, MFA-change alerts) as a high-value post-compromise signal, since this group specifically automates that cleanup step.

*See also: [UNC6671 - Multi-Brand Vishing Extortion Group](/actors/unc6671/) for the actor's broader behavioral pattern.*

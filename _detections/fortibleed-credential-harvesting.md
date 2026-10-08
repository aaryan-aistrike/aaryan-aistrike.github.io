---
title: "FortiBleed - Mass Credential Harvesting Campaign Against FortiGate Appliances (Threat Brief)"
layout: default
---

## Overview

**FortiBleed** is an ongoing credential-harvesting campaign against internet-facing Fortinet FortiGate firewalls and SSL VPN gateways, originating from a mid-2026 leak of an estimated ~74,000 device credentials that prompted a CISA emergency alert on 2026-06-18. On 2026-10-06, the FBI and U.S. Secret Service issued a joint cybersecurity advisory (JCSA-20261006-01, "FortiBleed Operations Continue Targeting Exposed Systems Leading to Reports of Lockouts") warning that the campaign is still active months later and has escalated: SOCRadar has independently verified more than 86,644 compromised FortiGate devices across 194 countries, with one SOCRadar executive cited elsewhere as putting the wider operation's targeting scope as high as 400,000-450,000 firewalls.

Critically, Fortinet and the advisory are explicit that this is **not** a new software vulnerability or zero-day - it is a credential-compromise campaign. Attackers scan the internet for reachable FortiGate VPN portals, then run credential stuffing and password spraying using credentials sourced from prior Fortinet-related leaks and unrelated infostealer logs. The advisory specifically calls out exploitation of **legacy SHA-256 password storage** on affected devices, which lets attackers crack large batches of harvested password hashes offline at scale once they obtain them. After gaining administrative access, operators create additional administrator accounts to maintain persistence, and in many cases delete legitimate admin accounts or change their passwords outright - which is why organizations are reporting being locked out of their own appliances. The advisory links the campaign to initial-access brokers who resell FortiBleed-derived access to ransomware affiliates, naming **INC**, **Lynx** (INC's closely related fork/rebrand), and **Payload** ransomware operations as downstream beneficiaries.

## Why this matters for detection

FortiBleed is a reminder that not every "we have 86,000+ compromised devices" headline maps to a patchable CVE - here, the fix is entirely in credential hygiene and account-change monitoring, not a firmware update. Because the weak point is password reuse plus a crackable legacy hash format rather than a code flaw, signature-based vulnerability scanning will show nothing; the only reliable telemetry is the FortiGate's own authentication and administrative-configuration event log. Two patterns matter most: a burst of failed admin-portal authentication attempts from an external source followed by a success (credential stuffing/spraying), and - the single highest-confidence indicator in this campaign - administrator account creation or deletion/password-change events that don't correlate to a known change window or ticket. Because the attackers' end goal is handing access to ransomware affiliates (INC/Lynx, Payload), a compromised FortiGate found this way should be treated as a likely ransomware precursor, not just a credential-theft incident.

## Detection Guidance

```yaml
title: FortiGate Admin Portal Credential Stuffing Followed by Account Tampering
status: experimental
description: >-
  Detects a burst of failed FortiGate administrative/SSL-VPN authentication
  attempts from an external source followed by a successful login, and/or
  administrator account creation or deletion/password-change events with
  no corresponding authenticated change-management session - consistent
  with the FortiBleed credential-harvesting campaign (JCSA-20261006-01).
references:
  - https://www.cybersecuritydive.com/news/fbi-fortibleed-credential-harvesting-attacks/832366/
  - https://thehackernews.com/2026/10/fbi-warns-fortibleed-remains-active.html
  - https://gbhackers.com/fbi-warns-fortibleed-campaign-targeting-fortinet-firewalls/
author: Aryan
date: 2026-10-08T00:00:00.000Z
tags:
  - attack.credential_access
  - attack.t1110
  - attack.t1110.004
  - attack.persistence
  - attack.t1098
  - attack.impact
  - attack.t1531
logsource:
  category: firewall
  product: fortios
  definition: 'Requires FortiGate admin/VPN authentication and configuration-change event logging forwarded to a SIEM'
detection:
  selection_failed_admin_auth:
    EventType: 'admin_login'
    Status: 'failure'
    SourceZone: 'wan'
  selection_success_admin_auth:
    EventType: 'admin_login'
    Status: 'success'
    SourceZone: 'wan'
  selection_admin_account_change:
    EventName:
      - 'admin_account_added'
      - 'admin_account_deleted'
      - 'admin_password_changed'
    ChangeSession: 'none'
  condition: (selection_failed_admin_auth and selection_success_admin_auth) or selection_admin_account_change
  timeframe: 1h
  # Treat selection_admin_account_change as critical/confirmed-compromise on
  # its own - correlate selection_failed_admin_auth count >= 10 from the same
  # SourceIP before the success event as the credential-stuffing precursor
falsepositives:
  - Legitimate administrators mistyping credentials before a successful login
  - Authorized account provisioning or offboarding performed through documented change management
  - Password rotation performed by an authenticated administrator during a scheduled maintenance window
level: critical
```

## Prevention

- Treat FortiBleed as a credential-hygiene incident, not a patchable vulnerability: rotate all FortiGate admin and SSL-VPN credentials, especially any reused elsewhere or present in known breach/infostealer datasets, rather than waiting on a firmware fix.
- Disable legacy SHA-256 password storage where FortiOS offers a stronger alternative, and enforce unique, high-entropy passwords for every administrative account.
- Require MFA on all FortiGate admin and SSL-VPN access, and restrict the admin portal to known management source IPs wherever the deployment allows it.
- Alert on any administrator account creation, deletion, or password change that doesn't correlate to a documented change-management session - this is the clearest signal of post-compromise persistence in this campaign.
- Treat any FortiGate showing these indicators as a likely ransomware precursor (INC/Lynx, Payload affiliates are named beneficiaries of this access) and begin incident response accordingly, not just a credential reset.

*See also: [INC Ransom - Russian-Speaking RaaS Exploiting SonicWall Zero-Days](/actors/inc-ransom/) - the same group named as a downstream beneficiary of FortiBleed-derived access, showing a pattern of opportunistically absorbing access from multiple unrelated initial-access campaigns.*

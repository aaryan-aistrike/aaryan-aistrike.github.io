---
title: "EvilTokens - AI-Powered Device-Code Phishing-as-a-Service (Threat Brief)"
layout: default
---

## Overview

**EvilTokens** is a phishing-as-a-service (PhaaS) kit, first seen in February 2026 and attributed by Microsoft to a cluster it tracks as **Storm-2992**, that automates OAuth 2.0 **device authorization grant** ("device code") phishing against Microsoft accounts. The device code flow exists for input-limited hardware - smart TVs, printers, Teams Rooms devices - that can't run a normal interactive sign-in: the user visits `microsoft.com/devicelogin` on a separate device, types a short code, and authorizes the session. EvilTokens weaponizes this by having a phishing page generate a real, live device code via a background script talking to Microsoft's identity endpoints in real time, then presenting it to the victim with a "Copy Code" button and a "Continue with Microsoft" link that goes to the *real* Microsoft login page. While the victim is completing that legitimate-looking step, the kit's backend polls Microsoft every 3-5 seconds to detect the moment authorization completes - at which point the attacker's own already-initiated session becomes authenticated, with no password ever entered and no MFA challenge bound to the attacker's context.

Microsoft says the service compromised more than 12,000 inboxes across 10,000+ organizations before it disrupted the operation's infrastructure in September 2026, working with partners on a coordinated takedown that seized dozens of websites and led to arrests in the UK. Worst-hit sectors included wholesale distribution, construction, financial services, real estate, higher education, and healthcare, concentrated in the US, Canada, UK, Australia, India, and France.

## Why this matters for detection

Device-code phishing is dangerous specifically because it never touches a password field and doesn't trip classic MFA prompts on the victim's own device - the authenticating session lives entirely on infrastructure the attacker controls, so even security-aware users who'd never type a password into a fake login page can be fully compromised by pasting a code into the *genuine* Microsoft site. That also means detection can't rely on catching a phishing page's HTML or domain; it has to rely on the fact that device-code authentication itself is rare in most organizations outside a handful of headless-device scenarios. Any device-code sign-in is worth scrutiny, and one followed within hours by a new device registration, a spike in Graph API calls, or a new inbox rule (Storm-2992's customers commonly add rules to hide or auto-forward mail as the next BEC step) is a near-certain compromise.

## Detection Guidance

```yaml
title: OAuth Device-Code Sign-In Followed by Suspicious Inbox Rule or Device Registration
status: experimental
description: >-
  Detects a Microsoft Entra ID sign-in using the OAuth 2.0 device
  authorization grant (device code flow) followed within a short window by
  a new mailbox inbox rule or a new device/PRT registration for the same
  user, consistent with EvilTokens (Storm-2992) device-code phishing
  used to enable business email compromise.
references:
  - https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/
  - https://thehackernews.com/2026/09/microsoft-takes-down-eviltokens-device.html
  - https://blog.sekoia.io/new-widespread-eviltokens-kit-device-code-phishing-as-a-service-part-1/
author: Aryan
date: 2026-09-26
tags:
  - attack.initial_access
  - attack.t1528
  - attack.persistence
  - attack.t1098.002
  - attack.collection
  - attack.t1114.003
logsource:
  product: azure
  service: signinlogs
  definition: >-
    Correlate Entra ID sign-in logs (AuthenticationProtocol = deviceCode)
    against Microsoft 365 Unified Audit Log inbox-rule and device
    registration operations for the same UserId/UserPrincipalName
detection:
  selection_device_code_signin:
    AuthenticationProtocol: deviceCode
  selection_followon_inbox_rule:
    Operation:
      - New-InboxRule
      - Set-InboxRule
  selection_followon_device_reg:
    Operation:
      - Add device
      - Register device
  condition: selection_device_code_signin and (selection_followon_inbox_rule or selection_followon_device_reg)
  timeframe: 4h
  # Correlate on UserId between the sign-in event and the follow-on operation
falsepositives:
  - Legitimate device-code sign-ins from Teams Rooms devices, smart TVs, or headless IoT hardware, coincidentally followed by an unrelated mailbox rule change
  - IT-provisioned onboarding flows that intentionally combine device-code auth with device registration
level: high
```

## Prevention

- Disable the OAuth device authorization grant tenant-wide via Conditional Access unless a specific, documented headless-device scenario requires it; where it is required, scope it tightly by user group and device type.
- Treat any device-code sign-in as high-signal and route it through the same scrutiny as a risky sign-in, since it is rare in most environments outside a narrow set of legitimate use cases.
- Alert on inbox rule creation and new device/PRT registration occurring shortly after any device-code authentication for the same user - this sequence is the kit's actual post-compromise fingerprint, not any single event in isolation.
- Move toward phishing-resistant authentication (FIDO2/WebAuthn, certificate-based auth) where possible, since device-code flow specifically sidesteps MFA methods that are bound to the user's own device.

*See also: [Storm-2992 - Developer and Operator of the EvilTokens Device-Code Phishing-as-a-Service Kit](/actors/storm-2992/) for the actor's broader behavioral pattern.*

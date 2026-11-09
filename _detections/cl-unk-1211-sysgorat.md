---
title: "CL-UNK-1211 - SysGoRAT Backdoor and AI-Generated Scripts Against Government Linux Servers (Threat Brief)"
layout: default
---

## Overview

On 2026-10-15, Palo Alto Networks Unit 42 published analysis of **CL-UNK-1211** (Cluster, Unknown motivation - Unit 42's naming convention for an activity cluster it has not yet tied to a known nation-state or criminal group), an espionage campaign that compromised Linux-based government servers, including machines running the Plesk hosting-control-panel, between October 2025 and April 2026. The campaign's primary implant is **SysGoRAT**, a custom cross-platform backdoor written in Go (internally named `sys-control-client` before being renamed to blend in) that communicates with its command-and-control server over WebSocket, with at least one documented hardcoded C2 address of `104.194.158[.]65:443`. Some reporting also describes covert command polling tunneled inside DNS-over-HTTPS queries to public resolvers (Cloudflare, Google) as an additional covert channel.

What makes this cluster especially notable is forensic, not just technical: several of the PHP and shell scripts recovered from compromised hosts contain conversational, step-by-step reasoning comments characteristic of large-language-model output - code that reads as if it is explaining itself to an operator, rather than typical hand-written attacker tooling. Unit 42 frames this as evidence consistent with scripts generated or adapted via an LLM during the intrusion itself, making it one of the more concrete forensic examples of AI-assisted hands-on-keyboard tradecraft documented to date, as distinct from vendor claims about agentic pentesting frameworks. That inference is circumstantial (based on code style, not a confirmed tool or account), so it should be treated as an assessment rather than proven fact.

For persistence, the operators abused PHP's `auto_prepend_file` directive - editing PHP configuration under paths like `/etc/php/` and `/opt/plesk/php/` so a malicious PHP file silently executes before every legitimate PHP script on the server runs, and disguised a web shell as a legitimate Plesk system driver file to blend into the hosting environment. For credential theft, they modified victims' `.bashrc` files to plant a shell alias that intercepted `sudo` invocations, capturing the administrator's password before transparently forwarding it to the real `sudo` binary, and injected credential-logging code into PHP login pages. A dedicated reconnaissance script (`search_social.php`) scanned government mailboxes for password-reset and social-media-notification emails to identify officials' personal social media accounts as potential pivot targets. The group also attempted to disable endpoint security products and tamper with logs/timestamps to cover its tracks.

## Why this matters for detection

Nearly every indicator in this campaign is designed to hide inside something that already looks legitimate: `auto_prepend_file` persistence leaves no new malicious file reference in the web root, a `.bashrc` sudo alias leaves the victim's actual password prompt and command flow completely unchanged, and a web shell disguised as a Plesk driver file blends into normal hosting-panel operations. None of these rely on a specific exploited CVE - they're post-compromise configuration abuse, which means patching alone won't catch this cluster; detection has to focus on **unexpected changes to PHP interpreter configuration and shell profile files**, since those are both rarely modified in normal operations and are exactly where this tradecraft hides.

## Detection Guidance

```yaml
title: Suspicious PHP auto_prepend_file Configuration Change or Shell Profile Alias Tampering
status: experimental
description: >-
  Detects modification of php.ini-equivalent configuration to set or change
  auto_prepend_file, or insertion of a sudo-intercepting alias into a user's
  .bashrc/.bash_profile, consistent with SysGoRAT/CL-UNK-1211 persistence and
  credential-theft tradecraft on Linux hosting infrastructure.
references:
  - https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/
  - https://thehackernews.com/2026/11/government-linux-servers-targeted-with.html
  - https://gbhackers.com/ai-generated-scripts/
  - https://securityonline.info/sysgorat-malware-cl-unk-1211-linux/
author: Aryan
date: 2026-11-09T00:00:00.000Z
tags:
  - attack.persistence
  - attack.t1546.007
  - attack.credential_access
  - attack.t1552.004
  - attack.t1556.003
  - attack.defense_evasion
  - attack.t1070
  - attack.command_and_control
  - attack.t1071.001
logsource:
  category: file_event
  product: linux
detection:
  selection_php_prepend_change:
    TargetFilename|contains:
      - 'php.ini'
      - '/etc/php/'
      - '/opt/plesk/php/'
    FileContent|contains: 'auto_prepend_file'
  selection_bashrc_sudo_alias:
    TargetFilename|endswith:
      - '/.bashrc'
      - '/.bash_profile'
      - '/.profile'
    FileContent|contains:
      - 'alias sudo='
      - 'function sudo'
  condition: selection_php_prepend_change or selection_bashrc_sudo_alias
  # Correlate: either selection followed by outbound WebSocket (wss://) or
  # DNS-over-HTTPS traffic from the same host within a short window
falsepositives:
  - Legitimate hosting-provider or sysadmin automation that intentionally sets auto_prepend_file for application-wide bootstrapping (e.g. APM/profiling agents)
  - Shell customization frameworks (oh-my-zsh style dotfile managers) that define sudo-related aliases for unrelated convenience reasons
level: high
```

## Prevention

- Baseline and alert on any change to `auto_prepend_file` (or `auto_append_file`) in PHP configuration on internet-facing hosting infrastructure - this directive is rarely touched after initial setup, so any drift is a strong signal.
- Treat `.bashrc`/`.bash_profile`/`.profile` as monitored configuration, not just a convenience file - file-integrity monitoring on these paths would have caught the sudo-interception alias immediately.
- Audit Plesk (and other hosting-panel) installations for files that match known system driver/component names but differ in hash, size, or modification time from the vendor-shipped originals.
- Don't assume AI-generated or AI-assisted code in a forensic artifact implies a more sophisticated actor than usual - the underlying techniques here (config-based persistence, shell alias credential theft) are well-understood and detectable with standard file-integrity and configuration-drift monitoring regardless of how the script was authored.

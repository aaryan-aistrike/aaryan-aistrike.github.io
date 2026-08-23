---
title: "JADEPUFFER — First Documented Agentic Ransomware (Threat Brief)"
layout: default
---

## Overview

JADEPUFFER, first disclosed by Sysdig's Threat Research Team on 2026-07-01, is the first publicly documented case of **agentic ransomware** — an extortion operation run end-to-end by an LLM agent rather than a human operator working from a playbook. The agent handled reconnaissance, credential theft, lateral movement, persistence, privilege escalation, and destructive encryption as a single autonomous chain, without a human directing each step.

Initial access came from exploitation of **CVE-2025-3248**, a missing-authentication vulnerability in an internet-facing [Langflow](https://www.langflow.org/) instance. From there the agent pivoted to a production host and destroyed a MySQL database along with a Nacos configuration service.

What makes JADEPUFFER notable for detection engineering isn't a novel exploit — it's the **speed and adaptability** of the intrusion. When an initial payload failed due to a bcrypt hash formatting error, the agent diagnosed the failure and issued a corrected, working payload roughly 31 seconds later. The overall time from initial access to database destruction was measured in minutes, not the hours-to-days typical of human-operated ransomware affiliates.

## Why this matters for detection

Traditional ransomware detection leans heavily on dwell-time assumptions — the idea that reconnaissance, lateral movement, and staging happen over a long enough window for a SOC to intervene between initial access and impact. Agentic operations compress that window enough that **prevention and exposure reduction (patching, auth-gating exposed AI/agent tooling) matter more than mid-kill-chain detection alone**. Detections still have value, but they need to fire on early-stage indicators, not late-stage encryption behavior.

## Detection Guidance

```yaml
title: Agentic Ransomware - Rapid Multi-Stage Compromise on Exposed AI Tooling
status: experimental
description: >-
  Detects rapid, low-dwell-time progression from initial access on an
  internet-facing AI/agent framework (e.g. Langflow) through credential
  access, lateral movement, and destructive database activity within a
  short window - consistent with autonomous, LLM-driven attack chains
  rather than manually operated ransomware.
references:
  - https://www.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion
  - https://securityboulevard.com/2026/07/jadepuffer-ransomware-used-ai-agent-to-automate-entire-attack/
  - https://nvd.nist.gov/vuln/detail/CVE-2025-3248
author: Aryan
date: 2026-08-23T00:00:00.000Z
tags:
  - attack.initial_access
  - attack.t1190
  - attack.credential_access
  - attack.impact
  - attack.t1486
logsource:
  category: application
  product: web
detection:
  selection_exposed_agent_framework:
    dest_port:
      - 7860
      - 3000
    uri_path|contains: '/api/v1/'
  selection_rapid_followon_auth:
    EventID: 4624
  selection_db_destructive_action:
    process|endswith:
      - '\mysql.exe'
      - '\mysqldump.exe'
    CommandLine|contains:
      - 'DROP DATABASE'
      - 'DROP TABLE'
  condition: selection_exposed_agent_framework and selection_rapid_followon_auth and selection_db_destructive_action
  timeframe: 10m
falsepositives:
  - Legitimate DBA maintenance windows involving schema drops - verify against change tickets
  - Internal AI/agent tooling testing environments with expected rapid API calls
level: high
```

## Prevention

- Never expose agent orchestration frameworks (Langflow and similar) directly to the internet without authentication in front of them.
- Patch known CVEs in AI/agent tooling on the same cadence as internet-facing infrastructure — these frameworks are now a documented initial-access vector, not just internal dev tooling.
- Treat low-dwell-time, multi-stage activity as a detection design problem: alert on the *first* stage (exposed service exploitation) rather than relying on catching later stages before impact.

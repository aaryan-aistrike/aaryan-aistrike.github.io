---
title: "Mirage Kitten - NodeRabbit/PollCat Recruiter-Lure Malware (Threat Brief)"
layout: default
---

## Overview

In a campaign disclosed by Kaspersky on 2026-09-01, the Iran-linked actor **Mirage Kitten** (aka UNC1549, Smoke Sandstorm, Nimbus Manticore) targeted developers at aviation, aerospace, and fintech organizations - with victims identified in Egypt, Ethiopia, and Afghanistan - using fake LinkedIn recruiter personas offering a technical role. Targets were sent a "coding challenge" or "technical assessment" archive that bundled a trojanized npm package, `colorized_terminal` v2.1.0, directly inside its `node_modules` directory rather than publishing it to the public npm registry. Importing the package silently launched a hidden implant as a detached background process.

The campaign delivered two previously undocumented, cross-platform malware families: **NodeRabbit** (Node.js, Windows/Linux/macOS) and **PollCat** (obfuscated JavaScript, delivered separately inside a React-based assessment named `RankChallenge-react`). More advanced NodeRabbit variants add anti-analysis checks, corporate proxy support, Outlook account discovery, and two developer-tooling-specific persistence mechanisms: launcher code injected into Git hooks (`.git/hooks/post-merge`, `.git/hooks/post-checkout`) and a fake VS Code extension impersonating "GitHub Copilot Helper" with a spoofed publisher identity.

## Why this matters for detection

This intrusion path is built to slip past exactly the controls most organizations rely on for supply-chain risk: the malicious package was never published to npm, so registry/dependency-scanning tools have nothing to flag, and the initial "test project" looks like completely normal candidate activity on a developer's own machine. The persistence choices are also developer-tooling-specific rather than generic autoruns - Git hooks and VS Code extensions are rarely covered by standard persistence detections, and both re-trigger through everyday developer actions (`git pull`, opening the editor) rather than reboot or logon events. Developer endpoints frequently run with looser EDR policy than standard corporate laptops (to tolerate compilers, package managers, and other "noisy" tooling), making this an attractive and comparatively under-monitored initial-access surface.

## Detection Guidance

```yaml
title: Mirage Kitten - NodeRabbit/PollCat Recruiter-Lure Persistence
status: experimental
description: >-
  Detects developer-tooling persistence techniques associated with Mirage
  Kitten's NodeRabbit/PollCat campaign: launcher code written into Git
  hook files, or a Node.js process spawning a detached child process from
  inside a project's node_modules directory shortly after a package
  install, consistent with a trojanized "coding challenge" dependency
  bundled outside the npm registry.
references:
  - https://securelist.com/mirage-kitten-new-backdoors-noderabbit-pollcat/121244/
  - https://securityaffairs.com/198289/apt/iran-linked-apt-mirage-kitten-uses-fake-job-tests-to-spread-malware.html
  - https://gbhackers.com/mirage-kitten-campaign/
author: Aryan
date: 2026-09-15T00:00:00.000Z
tags:
  - attack.initial_access
  - attack.t1566.003
  - attack.persistence
  - attack.t1546
  - attack.command_and_control
  - attack.t1071
  - attack.collection
  - attack.t1114
logsource:
  category: process_creation
  product: multi
detection:
  selection_git_hook_write:
    TargetFilename|contains:
      - '\.git\hooks\post-merge'
      - '\.git\hooks\post-checkout'
      - '/.git/hooks/post-merge'
      - '/.git/hooks/post-checkout'
  selection_node_modules_spawn:
    Image|endswith:
      - '\node.exe'
      - '/node'
    CommandLine|contains: 'node_modules'
    ParentImage|endswith:
      - '\npm.exe'
      - '\npm-cli.js'
      - '/npm'
  selection_vscode_extension_install:
    CommandLine|contains|all:
      - '.vscode'
      - 'extensions'
    CommandLine|contains: 'Copilot Helper'
  condition: selection_git_hook_write or selection_node_modules_spawn or selection_vscode_extension_install
  # Escalate to critical if a node_modules-spawned process is followed by
  # outbound network connections from node.exe/node not matching known
  # package-registry or corporate-proxy destinations
falsepositives:
  - Legitimate Git hook tooling deployed by CI/CD systems (Husky, pre-commit frameworks) that also write to post-merge/post-checkout
  - Build tooling that legitimately spawns detached Node.js child processes from within node_modules (e.g. background watchers, dev servers)
  - Developers installing genuine VS Code extensions with "Copilot" or "Helper" in the name
level: high
```

## Prevention

- Treat "coding challenge" or take-home-assessment archives received from unsolicited recruiter contact as untrusted code: run them only in a disposable VM or sandboxed container, never directly on a corporate-joined developer workstation.
- Apply the same EDR policy rigor to developer endpoints as to standard corporate laptops - "noisy" build tooling is not a reason to blanket-exempt `node`/`npm` process trees from behavioral monitoring.
- Monitor and alert on writes to `.git/hooks/` outside of known CI/CD or hook-management tooling (Husky, pre-commit, lefthook) - this is an uncommon and high-signal persistence location.
- Restrict or audit VS Code extension installation on managed developer machines, and verify publisher identity rather than trusting display names alone.
- Provide engineering staff with a clear, low-friction path to verify unsolicited recruiter contact and technical-assessment legitimacy before running any provided code.

*See also: [Mirage Kitten / UNC1549 - Iranian Recruiter-Lure Espionage Actor](/actors/mirage-kitten/) for the actor's broader behavioral pattern.*

---
title: "Mastra npm Supply Chain Compromise - Hijacked-Publisher Attack (Threat Brief)"
layout: default
---

## Overview

On 2026-06-17, an attacker who had taken over a trusted npm contributor account (publishing rights to the `@mastra` scope were never revoked after the account was compromised) ran an automated, 88-minute campaign that republished 141–144 packages in the `@mastra` namespace. Each republished package was left functionally unmodified - the compromise was delivered entirely through a single **injected dependency**: `easy-day-js`, a typosquat of the legitimate `dayjs` library.

`easy-day-js` carried an obfuscated payload inside a `postinstall` script, meaning the malicious code executed automatically the moment a developer ran `npm install` - before any application code was ever imported or run. The payload harvested browser data (Chrome, Edge, Brave), extracted credentials from 166 cryptocurrency-wallet browser extensions (including MetaMask, Phantom, Coinbase, and Binance), performed host reconnaissance, established cross-platform persistence, and exfiltrated everything collected to attacker infrastructure. Microsoft attributed the campaign to the group it tracks as Sapphire Sleet.

## Why this matters for detection

This wasn't a case of malicious code hiding inside application logic - it hid in the **dependency graph**, one level removed from the package a developer actually intended to install. Traditional SCA (software composition analysis) tools that only diff known package versions can miss a typosquat introduced as a *new* transitive dependency. `postinstall` script execution is also a blind spot for most EDR coverage, since it runs as a child of `npm`/`node` during routine developer or CI activity - behavior that looks identical to legitimate build tooling unless you're specifically watching for network egress or wallet-extension file access immediately afterward.

## Detection Guidance

```yaml
title: Suspicious npm postinstall Script Network/Credential Activity
status: experimental
description: >-
  Detects node/npm child processes spawned during package installation
  (postinstall/preinstall lifecycle scripts) that immediately perform
  outbound network connections or access browser credential/extension
  storage paths, consistent with a supply-chain-delivered infostealer
  payload rather than legitimate build tooling.
references:
  - https://www.microsoft.com/en-us/security/blog/2026/06/17/postinstall-payload-inside-mastra-npm-supply-chain-compromise/
  - https://socket.dev/blog/mastra-npm-packages-compromised
  - https://thehackernews.com/2026/06/144-mastra-npm-packages-compromised-via.html
author: Aryan
date: 2026-08-23T00:00:00.000Z
tags:
  - attack.initial_access
  - attack.t1195.002
  - attack.credential_access
  - attack.t1555.003
logsource:
  category: process_creation
  product: linux
detection:
  selection_npm_install_context:
    ParentImage|endswith:
      - '/npm'
      - '/npm-cli.js'
      - '/node'
  selection_network_process:
    Image|endswith:
      - '/curl'
      - '/wget'
      - '/node'
    CommandLine|contains:
      - 'http'
  selection_credential_paths:
    CommandLine|contains:
      - 'Login Data'
      - 'Local Extension Settings'
      - 'wallet.dat'
      - '.config/google-chrome'
      - '.mozilla/firefox'
  condition: selection_npm_install_context and (selection_network_process or selection_credential_paths)
  timeframe: 5m
falsepositives:
  - Legitimate postinstall scripts that fetch prebuilt binaries (e.g. node-sass, esbuild, playwright) from vendor CDNs
  - Internal package registries and mirrors performing expected network calls during install
level: high
```

## Prevention

- Pin exact dependency versions (and their transitive dependencies) via lockfiles, and diff lockfile changes in code review - a new, unfamiliar transitive dependency appearing in a diff is a signal worth stopping on.
- Run `npm install --ignore-scripts` in CI and only allow lifecycle scripts to execute in an isolated, network-restricted build step where their behavior can be observed.
- Revoke publish access immediately when any maintainer account shows signs of compromise - this specific incident was enabled by access that was never revoked after a prior account takeover.
- Monitor for outbound network connections and browser-credential-store file access originating from `node`/`npm` process trees during install, not just at runtime.

*See also: [Sapphire Sleet - Supply Chain & Credential Theft Tradecraft](/actors/sapphire-sleet/) for the actor's broader behavioral pattern.*

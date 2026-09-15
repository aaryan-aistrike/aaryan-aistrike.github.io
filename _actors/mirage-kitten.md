---
title: "Mirage Kitten / UNC1549 - Iranian Recruiter-Lure Espionage Actor"
layout: default
---

## Who they are

Mirage Kitten is an Iran-linked state-backed cyberespionage group, also tracked by other researchers as **UNC1549**, **Smoke Sandstorm**, and **Nimbus Manticore**. In a campaign documented by Kaspersky on 2026-09-01, the group was observed deploying two previously undocumented, cross-platform malware families - **NodeRabbit** (Node.js) and **PollCat** (obfuscated JavaScript) - against developers and technical staff at aviation, aerospace, and fintech organizations, with victims identified in Egypt, Ethiopia, and Afghanistan.

## Behavioral pattern

- **Fake-recruiter social engineering.** Operators pose as recruiters on LinkedIn, offering a technical role and a time-sensitive "coding challenge" or "technical assessment" as the pretext for getting a malicious project onto a target's workstation.
- **Malicious code bundled, not published.** The trojanized npm package used in the observed intrusion (`colorized_terminal`, version 2.1.0) was never published to the public npm registry - it was bundled directly inside the challenge archive's `node_modules` directory, so registry-scanning defenses never see it.
- **Detached-process launch from a hidden cache path.** Importing the package silently spawns an implant from a hidden cache path inside `node_modules` as a detached background process, decoupling the malware's lifetime from the developer's editor or test-runner process.
- **Developer-environment persistence.** Beyond typical autoruns, the malware plants persistence inside a victim's development tooling itself: launcher code injected into Git hooks (`post-merge`, `post-checkout`) that re-executes on routine `git pull`/`git checkout` activity, and a fake VS Code extension impersonating "GitHub Copilot Helper" (using a spoofed publisher identity) for editor-level persistence.
- **Cross-platform, capability-rich implants.** NodeRabbit runs on Windows, Linux, and macOS and supports system/user reconnaissance, file manipulation, arbitrary command execution, Outlook account discovery, anti-analysis checks, and corporate proxy support. PollCat, delivered separately inside a React-based assessment, adds file transfer, drive/directory enumeration, process control, hidden process creation, ZIP handling, Windows DLL execution, and arbitrary JavaScript execution via an `EVAL_JS` command.
- **Consistent with the group's long-running targeting.** The recruiter-lure approach and focus on aerospace/aviation and fintech developers is consistent with this cluster's tracked history under its other aliases, which has repeatedly used fake job offers as an initial-access vector against technically skilled targets.

## What this means for defenders

Because the malicious package is bundled locally rather than published, npm registry reputation and scanning tools will not catch it - detection has to focus on **behavior at the developer endpoint**: a `node`/`npm` process spawning a detached child from inside a project's `node_modules` directory, or new executable content appearing in `.git/hooks/`, is anomalous regardless of which specific campaign produced it. Developer workstations - which often have weaker EDR tuning and higher tolerance for "noisy" tooling than standard corporate endpoints - are the actual perimeter this group is attacking, and interview/recruiting-themed lures targeting engineers should be treated as a live initial-access vector, not just a HR/phishing awareness topic.

*See also: [Mirage Kitten - NodeRabbit/PollCat Recruiter-Lure Malware](/detections/mirage-kitten-noderabbit-pollcat/) for detection logic.*

**Sources:** [Kaspersky Securelist](https://securelist.com/mirage-kitten-new-backdoors-noderabbit-pollcat/121244/), [Security Affairs](https://securityaffairs.com/198289/apt/iran-linked-apt-mirage-kitten-uses-fake-job-tests-to-spread-malware.html), [GBHackers](https://gbhackers.com/mirage-kitten-campaign/)

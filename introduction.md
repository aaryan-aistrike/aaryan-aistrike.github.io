---
layout: default
title: "Introduction"
permalink: /introduction/
---

# Introduction

Most of what happens on a network is noise — routine logins, scheduled jobs, the ordinary hum of people doing ordinary work. Somewhere inside that noise, occasionally, is a signal: an encoded PowerShell command that shouldn't exist, a service ticket request that doesn't fit the pattern, a beacon calling home on a suspiciously round interval. Finding that signal — and building systems that find it automatically, before I have to — is what I actually do all day, and three years in, I still find it genuinely fun.

I'm Aryan. I work in detection engineering, threat hunting, and incident response, mostly across SIEM/EDR telemetry in enterprise and cloud environments, with everything mapped back to MITRE ATT&CK so the coverage story stays honest rather than aspirational. Lately that's meant spending a lot of time at the intersection of security and AI — using LLMs to speed up the boring parts of investigation, and researching how attackers are starting to use the same tools against us.

## What I actually spend time on

- **Detection Engineering** — behavioral detections, detection-as-code, Sigma, false-positive tuning, adversary emulation
- **Threat Hunting & DFIR** — endpoint forensics, incident investigations, root cause analysis, IOC/behavioral hunting
- **AI for Security Operations** — LLM-assisted alert triage and enrichment, validating AI-generated investigation output against ground truth before it drives analyst decisions, and building automation around that human-in-the-loop workflow to cut noise and speed up detection engineering
- **AI as a Threat Surface** — researching emerging AI-driven attack techniques (agentic malware, LLM-abuse patterns, AI-tooling exposure) as part of ongoing threat research — see [JADEPUFFER](/detections/jadepuffer-agentic-ransomware/)
- **SIEM & EDR** — Microsoft Sentinel, CrowdStrike, Defender for Endpoint, Cortex, Darktrace
- **Threat frameworks** — MITRE ATT&CK, Cyber Kill Chain, threat modeling
- **Cloud & identity** — AWS (EC2, S3, IAM, GuardDuty), Azure (Entra ID, Logic Apps, Graph API)
- **Programming/automation** — Python, PowerShell, Bash, KQL, API integrations

## How I got here

It started at **Anko**, the global capability centre for Kmart Group Australia, where I spent two and a half years in the trenches of a SOC — investigating phishing, malware, privilege escalation, and the occasional ransomware scare across endpoint, email, network, and cloud. It's the kind of job that teaches you what "normal" actually looks like on a real network, which turns out to be the single most useful thing you can know before you start writing detections for what isn't normal. I wrote Sentinel KQL rules, automated IOC blocking, and got comfortable moving between CrowdStrike, Defender, Darktrace, Proofpoint, and Palo Alto without needing a manual open in another tab.

From there I moved to **Arctic Wolf** as a Threat Researcher, where the job shifted from "respond to what's already happened" to "build the thing that catches it next time." I designed and maintained behavioral detections across SIEM/EDR telemetry using detection-as-code, and spent real time inside a handful of specific adversary techniques — Kerberoasting, encoded PowerShell, WMI-based lateral movement, reverse shells and C2 — building test cases, simulating them in lab environments, and tuning until the false-positive rate stopped embarrassing me. That last part matters more than people expect: a detection nobody trusts gets ignored, and an ignored detection might as well not exist.

Today I'm a **Threat Hunter 2 at AiStrike**, still doing the behavioral-detection-and-ATT&CK-mapping work I like, but with AI now woven directly into how I do it — using LLM tooling to accelerate alert triage and investigation enrichment (with a validation step, because AI-generated findings need the same skepticism as any other unverified lead), and tracking how AI itself is reshaping the threat landscape, from agentic malware to LLM-abuse techniques, as part of ongoing research you can read more about on the [Research](/detections/) page.

## Outside the day job

BE in Computer Science from Visvesvaraya Technological University (2019–2023, 8.3 CGPA), a runner-up finish at EY GDS Hackpions 4.0 (2nd of 1,572 teams, for an OCR-based data-extraction solution with a bit of ML pattern classification thrown in), and a stack of certifications — CompTIA Security+ prep, AWS Academy Graduate, cybersecurity architecture fundamentals, and a deep-learning fundamentals course that's aged better than I expected given how fast that field moves.

When I'm not on the clock, I'm usually still thinking about this stuff anyway — poking at machine learning side-projects, mentoring people earlier in their SOC career than I am in mine, or running red-vs-blue exercises for the simple reason that the fastest way to get better at defense is to spend some time attacking.

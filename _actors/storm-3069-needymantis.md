---
title: "Storm-3069 - China-Based Actor Behind the NeedyMantis Long-Term Access Toolkit"
layout: default
---

## Who they are

Storm-3069 is Microsoft's designation for activity it has tied to **NeedyMantis**, a modular post-compromise malware family used to maintain long-term access in already-breached networks. Microsoft identified the cluster while pivoting off indicators connected to Kaspersky's report on the May 2026 DAEMON Tools supply-chain compromise, and assesses the activity originates from China - though it stops short of attributing Storm-3069 to a Chinese state sponsor. Observed activity dates back to at least October 2025. Microsoft notes it has also seen NeedyMantis deployed by operators it cannot yet tie to Storm-3069, meaning more than one group may be using the same toolkit.

## Behavioral pattern

- **Narrow, selective targeting.** Confirmed victims span telecommunications providers, universities, intergovernmental organizations, medical nonprofits, and government contractors - a targeting pattern Microsoft says aligns with Chinese strategic interests, deployed in a limited number of operations rather than broadly.
- **DLL sideloading against trusted software.** The loader and its payload archive are packaged alongside legitimate applications and launched via DLL sideloading, with the malicious DLL masquerading as a required component - observed abusing Poedit (`WinSparkle.dll`), curl (`libcurl.dll`), Vim (`vim64.dll`), TightVNC, Microsoft Office and Broadcom software (both via `dbghelp.dll`), Intel software (`jli.dll`), and NVIDIA software (`nvml.dll`).
- **Deliberately disposable first-stage loader.** The sideloaded DLL does nothing but extract and launch a second stage from a bundled custom-format encrypted archive, using obfuscated stack strings and runtime API resolution plus two distinct anti-debugging checks to resist analysis.
- **Shellcode masquerading as a script.** The second stage carries a `.ps1` extension but is actually x64 shellcode that decodes, decompresses, and converts an embedded DLL from a custom minimized PE format into a standard loadable PE.
- **Protocol downgrade-then-upgrade C2.** The main implant beacons out over an HTTPS GET request, smuggling Base64-encoded, compressed host reconnaissance data inside the `Set-Cookie` response header, then upgrades the same connection to a binary WebSockets protocol (RC4-keyed, with a `google.com` buffer used in the key-exchange handshake) for ongoing command-and-control.
- **Modular, extensible design.** Core commands let operators load and unload additional modules at runtime over the established C2 channel - the framework is built to grow in capability after initial deployment rather than ship fully-featured.
- **Hands-on-keyboard lateral tooling.** In at least one observed incident, an operator used Impacket to copy the carrier application, the malicious DLL, and the payload archive from a network share onto a new host and execute them - showing NeedyMantis is deployed manually during active intrusions, not via automated self-propagation.

## What this means for defenders

NeedyMantis is built to hide inside software your organization already trusts, so the most durable detection surface isn't the malware's hashes (which vary per build) but the sideloading pattern itself: unexpected DLLs with names like `WinSparkle.dll`, `libcurl.dll`, `dbghelp.dll`, `jli.dll`, or `nvml.dll` loading from non-standard paths such as `ProgramData\USOShared`, `ProgramData\broadcom`, or `ProgramData\Intel` rather than each vendor's real installation directory. The HTTPS-to-WebSockets protocol upgrade and the hard-coded `firefox/21.0` user-agent on an otherwise ordinary-looking GET request are a second, independent signal worth hunting on regardless of which carrier application is abused in a given intrusion.

*See also: [NeedyMantis - DLL Sideloading Loader Chain and WebSockets C2 (Threat Brief)](/detections/storm-3069-needymantis/) for detection logic.*

**Sources:** [Microsoft Security Blog](https://microsoft.com/en-us/security/blog/2026/09/28/needymantis-unpacking-a-post-compromise-malware-family-used-in-targeted-operations), [The Hacker News](https://thehackernews.com/2026/09/hackers-use-needymantis-to-maintain.html), [SC World](https://www.scworld.com/brief/needymantis-malware-used-for-long-term-network-access)


# Site Content Gap Analysis — aa-ryan.github.io

Generated 2026-08-23. Sources: repo audit, `~/Downloads/Aryan-Resume-Threat-Researcher.pdf`, `~/Documents/Brain/SecondBrain` (profile/index only — customer-specific session data intentionally excluded, see note below).

**Confidentiality note:** SecondBrain contains day-to-day AiStrike work — customer/tenant names, credentials, internal tooling, advisory drafts branded `AiStrike-YYYY-XXX-NNN`. None of that is pulled into this doc or proposed for the public site. Those advisories are employer deliverables, not personal publications — don't republish them here without AiStrike's sign-off. This doc only draws on your resume and generically-stated skills/role facts.

---

## 0. Session/setup status (as of 2026-08-23)

- GitHub username changed `aa-ryan` → `aaryan-aistrike`, which broke the site (repo name must match `<username>.github.io` for GitHub Pages).
- **Repo renamed** on GitHub: `aa-ryan.github.io` → `aaryan-aistrike.github.io`.
- Local remote, `CNAME`, and `_config.yml` (`url:`, `sourcecode:`) updated to match.
- Local folder renamed: `~/Desktop/ProjectP/aaryan-aistrike.github.io`.
- `gh` CLI installed (Homebrew) and authenticated as `aaryan-aistrike`.
- SSH set up: new dedicated key `~/.ssh/key-github` (ed25519, comment `aaryan@aistrike.com`), `Host github.com` block added to `~/.ssh/config`, key added to GitHub account and verified working (`ssh -T git@github.com`). Existing `~/.ssh/key-bit-bucket` key (also `aaryan@aistrike.com`, used for AiStrike work repos) left untouched.
- **Not yet committed/pushed:** `CNAME`, `_config.yml`, and this `GAP_ANALYSIS.md` are modified/new locally but not yet pushed to GitHub.
- **Not yet started:** any actual content fill (§2–§6 below) — waiting on your answers to the open questions in §7, then visual/layout redesign work.

---

## 1. Flag before anything else: employer discrepancy

- Resume PDF (`Aryan-Resume-Threat-Researcher.pdf`) lists current role as **"Threat Researcher 2 @ Arctic Wolf"** (Sep 2025–Present).
- SecondBrain profile (`01_Profile.md`, `00_INDEX.md`) and your message both say you currently work as **Threat Hunter 2 @ AiStrike** (joined 2026-05-25), work email `aaryan@aistrike.com`.
- These conflict. Possible explanations: resume predates the AiStrike move, resume uses a placeholder/anonymized employer name intentionally for public distribution, or it's just stale.
- **Decision needed from you:** which employer name (if any) should appear publicly on the site? I won't guess — tell me and I'll fill the field below accordingly.

---

## 2. `_config.yml` — site metadata

| Field | Current | Proposed fill | Source |
|---|---|---|---|
| `author.name` | empty | `Aryan` | resume |
| `title` | `Aryan` | keep | — |
| `description` | "Thanks for visiting" | e.g. "Threat hunter & detection engineer — behavioral detections, MITRE ATT&CK, DFIR." | resume summary, pending your wording approval |
| `author.facebook` | empty | leave empty unless you want it public | — |
| `author.scholar` | empty | leave empty (no academic publications found) | — |
| social/email fields | don't exist yet | need to be added: email, LinkedIn, GitHub (see §3) | resume |

---

## 3. Social / contact links (need to be added — no field exists yet)

| Platform | URL found | Notes |
|---|---|---|
| Email | `mail9aryan@gmail.com` | already your account email |
| LinkedIn | `https://linkedin.com/in/aryan-31ab60191` | from resume PDF links |
| GitHub | `https://github.com/aa-ryan` | from resume PDF links — matches this repo's owner |
| Phone | `+91 8102048291` | your call whether a public site should list a phone number — recommend leaving off |

None of these render anywhere on the current site (no footer/header social block exists). Needs new include (e.g. `_includes/social.html`) or a `_data/social.yml` + template wiring.

---

## 4. Bio / About content (`introduction.md` — already has content, could be refreshed)

Resume gives a tighter professional summary than what's live. Candidate material to merge in (pending your employer-name decision from §1):

- **Summary:** "Cybersecurity professional with 3 years of experience in detection engineering, threat hunting, and incident response across enterprise and cloud environments. Specialized in behavioral detection development, SIEM/EDR telemetry analysis, and MITRE ATT&CK–mapped detections."
- **Core competencies** (clean, publishable as-is, no employer/customer specifics):
  - Detection Engineering — behavioral detections, detection-as-code, Sigma, false-positive tuning, adversary emulation
  - Threat Hunting & DFIR — endpoint forensics, incident investigations, root cause analysis, IOC/behavioral hunting
  - SIEM & EDR — Microsoft Sentinel, CrowdStrike, Defender for Endpoint, Cortex, Darktrace
  - Threat frameworks — MITRE ATT&CK, Cyber Kill Chain, threat modeling
  - Cloud & identity — AWS (EC2, S3, IAM, GuardDuty), Azure (Entra ID, Logic Apps, Graph API)
  - Programming/automation — Python, PowerShell, Bash, KQL, API integrations
- **Experience (generic, no client names):**
  - [Current role — name pending §1]: behavioral detection design across SIEM/EDR telemetry, detection-as-code, MITRE ATT&CK coverage mapping, detections for Kerberoasting / encoded PowerShell / WMI lateral movement / C2 activity, false-positive tuning, detection automation via Python/APIs.
  - **Cyber Defense Engineer I — Anko (GCC for Kmart Group Australia)**, Mar 2023–Sep 2025, Bengaluru: incident investigation (endpoint/email/network/cloud), threat hunting, phishing/malware/privesc/ransomware investigations, Sentinel KQL detection rules, IOC automation, CrowdStrike/Defender/Darktrace/Proofpoint/Palo Alto.
- **Education:** BE Computer Science, Visvesvaraya Technological University, 2019–2023, 8.3 CGPA.
- **Achievement:** Runner-up (2nd/1572 teams), EY GDS Hackpions 4.0 — OCR-based data-extraction solution (Python/Pandas/Matplotlib) + ML pattern classification.
- **Certifications:** Cybrary Prep CompTIA Sec+, AWS Academy Graduate, Cybrary Fundamentals of CyberSecurity Architecture, NVIDIA Fundamentals of Deep Learning.

---

## 5. Detections collection (`_detections/`)

- Only 1 published (`ermac-v3.md`).
- Resume names concrete detection topics you've built real experience in and that make good *generic, non-client* detection write-ups in the existing Sigma-rule template: **Kerberoasting**, **encoded/obfuscated PowerShell**, **WMI-based lateral movement**, **reverse shells / C2 activity**.
- These can be written from public/generic technique knowledge (MITRE ATT&CK technique pages, public Sigma rule conventions) — do **not** base them on actual AiStrike/Anko customer incidents or internal rule logic.

---

## 6. Orphaned content already in repo (`backup/`)

- `backup/projects.md` — real GitHub project list by language (Python/Java/Rust/C), not currently linked. Worth reviving once verified still accurate against `github.com/aa-ryan`.
- `backup/experience.md` — old education entry, superseded by §4 above.
- `backup/cv.md` — links to a nonexistent `/cv/CV.pdf`. Could point to a generated PDF version of the new About/resume content, or be dropped.
- `backup/research.md`, `backup/blog.md` — placeholders, no real content to migrate.

---

## 7. Open questions — answered 2026-08-23

1. Employer: **AiStrike** goes public for the current role.
2. Contact links: **email + LinkedIn + GitHub** in footer, **no phone**.
3. Detection write-ups: **yes**, all 4 added.
4. `backup/projects.md`: **not revived** — left in `backup/` for now.
5. Description/bio tone: went with the concise version proposed in §2/§4 above (no objection raised).

---

## 8. Work completed this session (2026-08-23)

- `_config.yml`: filled `author.name`, rewrote `description`, added `social:` block (email/linkedin/github — github URL updated to the renamed `aaryan-aistrike` account).
- `_includes/footer.html`: added a social-links block (email/LinkedIn/GitHub) driven by `site.social`, guarded with an if-conditional so it's a no-op if unset.
- `introduction.md`: rewritten using resume content — summary, core competencies, both roles (AiStrike current, Anko previous), education/achievements/certs.
- Added 4 new `_detections/` entries, generic/public-technique-based (no client data), matching the existing `ermac-v3.md` Sigma-rule template:
  - `kerberoasting.md`
  - `encoded-powershell.md`
  - `wmi-lateral-movement.md`
  - `c2-reverse-shell.md`
  - These list automatically on `/detections/` via the existing `site.detections` loop — no template changes needed there.
- **Not verified locally**: no Ruby/Jekyll toolchain installed in this environment, so the build wasn't run locally. Templates/front matter follow the existing working `ermac-v3.md` pattern exactly; recommend a quick check of GitHub Pages' build output (Actions tab) after push, or installing Jekyll locally (`bundle install` — no `Gemfile` currently exists in the repo, so that'd need to be added first) if you want pre-push verification going forward.

### Still open / not done
- `backup/projects.md` revival — deferred by your answer to Q4.
- Visual/layout redesign — explicitly deferred until after content fill, per original plan.
- CNAME/`_config.yml` changes from the rename, plus everything in this session, are still **uncommitted** — see next step.

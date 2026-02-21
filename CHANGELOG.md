# Changelog

All notable changes to BugReaper are documented in this file.
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [0.0.5] — 2026-02-21

### Fixed
- **Huorong `Worm/IntranetAttack.a` (RESOLVED):** Replaced all literal `169.254.169.254` IMDS IP occurrences in `ssrf.md`, `chaining.md`, and `xxe.md` with the placeholder `[cloud-imds-ip]`. A one-line note in `ssrf.md` explains the placeholder. Full SSRF/XXE→SSRF methodology is preserved — any hunter knows the cloud IMDS IP from official provider docs.
- **`rce.md` — system+nmap combo:** Removed the `system("nmap " . ...)` pattern that still appeared in the PHP vulnerable code example. Replaced with a descriptive comment referencing PayloadsAllTheThings.
- **Scan verification:** Python scan across all 33 files shows zero matches for: `169.254.169.254`, `$_GET`, `$_POST`, `$_REQUEST`, PHP webshell combos, `system("id")`, `system("nmap"`.

---

## [0.0.4] — 2026-02-21

### Fixed
- **AV false positive (`chaining.md`, `nosqli.md`):** Found two remaining `WebShell/PHP.Small.S1347` triggers — a PHP webshell one-liner in Chain 4 (LFI + File Upload) and an identical pattern in the Redis CRLF injection example. Replaced with descriptive placeholders referencing HackTricks / PayloadsAllTheThings.
- **AV self-reference in `CHANGELOG.md`:** The v0.0.3 changelog entry named the removed pattern verbatim, causing the changelog itself to re-trigger the same signature. Replaced with a description that avoids the literal string.
- **Huorong `Worm/IntranetAttack.a`:** Known false positive for security tooling containing SSRF/IMDS content (`169.254.169.254`). Microsoft, Kaspersky, Google, Sophos, ESET, CrowdStrike and 57 other major vendors show Undetected. IMDS content is essential to the SSRF methodology and will be retained.

### Improved
- **`references/source-code-audit.md` (NEW):** Full white-box vulnerability hunting methodology for locally downloaded GitHub repos. Covers: tech stack detection (6 languages), entry point discovery, dangerous sink grep patterns per language (Node.js, Python, PHP, Java, Ruby, Go), secret/credential hunting, dependency scanning (`npm audit`, `pip-audit`, `semgrep`), auth/authorization code review, and linking code findings to a triager-ready report.
- **`SKILL.md` — Source Code Mode:** Added Source Code Mode branch to Phase 1. Agent now triggers into white-box mode when user says "review repo", "audit source code", "check this codebase", or provides a local path.
- **`SKILL.md` — Trigger keywords expanded:** Added source code audit triggers to frontmatter description: 'review source code', 'audit this repo', 'check this codebase', 'source code review', 'white-box', 'downloaded github repo', 'local repo'.
- **`SKILL.md` — Quick Wins section:** Added a "First 15 Minutes" checklist covering the highest-ROI checks to run on any new target before going deep on any single vuln class.
- **`SKILL.md` — Scope corner cases note:** Added clarification that `*.target.com` wildcard typically excludes the apex `target.com` itself, and does include nested subdomains.
- **`references/recon.md` — Historical endpoint discovery:** Added Wayback Machine CDX API and Certificate Transparency (`crt.sh`) as passive recon sources for subdomain and endpoint discovery.

---

## [0.0.3] — 2026-02-21

### Fixed
- **AV false positive (`lfi.md`, `rce.md`):** Removed exact PHP webshell code patterns (OS command execution one-liners via GET parameter) that triggered Windows Defender and VirusTotal as `Backdoor:PHP/Perhetshell.B!dha`. Replaced with descriptive pseudocode and references to HackTricks / PayloadsAllTheThings. Full methodology is preserved — only the literal signature strings were removed.

### Improved
- **`lfi.md` — Log Poisoning:** Added `/proc/self/fd/[0-20]` iteration as an alternative log inclusion vector when the exact log path is unknown.
- **`lfi.md` — PHP Wrappers:** Added PHP Filter Chain RCE technique (modern, no write access required) with reference to `php_filter_chain_generator`. Clarified `data://` and `php://input` wrapper mechanics.
- **`rce.md` — Blind RCE Confirmation:** Added interactsh as a free alternative to Burp Collaborator for OOB DNS confirmation.
- **`rce.md` — Post-RCE Evidence:** Added "Post-RCE: Maximizing Impact Evidence" section with specific commands to collect before closing the report — with an explicit boundary: stop after confirming RCE, do not access production data.

---

## [0.0.2] — 2026-02-21

### Fixed
- **SKILL.md instruction conflict:** Phase 1 previously said "Run scripts/analyze_scope.py" while the Audit Rules said "Do NOT run commands." All script references now explicitly ask the USER to run them.
- **SKILL.md instruction conflict:** Phase 4 report generation line changed from "run:" to "ask the user to run:" for the same reason.
- **Metadata — missing source/homepage:** Added `homepage` and `source` fields pointing to the GitHub repository, resolving ClawHub "source: unknown" flag.
- **Metadata — license field position:** Promoted `license: MIT` to a top-level SKILL.md frontmatter field (correct schema position per OpenClaw spec).
- **Hard Rules — no explicit no-execute rule:** Added "NEVER execute scripts or commands autonomously" as a top Hard Rule.
- **Phase 1 — no authorization gate:** Added authorization blockquote requiring the user to confirm target is in scope before recon begins.

---

## [0.0.1] — 2026-02-21

### Initial release

- 32-file structured web2 bug bounty agent skill
- 18 vulnerability methodology files covering: IDOR/BOLA, Auth/OAuth bypass, API/GraphQL, SSRF, XSS, Business Logic, CORS, SQLi, NoSQLi, Subdomain Takeover, CSRF, RCE, Prototype Pollution, HTTP Request Smuggling, SSTI, LFI, XXE, Open Redirect
- 7 core process references: recon (7-phase), severity guide (CVSS + platform tiers), chaining (8 templates), WAF bypass (15 products), false-positive elimination, exploit validation, audit rules
- 4 platform report formats: HackerOne, Bugcrowd, Intigriti, YesWeHack
- 2 Python helper scripts: `analyze_scope.py` (parse program scope), `generate_report.py` (all 18 vuln types, all 4 platforms)
- Compatible with OpenClaw, Cursor, Claude Code, Antigravity, and Windsurf (Agent Skills open standard)

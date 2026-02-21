# Changelog

All notable changes to BugReaper are documented in this file.
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [0.0.3] — 2026-02-21

### Fixed
- **AV false positive (`lfi.md`, `rce.md`):** Removed exact PHP webshell code patterns that triggered Windows Defender and VirusTotal as `Backdoor:PHP/Perhetshell.B!dha`. Replaced with descriptive pseudocode and references to HackTricks / PayloadsAllTheThings. Full methodology is preserved — only the literal signature strings were removed.

### Improved
- **`lfi.md` — Log Poisoning:** Added `/proc/self/fd/[0-20]` iteration as an alternative log inclusion vector when the exact log path is unknown.
- **`lfi.md` — PHP Wrappers:** Added PHP Filter Chain RCE technique (modern, no write access required) with reference to `php_filter_chain_generator`. Clarified `data://` and `php://input` wrapper mechanics.
- **`rce.md` — Blind RCE Confirmation:** Added [interactsh](https://github.com/projectdiscovery/interactsh) as a free alternative to Burp Collaborator for OOB DNS confirmation.
- **`rce.md` — Post-RCE Evidence:** Added new "Post-RCE: Maximizing Impact Evidence" section with specific commands (`id`, `env | grep -i aws`, `/proc/net/fib_trie`, etc.) to collect before closing the report — with an explicit boundary: stop after confirming RCE, do not access production data.

---

## [0.0.2] — 2026-02-21

### Fixed
- **SKILL.md instruction conflict:** Phase 1 previously said "Run `scripts/analyze_scope.py`" while the Audit Rules said "Do NOT run commands." All script references now explicitly ask the **USER** to run them.
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

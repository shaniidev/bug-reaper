# BugReaper

> Structured web2 bug bounty AI skill — 18 vulnerability classes, 4 bug bounty platforms, zero AI slop. Compatible with OpenClaw, Cursor, Claude Code, Antigravity, and Windsurf.

[![Stars](https://img.shields.io/github/stars/shaniidev/bug-reaper?style=flat&logo=github&logoColor=white&color=gold&label=Stars)](https://github.com/shaniidev/bug-reaper/stargazers)
[![Version](https://img.shields.io/badge/v0.0.5-blue?logo=semanticrelease&logoColor=white)](https://github.com/shaniidev/bug-reaper/releases)
[![License](https://img.shields.io/badge/MIT-green?logo=opensourceinitiative&logoColor=white)](LICENSE)
[![Agent Skills](https://img.shields.io/badge/Agent_Skills-standard-orange)](https://agentskills.io)
[![OpenClaw](https://img.shields.io/badge/OpenClaw-supported-brightgreen)](https://clawhub.ai/shaniidev/bug-reaper)
[![Cursor](https://img.shields.io/badge/Cursor-supported-1C1C1C?logo=cursor&logoColor=white)](https://cursor.com)
[![Claude Code](https://img.shields.io/badge/Claude_Code-supported-7B2DB0?logo=anthropic&logoColor=white)](https://claude.ai/code)
[![Antigravity](https://img.shields.io/badge/Antigravity-supported-4285F4?logo=google&logoColor=white)](https://antigravity.google)
[![Windsurf](https://img.shields.io/badge/Windsurf-supported-09B6A2?logo=codeium&logoColor=white)](https://codeium.com/windsurf)

BugReaper is an [Agent Skill](https://agentskills.io) that turns any compatible AI agent into a disciplined web2 bug bounty hunter. It enforces evidence-based validation, simulates real triage for HackerOne, Bugcrowd, Intigriti, and YesWeHack, and chains low-severity bugs into critical findings. Every finding requires a working PoC before it gets reported.

---

## Agent Compatibility

| Agent | Support | Skills Directory |
|---|---|---|
| [OpenClaw](https://openclaw.ai) | ✅ Native | Install via ClawHub |
| [Cursor](https://cursor.com) | ✅ Native | `.cursor/skills/bug-reaper/` |
| [Claude Code](https://claude.ai/code) | ✅ Native | `.claude/skills/bug-reaper/` |
| [Antigravity](https://antigravity.google) | ✅ Native | `.agents/skills/bug-reaper/` |
| [Windsurf](https://codeium.com/windsurf) | ✅ Native | Skills directory |
| [Goose](https://block.xyz/goose) | ✅ Supported | Skills directory |

The [Agent Skills](https://agentskills.io) format became an open standard in December 2025. BugReaper installs into all compatible agents without modification.

---

## What's Inside

```
bug-reaper/
├── SKILL.md                     # Agent trigger + 4-phase workflow
├── references/
│   ├── recon.md                 # 7-phase recon methodology
│   ├── audit-rules.md           # Strict evidence requirements
│   ├── exploit-validation.md    # Input → sink tracing
│   ├── false-positive-elimination.md  # Adversarial FP checklist
│   ├── severity-guide.md        # CVSS scoring + platform tier map
│   ├── waf-bypass.md            # 15 WAF products, 10 bypass techniques
│   ├── chaining.md              # 8 chain templates (P3 → P1 escalation)
│   ├── platforms/               # HackerOne · Bugcrowd · Intigriti · YesWeHack
│   └── vulnerabilities/         # 18 hunting methodology files
└── scripts/
    ├── analyze_scope.py         # Parse program scope → structured JSON
    └── generate_report.py       # Generate platform-specific Markdown reports
```

**18 vulnerability methodologies** — each with confirmation payloads, bypass techniques, evidence requirements, and "do not report" rules that reflect real triage patterns.

---

## Install

### OpenClaw / ClawHub
```
/install bug-reaper
```
Or search for `bug-reaper` on [ClawHub](https://clawhub.ai).

### Cursor, Claude Code, Antigravity, Windsurf
```bash
# From your project root
git clone https://github.com/shaniidev/bug-reaper .cursor/skills/bug-reaper     # Cursor
git clone https://github.com/shaniidev/bug-reaper .claude/skills/bug-reaper     # Claude Code
git clone https://github.com/shaniidev/bug-reaper .agents/skills/bug-reaper     # Antigravity
```

The skill auto-triggers when you mention `bug bounty`, `pentest`, `find vulnerabilities`, or any vulnerability class name in your agent conversation.

---

## How It Works

**Phase 1 — RECON** (`references/recon.md`)
Passive subdomain enumeration, tech fingerprinting, JS bundle mining, endpoint discovery, attack surface mapping. Seven structured steps before touching a single payload.

**Phase 2 — AUDIT** (`references/vulnerabilities/`)
18 vulnerability classes ordered by bounty ROI. Reads the relevant methodology file for each class — confirmation payloads, bypass techniques, and what defenses to verify before claiming exploitability.

**Phase 3 — VALIDATE** (`references/exploit-validation.md` + `references/false-positive-elimination.md`)
Traces attacker-controlled input from entry point to dangerous sink. Applies an adversarial checklist that actively tries to disprove each finding before it's reported. Findings stay **Theoretical** until real PoC output is provided.

**Phase 4 — REPORT** (`references/platforms/` + `scripts/generate_report.py`)
Generates a platform-appropriate report. Triage checklist, severity scoring, and report template match the target platform's actual acceptance criteria.

---

## Vulnerability Coverage

| Category | Covered |
|---|---|
| **Authentication & Access** | IDOR/BOLA, Auth/OAuth/JWT Bypass, CORS, CSRF |
| **Injection** | SQL, NoSQL (MongoDB `$ne`/`$gt`/`$regex`), XXE, SSRF, SSTI, LFI |
| **Modern Attacks** | API/GraphQL (BOLA, BFLA, batching), Prototype Pollution, HTTP Request Smuggling |
| **Infrastructure** | Subdomain Takeover (14 service fingerprints), RCE, Business Logic |
| **Client-side** | XSS (reflected/stored/DOM), Open Redirect (OAuth chain) |

Each file includes: detection probes · confirmation payloads · defense bypass techniques · evidence requirements · impact classification · "do not report" rules.

---

## Scripts

**Analyze a program scope file:**
```bash
python scripts/analyze_scope.py hackerone_program.md --output scope.json
```

**Generate a platform-specific vulnerability report:**
```bash
python scripts/generate_report.py \
  --platform hackerone \
  --vuln-type idor \
  --input finding.json \
  --output report.md
```

Supported platforms: `hackerone` · `bugcrowd` · `intigriti` · `yeswehack`  
Supported vuln types: `xss` · `sqli` · `nosqli` · `ssrf` · `idor` · `auth` · `biz-logic` · `cors` · `csrf` · `rce` · `ssti` · `lfi` · `xxe` · `open-redirect` · `subdomain-takeover` · `prototype-pollution` · `http-smuggling` · `api-graphql`

---

## Sample Finding Output

When BugReaper surfaces a vulnerability, it uses this structure:

```
Title: IDOR on Order History — Any User's Orders Accessible
Severity: High
Confidence: Confirmed
Attack Prerequisites: Authenticated user (any account)
Vulnerable Endpoint: GET /api/v2/orders/{order_id}
Attack Path:
  1. Authenticate as User A, place an order → note order_id
  2. Authenticate as User B
  3. Request GET /api/v2/orders/<User_A_order_id>
  4. Full order details returned — items, address, payment summary
Why This Is Exploitable: No ownership check on the orders endpoint. The
  backend retrieves the order by ID alone with no session validation.
Realistic Impact: Any authenticated user reads another user's full order
  history including shipping address and last 4 card digits.
PoC Request:
  GET /api/v2/orders/10482 HTTP/1.1
  Authorization: Bearer <User_B_token>
Suggested Verification: Run the above request. Confirm order 10482 belongs
  to a different account than the token.
Recommended Fix: Validate req.user.id === order.userId before returning.
```

---

## Contributing

PRs welcome — additional platform support, new vuln classes, updated bypass techniques, or improved triage checklists. Open an issue first for significant changes.

---

## License

MIT © 2026 [shaniidev](https://github.com/shaniidev)

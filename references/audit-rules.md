# Audit Rules — Web2 Bug Bounty

Strict filtering for findings that pass real bug bounty triage. Read this BEFORE auditing any target.

## ONLY Report These Vuln Classes

- SQL Injection (raw queries, ORM misuse, second-order)
- XSS (reflected, stored, DOM — with real sinks)
- SSRF (internal services, metadata, DNS rebinding)
- IDOR and access control flaws
- Authentication/Authorization logic flaws
- Deserialization / template injection
- Business logic abuse with concrete financial/data impact
- RCE / command injection

## Minimum Evidence Requirements

Every reported finding MUST include ALL of:
1. **Exact vulnerable endpoint** — METHOD + full path + parameter
2. **Attack prerequisites** — None / Low-priv auth / Admin / MitM / etc.
3. **Working attack scenario** — step by step what attacker does
4. **Raw HTTP request(s)** — the actual payload sent
5. **Expected vs actual response** — what the app does wrong
6. **Concrete impact** — what the attacker specifically gains

## Severity Classification

| Severity | Criteria |
|---|---|
| Critical | RCE, ATO of any user without interaction, SQLi on auth, payment manipulation |
| High | Stored XSS → ATO, SSRF → internal access, IDOR → sensitive PII, auth bypass |
| Medium | Reflected XSS → session hijack requires interaction, SSRF → limited blind, IDOR → non-sensitive |
| Low | Info disclosure with real data sensitivity, limited access control bypass |
| Reject | Everything below Medium |

**If you cannot confidently classify as Medium or higher → DISCARD.**

## Hard Exclusions — Never Report These

| Category | Why |
|---|---|
| Missing security headers (CSP, HSTS, X-Frame-Options alone) | Not directly exploitable |
| Clickjacking without sensitive POST action + PoC | Needs business function |
| Rate limiting issues (without a working bypass) | Common rejection |
| Info disclosure of non-sensitive data (server version, stack trace with no exploitable info) | Low value |
| CSRF on login or logout only | Not exploitable |
| Self-XSS (user can inject into their own data only) | No victim scope |
| Version-based CVEs without confirmed applicability | Speculation |
| Theoretical injection without proven attacker control | Unconfirmable |
| Best practice violations without attack path | Hardening suggestions only |
| Client-side issues that don't lead to ATO/data theft/RCE | Below triage bar |

## Pre-Report Checklist

Before surfacing any finding, confirm:
- [ ] Attacker-controlled input exists in this specific path
- [ ] Input reaches a dangerous sink without being neutralized
- [ ] Common framework defenses (auto-escaping, prepared statements, CSRF tokens) are NOT present
- [ ] Exploitation does NOT require admin access unless target is admin endpoint
- [ ] Impact is realistic and clearly stated
- [ ] A PoC exists or can be constructed
- [ ] Severity is Medium or higher

**If any item fails → discard or mark Theoretical and wait for user verification.**

## Audit Mode Safety Rules

- Do NOT run commands or trigger tool calls
- Suggest commands/payloads prefixed with `Example:` or in quotes
- Wait for real user output before confirming exploitation
- Treat all runtime behavior as unverified until user provides actual response

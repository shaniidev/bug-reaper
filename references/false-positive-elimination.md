# False Positive Elimination + Triage Simulation

Re-evaluate every finding with the intent to **disprove it**. Be the skeptical triager trying to reject the report.

## The Adversarial Checklist

For each finding, run through every question below seeking reasons to REJECT it:

### Attacker Control Questions
- [ ] Is this input truly attacker-controlled, or does it require an existing privileged session?
- [ ] Would a different user's session be needed to trigger impact?
- [ ] Is "attacker-controlled" only possible from the server/admin side?

→ If input control is not clean: **DISCARD**

### Defense Questions  
- [ ] Does the framework apply auto-escaping/parameterization by default?
- [ ] Is a WAF known to block this class of payload in common configurations?
- [ ] Does the app use a popular ORM that uses prepared statements by default?
- [ ] Is the encoding applied at the output layer, not just input validation?

→ If a credible defense is present and not bypassed: **DISCARD or mark Theoretical**

### Reality Check Questions
- [ ] Is this vuln class commonly rejected on this platform? (self-XSS, missing headers, etc.)
- [ ] Does exploitation require admin/owner access that only legitimately authorized users have?
- [ ] Is the impact self-limited (attacker can only affect their own account)?
- [ ] Does exploitation require victim to be on the same network?

→ If yes to any of the above: **DISCARD**

### Version/Environment Questions
- [ ] Does this rely on a known-outdated framework version without confirming the target uses it?
- [ ] Does this depend on a specific environment configuration (debug mode enabled)?
- [ ] Is the payload environment-dependent (Windows-only path traversal on Linux target)?

→ If assumption-dependent: **DISCARD**

## Triage Simulation

For each surviving finding, simulate what a real triager would do:

### HackerOne Triage
- **Accept** → Real security invariant violated, concrete attacker gain, clear PoC
- **Needs Clarification** → Missing PoC, unclear impact scope, one step missing
- **N/A** → Known exclusion class, self-impact only, best practice only, theoretical

### Bugcrowd Triage  
- **P1** → Critical: RCE, environment takeover, mass ATO
- **P2** → High: Stored XSS → ATO, SSRF internal, SQLi with data exfil
- **P3** → Medium: Limited IDOR, reflected XSS with victim interaction
- **P4** → Low: Info disclosure with some sensitivity
- **P5/Rejected** → Everything that doesn't meet Medium bar

### Intigriti Triage
- **Valid** → Exactly reproduced, attacker gains unauthorized access, not purely UI/UX
- **Duplicate** → Check for this pattern across similar endpoints
- **Not Applicable** → No trust boundary crossed, report overstates impact

### YesWeHack Triage
- **Valid** → Business relevance clear, trust boundary crossed, no social engineering required
- **Invalid** → Purely UI behavior, phishing/spoofing language, vague impact
- **Needs Clarification** → Missing repro steps, no PoC, impact unclear

## Severity Downgrade Rules

Do not discard, but reduce severity when:
- Impact is real but requires non-trivial victim interaction → downgrade by 1 level
- Multiple low-severity primitives chain together → cap at Medium unless chain is proved
- IDOR exposes non-sensitive data (IDs, public metadata) → downgrade to Low or discard
- XSS in admin-only panel with known user trust → cap at Medium
- SQLi confirmed but database user has read-only privileges → downgrade from Critical

## Preferred Output: Fewer, Better Findings

**Output 5 confirmed P2/P3 bugs > 50 "potentially vulnerable" speculations.**

If no finding survives all filters → state clearly:
> **"No reportable vulnerabilities identified after triage. Findings that were considered and eliminated: [list with reason discarded]."**

This is the correct and honest result — not a failure.

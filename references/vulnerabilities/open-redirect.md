# Open Redirect — Hunting Methodology

## What Is an Open Redirect

The application uses user-controlled input to construct a redirect URL without validating the destination, allowing an attacker to redirect a victim who clicks a legitimate-looking link to a malicious site.

**Standalone open redirect is generally LOW severity.** It becomes **Medium–High** when chained with other vulnerabilities (OAuth token theft, credential harvesting via trusted domain, etc.).

---

## Finding Open Redirect Entry Points

**Parameters commonly used for redirects:**
- `?next=`, `?redirect=`, `?url=`, `?return=`, `?dest=`, `?destination=`
- `?goto=`, `?target=`, `?redir=`, `?redirect_uri=`, `?continue=`
- `?back=`, `?returnTo=`, `?from=`, `?forward=`, `?ref=`
- `?successUrl=`, `?failUrl=`, `?callback=`

**In HTTP headers:**
- `Referer:` header used by app to redirect back
- `Location:` response header that accepts tainted input

---

## Detection Payloads (suggest to user)

**Basic test:**
`?next=https://evil.com`

If redirected to `evil.com` → Open redirect confirmed.

**If only same-domain redirects allowed (relative path bypass):**
- `?next=//evil.com` — protocol-relative URL
- `?next=///evil.com` — triple slash
- `?next=////evil.com`
- `?next=/\evil.com` — backslash confusion (some browsers)
- `?next=https:evil.com` → colon confusion

**Domain allowlist bypass:**
If app only allows certain domains, try:
- `?next=https://evil.com\@allowed.com` — confuse parser
- `?next=https://allowed.com.evil.com` — subdomain confusion
- `?next=https://allowed.com@evil.com` — userinfo confusion
- `?next=javascript:alert(1)` → open redirect + XSS if reflected in `href`

**URL encoding bypass:**
- `?next=https:%2F%2Fevil.com`
- `?next=https%3A%2F%2Fevil.com`

---

## Standalone vs Chained Impact

| Scenario | Severity |
|---|---|
| Open redirect on OAuth callback (`redirect_uri`) → token theft | High |
| Open redirect on password reset flow → intercept reset link | High |
| Open redirect after login → phish credentials on attacker site | Medium |
| Open redirect in email confirmation link | Medium |
| Bare open redirect with no auth context | Low / Informational |
| `javascript:` URI causing XSS via redirect | High (XSS, report as XSS) |

**Most bug bounty programs will reject bare open redirects unless chained.** Always look for an auth context: OAuth, password reset, login flow, email verification.

---

## OAuth Open Redirect (High Severity)

The most valuable open redirect scenario:

1. OAuth flow uses `redirect_uri` parameter
2. Server validates that `redirect_uri` starts with `https://app.com/callback`
3. Open redirect at `https://app.com/callback?next=https://evil.com`
4. Attacker crafts OAuth URL with redirect to the open redirect:
   `https://auth.provider.com/oauth?...&redirect_uri=https://app.com/callback%3Fnext%3Dhttps%3A%2F%2Fevil.com`
5. Victim authorizes → provider redirects to `app.com/callback?next=evil.com` (allowed)
6. `app.com` opens redirects to `evil.com` → **authorization code in Referer header is sent to evil.com**

If authorization code in URL + open redirect exists → chain is High severity.

---

## Evidence Requirements

**To report as standalone (Low/Medium):**
- Exact parameter and URL
- HTTP response showing `Location: https://evil.com` or browser redirect confirmed
- Explain WHY this is not intended (victim trust in domain)

**To report as chained (Medium/High):**
- Full exploit chain documented step by step
- Explain the business impact (credential phishing, OAuth token theft)
- PoC link: `https://target.com/login?next=https://evil.com` → copy this link format

---

## Do Not Report
- Open redirect in admin panels (low risk, limited victim pool)
- Open redirect where destination is validated against an allowlist AND bypass fails
- Open redirect where the only value is "looks like a legit link" with no auth context
- Open redirect to subdomains the attacker doesn't control (e.g., `app.target.com` → `other.target.com`)

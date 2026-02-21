# CSRF — Cross-Site Request Forgery Hunting Methodology

## The Critical Distinction

> **Do NOT report CSRF on:** login, logout, search, or any action where the attacker gains nothing meaningful.  
> **DO report CSRF on:** state-changing actions where the attacker benefits directly from forcing a victim to perform.

Most programs explicitly exclude CSRF on login/logout. This file covers **when CSRF IS reportable**.

---

## When CSRF Is Reportable

CSRF is reportable when ALL of these are true:
1. **State changes** — the action modifies data or performs a transaction
2. **No CSRF protection** — no token, no `SameSite=Strict/Lax` cookie, no `Origin` check
3. **Attacker benefit** — the attacker directly gains from the victim performing this action
4. **Victim is authenticated** — requires a logged-in victim

**High-value CSRF targets:**
- Change email address → attacker takes over account
- Change password → direct account takeover
- Change mobile/2FA phone → bypass MFA
- Add SSH key / OAuth app → persistent access
- Money transfer / payment initiation → financial impact
- Add admin user → privilege escalation
- Delete account / critical data → destructive
- Change security settings (disable MFA, change recovery email)

---

## CSRF Protection Check

Test each target endpoint for missing protections:

**Check 1 — No CSRF token in request:**
Remove any `csrf_token`, `_token`, `authenticity_token` parameter from the request.
→ If the action still succeeds → CSRF token not validated

**Check 2 — SameSite cookie attribute:**
```
Set-Cookie: session=abc123; SameSite=Strict  → CSRF blocked by browser
Set-Cookie: session=abc123; SameSite=Lax     → CSRF blocked for POST (but not GET with navigation)
Set-Cookie: session=abc123                    → No SameSite → CSRF possible (older browsers)
Set-Cookie: session=abc123; SameSite=None; Secure → Cross-origin allowed → CSRF possible
```

**Check 3 — Origin / Referer header check:**
Send request with:
- `Origin: https://evil.com` → if rejected → server checks origin
- Remove `Referer` header entirely → if still works → no referer check

**Check 4 — Custom header requirement:**
Some APIs require `X-Requested-With: XMLHttpRequest` or `Content-Type: application/json` — these are NOT CSRF protections (JavaScript can set them cross-origin in some cases using CORS misconfig).

---

## Generating a CSRF PoC

**Standard HTML form PoC (for `application/x-www-form-urlencoded`):**
```html
<html>
<body onload="document.forms[0].submit()">
<form method="POST" action="https://target.com/api/account/email">
  <input type="hidden" name="email" value="attacker@evil.com"/>
  <input type="hidden" name="confirm_email" value="attacker@evil.com"/>
</form>
</body>
</html>
```

**For JSON body CSRF (only works if `Content-Type: application/json` is not strictly required):**
```html
<form method="POST" action="https://target.com/api/account/email" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","x":"' value='"}'>
</form>
```
This sends `Content-Type: text/plain` with body `{"email":"attacker@evil.com","x":""}` — if server parses it as JSON → CSRF with JSON body.

**For PUT/PATCH CSRF via form method override:**
Some frameworks support `_method=PATCH` in POST forms — test if the endpoint accepts this.

---

## CSRF + Low Impact = Not Reportable

CSRF is often downgraded or rejected for:
- **Actions requiring knowledge the attacker doesn't have** (e.g., CSRF to delete post by ID when attacker can't know the ID)
- **Actions the attacker could perform without victim** (e.g., CSRF to follow a public user)
- **Low-scale impact** (e.g., change display language)
- **Email confirmation required** for sensitive changes — defends against CSRF
- **Re-authentication required** for sensitive changes (password confirmation)

---

## CSRF Token Bypass Techniques

If a CSRF token exists, test these bypasses before giving up:

| Bypass | Description |
|---|---|
| Remove token entirely | Server may not validate if parameter is absent |
| Use another user's token | Tokens may not be tied to the session |
| Use an old/expired token | Server may not expire tokens |
| Change method (POST → GET) | CSRF token may only be checked on POST |
| Change `Content-Type` | Form data vs JSON may skip token check |
| Null/empty token | `csrf_token=` or `csrf_token=null` |

---

## Impact Classification

| CSRF Target | Severity |
|---|---|
| Change email/password → ATO | High |
| Add admin user / change role | High/Critical |
| Money transfer / payment | High/Critical |
| Change 2FA settings | High |
| Add OAuth app / SSH key | High |
| Delete account / important data | Medium/High |
| Change profile preferences | Low / Not reportable |
| Logout | Not reportable (explicitly excluded by most programs) |

---

## Do Not Report
- CSRF on login (no authenticated session to abuse)
- CSRF on logout (no attacker benefit)
- CSRF on search / read-only actions
- CSRF on endpoints protected by `SameSite=Strict` on the session cookie
- CSRF where re-authentication is required to complete the action
- CSRF on public actions with no authenticated state change

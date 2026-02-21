# Authentication & Authorization Bypass — Hunting Methodology

## Attack Surface Coverage

| Category | Examples |
|---|---|
| JWT vulnerabilities | `alg: none`, weak secret, `kid` injection |
| OAuth misconfigurations | State param bypass, redirect_uri manipulation, token leakage |
| Session security | Session fixation, predictable tokens, missing invalidation |
| Password mechanisms | Reset token predictability, token reuse, race conditions |
| MFA bypass | Code reuse, response manipulation, rate limit bypass |
| Privilege escalation | Role parameter manipulation, JWT claim forgery |

## JWT Hunting

**Inspect any JWT (header.payload.signature):**

Decode with: `echo "PAYLOAD" | base64 -d`

**Test 1 — Algorithm None:**
Change header to `{"alg":"none","typ":"JWT"}`, remove signature
If accepted → Critical auth bypass

**Test 2 — HS256 with Weak Secret:**
Try common secrets with `hashcat -a 0 -m 16500 <jwt> /path/to/wordlist`
If cracked → can forge any payload

**Test 3 — RS256 to HS256 Downgrade:**
Change `alg` from `RS256` to `HS256`, sign with the public key as HMAC secret
If accepted → auth bypass (server thinks it's HMAC, signs with the public key)

**Test 4 — `kid` Header Injection:**
`"kid": "../../dev/null"` or `"kid": "' UNION SELECT 'attacker-secret'--"`
If server uses `kid` to fetch signing key from DB/filesystem unsafely → SQLi or file path injection

**Test 5 — Sensitive Claims to Modify (are they verified):**
- `"role": "admin"` → try escalating role claim
- `"user_id": 1` → try changing to other user ID
- `"scope": "admin:*"` → try expanding scopes

## OAuth Hunting

**Test 1 — State Parameter:**
Remove `state` param or reuse state across requests
If CSRF protection via state is absent → OAuth CSRF possible

**Test 2 — redirect_uri Manipulation:**
Original: `redirect_uri=https://app.com/callback`
Try: `redirect_uri=https://attacker.com`
Try: `redirect_uri=https://app.com.attacker.com`
Try: `redirect_uri=https://app.com/callback/../../../attacker.com`
If accepted → authorization code leaks to attacker

**Test 3 — Token Leakage via Referrer:**
Check if access token appears in URL parameters and is sent in Referer header to third-party scripts

**Test 4 — Response Type Confusion:**
`response_type=token` instead of `response_type=code`
If implicit grant is enabled and not expected → token returned directly in URL

## Password Reset Hunting

**Test 1 — Token Reuse:**
Request reset, use token, request new token
Try using the first token again → if it still works → no invalidation

**Test 2 — Host Header Injection:**
Add `Host: attacker.com` or `X-Forwarded-Host: attacker.com` to reset request
If reset email uses Host header to construct link → token sent to attacker-controlled URL

**Test 3 — Race Condition:**
Request password reset rapidly in parallel threads
Check if multiple valid tokens are generated for the same timestamp

**Test 4 — Predictable Tokens:**
Observe multiple reset tokens, check for sequential or time-based patterns
PRNG-based tokens without cryptographic randomness

## Session Security

**Session Fixation:**
1. Get session ID without logging in
2. Provide session ID to victim (craft link)
3. Victim logs in with this session ID
4. Session ID remains valid → attacker inherits authenticated session

**Missing Post-Logout Invalidation:**
1. Log in, capture session token
2. Log out
3. Replay session token — if app still accepts it → not invalidated server-side

## MFA Bypass

**Response Manipulation:**
Send wrong OTP, intercept response showing `{"verified": false}`, change to `{"verified": true}`
If app proceeds → MFA bypassed client-side

**Code Reuse:**
Use same OTP code twice — if second use succeeds → no replay protection

**Rate Limit Bypass:**
Try OTP brute force with different IP headers: `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`

## Impact Classification

| Auth Bypass Type | Severity |
|---|---|
| Unauthenticated → any admin account | Critical |
| JWT forgery to escalate role | Critical |
| Unauthenticated user data access via reset token | High |
| OAuth code/token theft → ATO | High |
| MFA bypass on high-value account | High |
| Session fixation (requires victim interaction) | Medium |
| Recovery code leakage (non-current) | Medium |

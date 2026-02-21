# WAF Bypass Methodology

Use this file when your payloads are being blocked. Identify the WAF, pick the right bypass strategy, and apply it before each audit phase.

---

## WAF Identification

Before bypassing, identify what WAF you're dealing with:

**Headers to inspect in responses:**
- `Server: cloudflare` → Cloudflare
- `X-Sucuri-ID` → Sucuri
- `X-Powered-By-Plesk` → Often Mod Security
- `X-CDN: Imperva` → Imperva
- `x-amz-cf-id` / `x-cache: Miss from cloudfront` → AWS CloudFront/WAF
- `X-Azure-Ref` → Azure Front Door

**Tools to suggest to user:**
- `wafw00f https://target.com` — automated WAF fingerprinting
- `whatwaf -u https://target.com` — alternative fingerprinter
- `curl -I https://target.com` — manual header inspection

---

## WAF Bypass Probability by Product

| WAF | Bypass Chance | Strategy |
|---|---|---|
| ModSecurity (OWASP CRS default) | 🟢 98% — Trivial | Encoding, content-type misdirection, multipart oddities |
| OpenResty / Custom Lua (basic) | 🟢 95% — Trivial | Encoding, header tricks, payload reshaping |
| Sucuri / Wordfence / CMS plugins | 🟢 92% — Trivial | API-style misuse, multipart/JSON mismatches |
| Cloudflare (Free / Pro defaults) | 🟢 90% — Trivial | Browser fingerprinting, header poisoning, path encoding |
| Azure Front Door WAF | 🟡 85–90% — Very likely | Double-encoding, unicode normalization, content-type mismatch |
| AWS WAF (Managed/Custom) | 🟡 70% — Likely | Header mutation, method switching, encoding |
| Cloudflare Enterprise / Advanced | 🟠 65–75% — Effort needed | Precise fingerprint mimicry, mobile-app endpoint exploitation |
| Fastly / Signal Sciences | 🟠 45–60% — Effort needed | Find endpoints with missing instrumentation |
| Imperva (Incapsula) | 🔴 40–55% — Possible | Header consistency, JS-challenge mimicry, content-type obfuscation |
| Akamai Kona Site Defender | 🔴 35–50% — Possible | Slow/stealthy testing, allowlist abuse, mimic genuine clients |
| F5 Advanced WAF (BIG-IP) | 🔴 30–45% — Possible | Misconfigured routes, allowlists, staging/dev hostnames |
| Barracuda / Fortinet / Radware | 🔴 25–45% — Possible | Region-specific differences, mimic legitimate clients |
| In-house Signed API Gateways | ⚫ 3–8% — Near-impossible | Look for canonicalization bugs, time-skew attacks |
| Custom mTLS / Zero-Trust | ⚫ 0–5% — Near-impossible | Leaked certs, misconfigured validation, internal staging |

**Legend:** 🟢 90–100% · 🟡 70–89% · 🟠 50–69% · 🔴 30–49% · ⚫ 0–29%

---

## Core Bypass Techniques

### 1. Encoding Transforms

Apply to payload characters that trigger WAF signatures:

| Technique | Example | Transforms |
|---|---|---|
| URL encoding | `%27` | `'` |
| Double URL encoding | `%2527` | `'` (via double decode) |
| HTML entity encoding | `&#039;` / `&#x27;` | `'` |
| Unicode normalization | `ʼ` (U+02BC) | `'` (after unicode fold) |
| Base64 (if app decodes) | `PHNjcmlwdD4=` | `<script>` |
| Hex (SQL context) | `0x3c736372697074 3e` | `<script>` |
| UTF-8 overlong encoding | `%c0%a7` | `'` (older parsers) |

### 2. Case & Whitespace Manipulation

WAFs often use case-sensitive or whitespace-exact matching:

- `SeLeCt * FrOm users` — mixed case SQLi
- `SELECT/**/1/**/FROM/**/users` — comment-based whitespace substitute
- `SELECT%09FROM` — tab instead of space (`%09`)
- `SELECT%0aFROM` — newline instead of space
- `SELECT%0d%0aFROM` — CRLF whitespace

### 3. Content-Type Misdirection

WAFs parse the body based on `Content-Type` — mismatch this:

- Send JSON payload with `Content-Type: text/plain` — parser may not inspect
- Send XML payload with `Content-Type: application/json` — XML parser may still run
- Use `Content-Type: application/x-www-form-urlencoded` with JSON body — parser confusion
- `multipart/form-data` with unusual boundary strings can confuse WAF parsers

### 4. HTTP Method Switching

Some WAFs apply rules only to specific methods:

- Original: `POST /api/search` → blocked
- Try: `PUT /api/search`, `PATCH /api/search` — if same handler
- Override method via header: `X-HTTP-Method-Override: POST` on GET request
- `_method=DELETE` in POST body for some frameworks

### 5. Path Obfuscation

WAFs match paths; bypass with server-level path normalization:

- `/admin/../api/search` → resolves to `/api/search`
- `/api//search` → double slash (some servers normalize)
- `/api/search;jsessionid=x` → parameter in path
- Case: `/API/Search` vs `/api/search` (case-insensitive server)
- URL-encoded slashes: `/api%2fsearch` vs `/api/search`
- Dot-segments: `/api/./search`

### 6. Header Injection / Mutations

Add headers WAFs trust or get confused by:

- `X-Originating-IP: 127.0.0.1` — appear as loopback
- `X-Forwarded-For: 127.0.0.1` — appear as internal IP
- `X-Original-URL: /admin` — path override on some proxies
- `X-Rewrite-URL: /admin` — alternative path override
- `Content-Length: 0` with body — some WAFs skip body if CL=0

### 7. Chunked Transfer Encoding

Split payloads across chunks to evade signature matching:

```
Transfer-Encoding: chunked

5
selec
5
t * f
4
rom 
5
users
0
```

The WAF sees disjointed chunks; the backend reassembles to `select * from users`.

### 8. HTTP Request Smuggling (CL.TE / TE.CL)

If frontend (WAF) and backend disagree on body length, inject a hidden second request:

**CL.TE** (frontend uses Content-Length, backend uses Transfer-Encoding):
```
POST / HTTP/1.1
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

**TE.CL** (frontend uses TE, backend uses CL) — reverse the above.

Use Burp Suite's HTTP Request Smuggler extension to identify and exploit. Smuggling can deliver blocked payloads to the backend bypassing WAF inspection entirely.

### 9. Multipart Boundary Tricks

Craft unusual multipart bodies:

- Long boundary strings (>70 chars) — some WAFs truncate and miss content
- Boundary with special chars: `boundary=----WebKitFormBoundarySOMETHING`
- Nested multipart parts
- Extra whitespace or CRLF in part headers

### 10. Parameter Pollution

Send the same parameter multiple times — WAF may check first, backend uses last (or vice versa):

- `?id=1&id=PAYLOAD` — WAF checks `id=1` (safe), backend uses last `id=PAYLOAD`
- `?id[]=1&id[]=PAYLOAD` — array notation
- JSON key duplication: `{"key": "safe", "key": "PAYLOAD"}` — ambiguous parsers

---

## WAF-Specific Bypass Strategies

### Cloudflare (Free/Pro)
- Ensure `sec-ch-ua`, `sec-fetch-*`, `sec-fetch-mode` headers are present (browser-like)
- Real browser user-agent string
- Path encoding: `%2f` instead of `/` in subpaths
- Try payloads via PUT/PATCH if POST is filtered
- HTTP/2 request when possible (header handling differs from HTTP/1.1 parsing)

### Cloudflare Enterprise
- Precise TLS fingerprint mimicry (use real browser TLS config)
- Target mobile-app specific endpoints (often have broader allowlists)
- Low-and-slow: spread requests over time, randomize parameters
- Look for endpoints excluded from WAF rules (API version paths, `/v2/`, `/beta/`)

### AWS WAF
- Content-type switching (JSON body with `text/plain` content-type)
- Header mutation on managed rule group thresholds
- Look for API Gateway exclusions (different rules than ALB/CloudFront)
- Test via different AWS regions if target is multi-region (rule differences)

### ModSecurity / Azure (CRS-based)
- Paranoia Level 1 default: many payloads pass at PL1 that fail at PL4
- Comment injection in SQL: `/*!50000select*/` (MySQL version comment)
- Alternative SQL functions: `SUBSTR()` vs `SUBSTRING()`, `IF()` vs `IIF()`
- Exploit encoding normalization order (URL decode before regex match)

### Akamai / Imperva (High-effort targets)
- Slow recon: 1 request per 5–10 seconds, randomized UA/IP
- Mimic a real browser: correct TLS ciphers, JA3 fingerprint
- Use legitimate-looking referrers and cookie sequences
- Look for allowlisted mobile SDK endpoints — often less inspected
- Target API calls that match expected patterns but have injectable fields

---

## Quick Decision Tree

```
Payload blocked?
│
├── Try encoding variants first → URL-encode key chars
│   └── Still blocked? Try double-encoding
│
├── Change Content-Type → text/plain or multipart
│
├── Switch HTTP method → PUT, PATCH
│
├── Add "trusted" headers → X-Forwarded-For: 127.0.0.1
│
├── Obfuscate path → /../ dots, %2f, trailing ;param
│
├── Chunked encoding → split payload across chunks
│
└── If nothing works:
    ├── Is WAF Akamai/Imperva/F5? → Realistic bypass chance 30–55%
    ├── Is WAF mTLS/Signed Gateway? → Skip WAF, look for logic bugs
    └── Document "WAF blocks exploit" → Still reportable if vuln is confirmed
```

---

## Important Notes for Bug Bounty

- **WAF bypass ≠ vulnerability.** The underlying bug must still exist; WAF bypass just proves exploitability despite defensive layers.
- **Never aggressive bypass scanning.** Use manual, targeted bypass attempts. Automated WAF scanners may violate program rules.
- **Document your bypass.** Include which bypass technique was used in the PoC — it significantly increases triage acceptance for "this is blocked by WAF" objections.
- **Cloudflare blocks ≠ not vulnerable.** If you prove the underlying logic flaw exists but WAF blocks it, report with the bypass method — most programs care about the vuln, not that WAF mitigates it.
- **If blocked and can't bypass:** Mark confidence as Probable, explain the technical basis, state what runtime verification is needed.

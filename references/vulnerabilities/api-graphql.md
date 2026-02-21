# API & GraphQL — Hunting Methodology

## REST API Specific Testing

### Finding Hidden Endpoints

REST APIs often expose more than their docs reveal:

**Discovery techniques (suggest to user):**
- JS bundle mining: `grep -r 'api/' bundled.js` — extract all `/api/` paths
- Common wordlists: `ffuf -u https://target.com/api/FUZZ -w api_wordlist.txt`
- Swagger/OpenAPI: try `/api/swagger.json`, `/api/openapi.yaml`, `/v1/docs`, `/api-docs`
- Nginx/Apache misconfig: `/api/`, `/v1/`, `/v2/`, `/internal/` — try all version prefixes
- Mobile app APK decompile: `apktool d app.apk` → grep strings for endpoints
- Wayback Machine: `https://web.archive.org/cdx/search/cdx?url=target.com/api/*`

**Versioning bypass:**
- API has `/v2/users` but also still serves `/v1/users` with old (less-protected) logic
- Try `/v0/`, `/beta/`, `/internal/`, `/admin/` prefixes alongside versioned endpoints

---

### Broken Object Level Authorization (BOLA / IDOR in APIs)

The most common and highest-impact REST API vulnerability. See also `references/vulnerabilities/idor.md`.

**API-specific BOLA targets:**
```
GET  /api/v1/users/{user_id}          → change user_id to another
GET  /api/v1/orders/{order_id}        → access another user's order
GET  /api/v1/invoices/{invoice_id}    → financial data of other users
PUT  /api/v1/users/{user_id}/email    → update another user's email
DEL  /api/v1/posts/{post_id}          → delete another user's post
GET  /api/v1/admin/users              → unauthenticated admin endpoint
```

**Testing pattern:**
1. Account A: make request, note resource ID
2. Account B: replay same request with Account A's ID
3. No ownership check → BOLA confirmed

---

### Broken Function Level Authorization (BFLA)

Accessing admin/privileged API functions as a regular user:

**Common targets:**
```
POST /api/v1/admin/users            → create user as non-admin
DELETE /api/v1/admin/users/{id}     → delete users
GET /api/v1/admin/audit-logs        → access audit logs
PUT /api/v1/users/{id}/role         → change someone's role
POST /api/v1/admin/impersonate      → impersonate another user
```

**Testing:** Make admin-level API calls with a regular user JWT. If they succeed → BFLA = **High/Critical**.

---

### Mass Assignment

API accepts additional fields in PUT/PATCH that modify privileged properties:

```json
// Intended request
PATCH /api/v1/profile
{"displayName": "Alice"}

// Attack — add privileged fields
PATCH /api/v1/profile
{"displayName": "Alice", "role": "admin", "isVerified": true, "creditBalance": 9999}
```

**If server accepts extra fields → mass assignment confirmed.** Check if role/permission/balance actually changes.

---

### API Key & Token Exposure

**Common locations to check:**
- JS bundles: `grep -r 'api_key\|apiKey\|Authorization\|Bearer\|secret\|token' app.js`
- Response headers: `X-API-Key`, `Authorization` in responses (should never be echoed)
- Error messages: stack traces may leak keys/tokens
- Git history: `git log --all -p | grep -i 'api_key\|secret'`
- `.env` accessible: `https://target.com/.env` — sometimes publicly accessible
- Swagger UI: parameters pre-filled with real tokens

---

### Rate Limiting & Quota Bypass

If an endpoint has per-user rate limits:

- Rotate IPs via headers: `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`, `CF-Connecting-IP`
- Rotate API keys (if multiple accounts)
- Use different subdomain endpoints (same API, different host rule)
- Change HTTP method: POST vs GET on same endpoint

---

## GraphQL Specific Testing

### Introspection — First Step Always

**Always try introspection to map the full schema:**
```graphql
{ __schema { types { name fields { name type { name } } } } }
```

If introspection is disabled in production, try:
- `{ __type(name: "User") { fields { name type { name } } } }`  (single type query)
- `{ __schema { queryType { name } } }` (minimal check)
- Introspection via POST with `content-type: application/json` when GET is blocked
- `IntrospectionQuery` via Altair/GraphiQL playgrounds if exposed at `/graphql`

Tools to suggest: **InQL** (Burp extension), **graphql-voyager**, **clairvoyance** (wordlist-based blind introspection)

---

### GraphQL IDOR / Authorization Issues

GraphQL resolvers often miss authorization checks:

```graphql
# Should only return current user's data — does it enforce this?
{ user(id: "ANOTHER_USER_ID") { email phone creditCard } }

# Mutation that should require ownership
mutation { deletePost(id: "OTHER_USER_POST_ID") { success } }

# Admin-only query accessible to regular users
{ adminDashboard { totalRevenue userList { email } } }
```

**Testing:** Run queries with another user's IDs using your token. Check if resolver validates ownership.

---

### GraphQL Batching Attacks

GraphQL allows batching multiple operations in one request — useful to bypass rate limits:

```json
[
  {"query": "mutation { login(email: \"admin@target.com\", password: \"password1\") { token } }"},
  {"query": "mutation { login(email: \"admin@target.com\", password: \"password2\") { token } }"},
  ...1000 more...
]
```

If rate limiting is per-HTTP-request (not per-operation) → effectively bypasses brute force protection.

Also useful for CSRF-less state changes in bulk.

---

### GraphQL Query Depth / Complexity DoS

Some GraphQL APIs have no depth limit:

```graphql
{ user { friends { friends { friends { friends { friends { id email } } } } } } }
```

Deeply nested queries can cause exponential server load. **Reportable if it causes measurable service degradation.** Not reportable as a theoretical concern alone.

---

### GraphQL Mutations — Business Logic

Check all mutations for:
- **Missing auth on state-changing mutations** (password change, email update, order placement)
- **IDOR in mutations**: `deleteUser(id: "OTHER_ID")`, `updateProfile(userId: "OTHER_ID", ...)`
- **Race conditions**: Send same mutation 50x in parallel — double-spend, duplicate orders
- **Type confusion**: Send unexpected types for arguments (array where string expected)

---

### Aliases — WAF/Rate Limit Bypass

GraphQL aliases let you call the same field multiple times under different names:

```graphql
{
  res1: user(id: "1") { email }
  res2: user(id: "2") { email }
  res3: user(id: "3") { email }
  ...
}
```

One HTTP request → 100 user records → rate limit effectively bypassed.

---

### GraphQL Injection

If GraphQL variables are interpolated into strings server-side:

```graphql
mutation {
  search(term: "a\") { __typename }") {
    results
  }
}
```

Test for SQLi, NoSQLi, and SSTI through GraphQL variable fields, especially in search, filter, and sort arguments.

---

## Impact Classification

| API/GraphQL Finding | Severity |
|---|---|
| BOLA — any user's sensitive data | High |
| BFLA — admin functions accessible by users | High/Critical |
| Mass assignment → role escalation | Critical |
| GraphQL — admin query accessible | High/Critical |
| Introspection enabled (alone) | Low/Informational |
| GraphQL batching → auth bypass | High |
| API key exposure in JS bundle | Medium/High |
| Unauthenticated endpoint with sensitive data | High |
| Rate limit bypass (no sensitive endpoint) | Low |

## Do Not Report
- Introspection enabled in isolation (informational only — no direct impact)
- GraphQL field suggestions (`Did you mean X?`) without proved exploitation
- Theoretical DoS without measurable server degradation
- API versioning differences without confirmed security regression

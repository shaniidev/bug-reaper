# Subdomain Takeover — Hunting Methodology

## What Is Subdomain Takeover

A subdomain (`sub.target.com`) has a DNS record (CNAME or A) pointing to an external service that the target no longer controls. An attacker can claim that external service and then serve content under `sub.target.com`, enabling phishing, cookie theft, or bypassing CORS/CSP policies that trust `*.target.com`.

---

## How It Happens

```
sub.target.com  CNAME  oldapp.github.io
```
Target stopped using GitHub Pages but forgot to remove the DNS record. An attacker claims the GitHub Pages repo `oldapp.github.io` → they control `sub.target.com`.

---

## Phase 1 — Find Dangling Subdomains

**From your passive recon step (recon.md Phase 1B), you already have subdomains. Now check each one:**

**Step 1 — Resolve all subdomains and look for NXDOMAIN or service-specific errors:**
```bash
cat subdomains.txt | dnsx -silent -a -resp-only > resolved.txt
# Subdomains that DON'T resolve = potential dangling CNAME
cat subdomains.txt | dnsx -silent -cname > cname_records.txt
```

**Step 2 — Check for service fingerprints in HTTP responses:**
```bash
httpx -l subdomains.txt -title -status-code -o http_probe.txt
# Look for error pages that match known service fingerprints
```

---

## Phase 2 — Service Fingerprints

Each external service has a unique error page when the resource doesn't exist. Match these to confirm a takeover opportunity:

| Service | Fingerprint in Response |
|---|---|
| **GitHub Pages** | `There isn't a GitHub Pages site here.` |
| **Heroku** | `No such app` |
| **AWS S3** | `NoSuchBucket` or `The specified bucket does not exist` |
| **AWS Elastic Beanstalk** | `404 Not Found` + `Elastic Beanstalk` in Server header |
| **Azure** | `404 Web Site not found` |
| **Netlify** | `Not Found - Request ID:` |
| **Vercel** | `The deployment could not be found` |
| **Fastly** | `Fastly error: unknown domain` |
| **Pantheon** | `404 error unknown site!` |
| **Ghost** | `Domain is not configured` |
| **Tumblr** | `There's nothing here.` |
| **Shopify** | `Sorry, this shop is currently unavailable.` |
| **Zendesk** | `Help Center Closed` |
| **Cargo** | `If you're moving your domain away from Cargo...` |
| **Surge.sh** | `project not found` |
| **Read the Docs** | `unknown to Read the Docs` |
| **Unbounce** | `The requested URL was not found` (Unbounce fingerprint in headers) |

**Automated tool to suggest:** [subjack](https://github.com/haccer/subjack) or [subzy](https://github.com/PentestPad/subzy):
```bash
subzy run --targets subdomains.txt --concurrency 100 --hide_fails
```

---

## Phase 3 — Confirm Exploitability

Not all dangling CNAMEs are claimable. Confirm before reporting:

| Service | How to Claim |
|---|---|
| GitHub Pages | Create repo matching the CNAME, enable Pages |
| Heroku | `heroku create <appname>` matching the subdomain |
| AWS S3 | `aws s3api create-bucket --bucket <name>` matching the CNAME |
| Netlify | Add custom domain pointing to new Netlify site |
| Fastly | Create new service with the domain in Fastly |
| Azure | Create Web App with custom domain |

**To prove takeover for the PoC without actually hosting malicious content:**
1. Claim the service
2. Host a simple `poc.txt` or HTML with your HackerOne handle and timestamp
3. Show `https://sub.target.com/poc.txt` → returns your content

Never host anything that could harm users (no phishing pages, no credential-harvesting forms).

---

## Phase 4 — Assess Impact

| Scenario | Severity |
|---|---|
| Subdomain used by main app (SSO, OAuth redirect, API) | Critical |
| Subdomain in CORS/CSP trusted list of main app | Critical (pair with CORS/CSP chain) |
| Subdomain receives auth cookies due to domain scope | High |
| Generic marketing subdomain (no auth, no cookies) | Medium |
| Subdomain in emails/links used by users | Medium |
| Unused sandbox/test subdomain with no user exposure | Low |

**High-value chain:** Subdomain takeover + CORS (`ACAO: *.target.com`) = Critical. Document the chain explicitly.

**Also check:** Does the main app set cookies with `Domain=.target.com`? If yes, and you control `sub.target.com`, you can read those cookies via JavaScript → ATO = Critical.

---

## Evidence for Report

1. DNS record showing the dangling CNAME: `dig sub.target.com CNAME`
2. HTTP response showing the service fingerprint (screenshot or HTTP response)
3. Proof of claim ability (either show the GitHub repo/Heroku dashboard, or ideally claim it and host the PoC file)
4. Screenshot of `https://sub.target.com/poc.txt` showing your content
5. Impact statement: what an attacker could serve on this subdomain

---

## Do Not Report
- Subdomains resolving to internal IPs (10.x, 192.168.x) without confirmed SSRF/access
- Expired domains where the record is gone (NXDOMAIN with no CNAME = can't take over)
- Subdomains already returning 200 OK (someone already claimed it, or app still running)
- Wildcard catch-all A records (`*.target.com → IP`) — you can't selectively takeover

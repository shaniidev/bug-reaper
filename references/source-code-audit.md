# Source Code Audit — White-Box Vulnerability Hunting

Use this file when you have access to a **locally downloaded GitHub repository or source code**. White-box auditing is significantly faster and more thorough than black-box — vulnerabilities that would take days to find by guessing can be found in minutes by reading the code.

> **Authorization:** Source code review must still target programs where you have permission to test (active bug bounty program, OSS program, or explicit written authorization).

---

## Step 1 — Identify the Tech Stack

Determine the language and framework from the repository root:

| File Found | Stack | Primary Framework Clue |
|---|---|---|
| `package.json` | Node.js | Check `dependencies`: `express`, `koa`, `fastify`, `nextjs` |
| `requirements.txt` / `setup.py` / `pyproject.toml` | Python | `django`, `flask`, `fastapi`, `tornado` |
| `pom.xml` / `build.gradle` | Java | `spring-boot`, `struts`, `quarkus` |
| `composer.json` | PHP | `laravel`, `symfony`, `codeigniter`, `slim` |
| `Gemfile` | Ruby | `rails`, `sinatra`, `grape` |
| `go.mod` | Go | `gin`, `echo`, `fiber`, `chi` |
| `*.csproj` / `*.sln` | .NET / C# | `aspnetcore`, `mvc` |

Once stack is identified, proceed with language-specific patterns below.

---

## Step 2 — Entry Point Discovery

Map where user input enters the application. These are the sources to trace to dangerous sinks.

**Node.js / Express:**
```
grep -rn "router\.\(get\|post\|put\|delete\|patch\)" routes/ app.js server.js
grep -rn "app\.\(get\|post\|put\|delete\)" --include="*.js"
grep -rn "req\.body\|req\.query\|req\.params" --include="*.js"
```

**Python / Django:**
```
grep -rn "path\|url\|re_path" urls.py
grep -rn "request\.GET\|request\.POST\|request\.data" --include="*.py"
```

**Python / Flask / FastAPI:**
```
grep -rn "@app\.route\|@router\.\|@bp\.route" --include="*.py"
grep -rn "request\.args\|request\.form\|request\.json" --include="*.py"
```

**Java / Spring:**
```
grep -rn "@RequestMapping\|@GetMapping\|@PostMapping\|@PutMapping" --include="*.java"
grep -rn "@RequestParam\|@PathVariable\|@RequestBody" --include="*.java"
```

**PHP / Laravel:**
```
cat routes/web.php routes/api.php
grep -rn "\$_GET\|\$_POST\|\$_REQUEST\|request()->" --include="*.php"
```

**Ruby / Rails:**
```
cat config/routes.rb
grep -rn "params\[" --include="*.rb"
```

---

## Step 3 — Dangerous Sink Patterns by Language

Search for these sinks, then trace backwards to find if user-controlled input reaches them.

### Node.js / JavaScript

| Vulnerability | Sink Pattern to Grep |
|---|---|
| Command Injection | `child_process.exec(`, `child_process.execSync(`, `spawn(` with `shell: true` |
| SQL Injection | `.query(` with string concat, `knex.raw(`, `sequelize.query(` |
| Path Traversal | `fs.readFile(`, `fs.readFileSync(`, `res.sendFile(`, `path.join(` with user input |
| Open Redirect | `res.redirect(req.query.`, `res.redirect(req.body.` |
| NoSQL Injection | `find({` with user input, `findOne(req.body` |
| Prototype Pollution | `Object.assign(`, `merge(`, `extend(` with user-controlled objects |
| SSRF | `axios.get(userInput`, `fetch(userInput`, `http.get(userInput` |

```bash
# Quick command injection scan
grep -rn "child_process" --include="*.js" --include="*.ts"
grep -rn "eval(" --include="*.js" --include="*.ts"
grep -rn "\.exec(" --include="*.js" | grep -v "regex\|RegExp\|\.test\|match"
```

### Python

| Vulnerability | Sink Pattern |
|---|---|
| Command Injection | `os.system(`, `subprocess.run(` with `shell=True`, `subprocess.Popen(` with `shell=True` |
| Code Injection | `eval(`, `exec(`, `compile(` with user input |
| SQL Injection | `.execute(f"`, `.execute("SELECT` + string concat |
| Path Traversal | `open(user_`, `send_file(`, `send_from_directory(` |
| Deserialization | `pickle.loads(`, `yaml.load(` without `Loader=yaml.SafeLoader` |
| SSTI | `render_template_string(user_input` |
| SSRF | `requests.get(url` where `url` is user-controlled |

```bash
# Quick Python sink scan
grep -rn "eval\|exec\|pickle\.loads\|yaml\.load" --include="*.py"
grep -rn "shell=True" --include="*.py"
grep -rn "\.execute(" --include="*.py"
```

### PHP

| Vulnerability | Sink Patterns |
|---|---|
| Command Injection | `exec(`, `passthru(`, `shell_exec(`, `popen(` — trace if arg contains user input |
| SQL Injection | `mysql_query(`, `mysqli_query(` with string concat, no prepared statement |
| File Inclusion | `include(`, `require(`, `include_once(` with user-controlled path |
| Open Redirect | `header("Location: " . $_GET[` |
| XSS | `echo $_GET[`, `echo $_POST[` without `htmlspecialchars()` |
| Deserialization | `unserialize($_` |

```bash
grep -rn "include\s*(\s*\$_GET\|include\s*(\s*\$_POST\|include\s*(\s*\$_REQUEST" --include="*.php"
grep -rn "echo\s*\$_GET\|echo\s*\$_POST\|echo\s*\$_REQUEST" --include="*.php"
grep -rn "unserialize\s*(" --include="*.php"
```

### Java

| Vulnerability | Sink Patterns |
|---|---|
| Command Injection | `Runtime.getRuntime().exec(`, `new ProcessBuilder(` |
| SQL Injection | `Statement.execute(` / `executeQuery(` with string concat (look for missing `PreparedStatement`) |
| Deserialization | `ObjectInputStream.readObject(`, `XMLDecoder(` |
| Path Traversal | `new File(userInput`, `Paths.get(userInput` |
| XXE | `DocumentBuilder`, `SAXParser` without disabling external entities |
| SSRF | `new URL(userInput).openConnection(` |

```bash
grep -rn "Runtime.getRuntime\|ProcessBuilder\|ObjectInputStream" --include="*.java"
grep -rn "Statement\b" --include="*.java" | grep "execute"
```

---

## Step 4 — Secret and Credential Hunting

Look for hardcoded credentials, API keys, and tokens accidentally committed:

```bash
# Generic secret patterns
grep -rn -i "api_key\|apikey\|api-key\|secret_key\|secretkey\|access_key\|accesskey" --include="*.js" --include="*.py" --include="*.php" --include="*.java" --include="*.rb" --include="*.go"

# AWS access keys (format: AKIA + 16 alphanumeric chars)
grep -rn "AKIA[A-Z0-9]\{16\}"

# Passwords in config
grep -rn -i "password\s*=\s*['\"][^'\"]\{6,\}" --include="*.js" --include="*.py" --include="*.php"

# .env files (even if gitignored, may exist locally)
cat .env .env.local .env.development .env.production 2>/dev/null

# Check git history for accidentally committed secrets
git log --all --full-history -- .env
git show HEAD:.env 2>/dev/null
```

**Also check:**
- `config/*.json`, `config/*.yaml`, `config/*.yml` — often contain credentials
- `appsettings.json` (.NET) — connection strings
- `application.properties` / `application.yml` (Spring Boot) — DB passwords, secrets
- Docker files: `ENV` directives with hardcoded values

---

## Step 5 — Dependency Vulnerability Scanning

Suggest the user run these to find known CVEs in dependencies:

| Language | Command |
|---|---|
| Node.js | `npm audit` or `npx better-npm-audit audit` |
| Python | `pip-audit` or `safety check -r requirements.txt` |
| Ruby | `bundle exec bundle-audit check --update` |
| Java (Maven) | `mvn dependency-check:check` |
| PHP | `composer audit` |
| Go | `govulncheck ./...` |

A HIGH/CRITICAL CVE in a dependency that is actually reachable via user input = reportable bug. Confirm exploitability before reporting.

---

## Step 6 — Authentication and Authorization Code Review

Manually read these files — authorization flaws are almost never detectable by grep alone:

1. **Middleware / auth guards** — does every route that requires auth actually have the guard attached?
2. **JWT validation** — is the signature actually verified? Is `alg` header accepted from client?
3. **Password reset logic** — is the token cryptographically random? Time-limited? Single-use?
4. **IDOR in ORM queries** — is `user_id` always filtered by the current session user?
5. **Role checks** — is the role checked server-side or only client-side?

```bash
# Find all places where user ID is used in queries
grep -rn "user_id\|userId\|owner_id\|account_id" --include="*.js" --include="*.py"

# Find JWT usage
grep -rn "jwt\|jsonwebtoken\|PyJWT" --include="*.js" --include="*.py" -l

# Find auth middleware
grep -rn "authenticate\|authorize\|requireAuth\|login_required\|@login_required" --include="*.js" --include="*.py" --include="*.rb"
```

---

## Step 7 — Link Source Code Findings to a Report

A source code finding report needs:
1. **File path + line number** (e.g., `src/controllers/userController.js:142`)
2. **Vulnerable code snippet** (show the exact lines — redact credentials if any)
3. **Exploitation path** — which user-controlled HTTP parameter reaches the sink
4. **Black-box PoC** (if possible — shows it's exploitable in production, not just theoretical)
5. **Impact** — what an attacker can achieve

> **Tip:** Pair every code finding with a black-box PoC request if the app is also running locally or accessible. "Confirmed via source code review AND live PoC" → rated higher than code-only findings.

---

## Semgrep — Automated Pattern Scanning

For broad coverage, suggest the user run Semgrep (free, open source):

```bash
# Install
pip install semgrep

# Run OWASP Top 10 rules on the repo
semgrep --config=p/owasp-top-ten .

# Run language-specific security rules
semgrep --config=p/javascript . 
semgrep --config=p/python .
semgrep --config=p/java .
semgrep --config=p/php .

# Run all security rules
semgrep --config=p/security-audit .
```

Semgrep findings should be **verified manually** — they have false positives. A confirmed Semgrep finding with a working PoC is reportable.

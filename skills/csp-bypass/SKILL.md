---
name: "csp-bypass"
version: "2.0"
category: "auth"
subcategory: "bypass"
phase: "exploitation"
tags: ["auth", "authentication", "bug-bounty", "bypass", "content-security-policy", "csp", "injection", "xss", "access-control", "account-takeover", "api", "authorization", "cloud", "cors", "exploitation", "fuzzing", "graphql", "idor", "iis", "information-disclosure", "js-recon", "mass-assignment", "mobile", "oauth", "path-traversal", "privesc", "session", "takeover", "token", "waf-bypass"]
tools: ["curl", "adb", "burp", "ghauri", "sqlmap", "csp-evaluator", "arjun", "authz", "autorize", "graphqlmap", "grpcurl", "john", "kiterunner", "paramalyzer", "parameth", "repeater", "restler", "zap"]
follow_up_skills: ["waf-bypass", "xss", "xss-polyglot", "css-injection"]
description: "Bug bounty skill: csp bypass - exploitation phase, auth category"
---
# CSP (Content Security Policy) Bypasses

## Summary

Content Security Policy (CSP) is a browser security feature that restricts which sources of content can be loaded and executed on a web page. It prevents XSS, data injection, and code injection attacks. However, weak or misconfigured CSP can be bypassed.

## Key Concepts

- **CSP**: Implemented via HTTP response headers or `<meta>` tags with directives specifying allowed sources for scripts, styles, images, fonts, etc.
- **Directives**: `default-src`, `script-src`, `style-src`, `img-src`, `font-src`, `object-src`, `frame-ancestors`, `upgrade-insecure-requests`.
- **Bypass Goal**: Execute arbitrary JavaScript (inline or external) despite the CSP policy.
- **CSP trusts domains, not intent**: If `script-src https://youtube.com` is set, the browser executes ANY JavaScript served from youtube.com — not just the intended scripts. Attackers find exploitable endpoints (JSONP, file uploads) on whitelisted domains.

## Technical Details

### How CSP Works

```html
<meta http-equiv="Content-Security-Policy" content="
    default-src 'self';
    script-src 'self' https://trusted-cdn.com;
    style-src 'self' https://trusted-cdn.com;
    img-src 'self' data:;
    font-src 'self' https://fonts.googleapis.com;
    object-src 'none';
    frame-ancestors 'none';
    upgrade-insecure-requests;
">
```

- `default-src 'self'` — Only content from the same origin.
- `script-src 'self' https://trusted-cdn.com` — Only JS from same site or trusted CDN.
- `style-src 'self' https://trusted-cdn.com` — Only CSS from same site or trusted CDN.
- `img-src 'self' data:` — Only images from same site or data URIs.
- `font-src 'self' https://fonts.googleapis.com` — Only fonts from same site or Google Fonts.
- `object-src 'none'` — No plugins/Flash.
- `frame-ancestors 'none'` — Prevents clickjacking (cannot embed in iframe).
- `upgrade-insecure-requests` — Auto-upgrade HTTP to HTTPS.

### Weak or Misconfigured CSP

If `script-src` includes `unsafe-inline` or `unsafe-eval`, inject inline scripts or use `eval()` to execute JS.

### CSP with Wildcards

If `script-src *` or `script-src https://*.example.com`, inject scripts from any subdomain or external source.

### File Upload on Trusted Domain

If CSP whitelists a domain that allows user-controlled file uploads (e.g., `https://cdn.example.com`), upload a `.js` file containing malicious JavaScript and include it via a `<script>` tag:

```
https://cdn.example.com/uploads/malicious.js  →  <script src="https://cdn.example.com/uploads/malicious.js">
```

The browser trusts it because the domain is whitelisted, even though the file content is attacker-controlled. This bypasses CSP without needing JSONP or inline execution.

### Exploiting JSONP

If CSP allows scripts from a domain with a JSONP endpoint, craft a malicious callback:

```html
<script src="https://example.com/api?callback=alert(document.cookie)"></script>
```

The server responds with:
```javascript
alert(document.cookie)({"key":"value"});
```

The poor JSONP implementation executes the attacker's function despite CSP blocking inline scripts.

### Base64-encoded Payloads via data: URIs

If `data:` URIs are allowed by CSP:

```html
<img src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
```

## Methodology

1. Identify the CSP policy (check response headers or `<meta>` tags).
2. Look for weaknesses:
   - `unsafe-inline` or `unsafe-eval` in `script-src` — inject inline scripts or eval.
   - Wildcards (`*` or `https://*.example.com`) — host payload on allowed domain/subdomain.
   - Trusted domains with JSONP endpoints — use JSONP callback injection.
   - `data:` URIs allowed — use base64-encoded payloads.
3. Test inline script injection first (simplest indicator of weak CSP).
4. Escalate with the appropriate bypass technique.

## Payloads

```html
<!-- JSONP callback injection -->
<script src="https://example.com/api?callback=alert(document.cookie)"></script>

<!-- Base64 via data: URI -->
<img src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
```

## Commands

None.

## Tools

None specified.

## Bypass Techniques

- **unsafe-inline / unsafe-eval**: Direct inline script or eval execution.
- **Wildcard CSP**: Host payload on any allowed domain/subdomain.
- **JSONP endpoints**: Craft malicious callback function on a trusted domain with JSONP.
- **data: URIs**: Use base64-encoded payloads if `data:` is allowed.
- **Nonce/Hash bypass**: Only mitigated by using nonces/hashes instead of unsafe-inline.

## Notes

- Always check CSP headers early in recon — the policy tells you exactly what's possible.
- JSONP callback injection is one of the most common CSP bypasses in the wild.
- CSP in report-only mode (`Content-Security-Policy-Report-Only`) won't block attacks but sends violation reports.
- Strict CSP uses nonces or hashes instead of `unsafe-inline` — much harder to bypass.
- Subresource Integrity (SRI) prevents tampered external resources even if CSP allows the domain.

## References

- https://shauryasharma05.medium.com/everything-about-csp-content-security-policy-and-bypassing-it-like-a-pro-290d3b06b721

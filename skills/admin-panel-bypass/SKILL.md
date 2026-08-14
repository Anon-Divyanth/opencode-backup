---
name: "admin-panel-bypass"
version: "2.2"
category: "auth"
subcategory: "bypass"
phase: "scanning"
tags: ["access-control", "admin-panel", "auth", "authentication", "bug-bounty", "bypass", "discovery", "injection", "default-credentials", "misconfiguration", "easy-wins", "account-takeover", "api", "authorization", "cloud", "cors", "exploitation", "fuzzing", "graphql", "idor", "iis", "information-disclosure", "js-recon", "mass-assignment", "mobile", "oauth", "path-traversal", "privesc", "session", "takeover", "token", "waf-bypass"]
tools: ["ffuf", "gobuster", "dirsearch", "burp-suite", "katana", "httpx", "waybackurls", "hydra", "adb", "burp", "ghauri", "sqlmap", "arjun", "authz", "autorize", "graphqlmap", "grpcurl", "john", "kiterunner", "paramalyzer", "parameth", "repeater", "restler", "zap"]
follow_up_skills: ["403-bypass", "host-header-injection", "waf-bypass-headers", "sqli", "xss", "idor"]
description: "Bug bounty skill: admin panel bypass - scanning phase, auth category"
---
# Admin Panel Bypass

## Summary

Techniques to discover and bypass access controls on admin panels and restricted areas of web applications. The single easiest win in this space is not a bypass at all — an admin panel left reachable with default or missing credentials. Always check "open panel + default creds" before attempting any bypass.

## Methodology

### Discovery

Brute-force or guess common admin panel paths:
```
/admin
/administrator
/adminpanel
/backend
/control-panel
/controlpanel
/cp
/dashboard
/manager
/panel
/wp-admin        (WordPress)
/admin/login
/admincp
/portal
/console
```

> Easy-win mindset: before payload-based bypasses, simply request the candidate paths unauthenticated. If any returns `200` with a login form, admin UI, or app functionality, you already have a misconfiguration finding. Then test default credentials (below) — `admin:admin` working = full admin access, no bypass needed.

### API Forced Browsing (Admin Endpoints)

Admin API endpoints often exist server-side even when the UI never exposes them:

- **Spider API docs** — Swagger/OpenAPI specs (`/swagger.json`, `/openapi.json`, `/api-docs`) reveal admin-tagged routes.
- **Guess API admin routes**: `/api/admin/`, `/api/internal/`, `/api/users/all`, `/api/admin/users`.
- **Check JS bundles** for hidden endpoint strings (`/api/admin`, `/api/internal`, `/api/export`).
- **Token rewriting via proxy** — use Burp/mitmproxy to swap a regular-user token into admin endpoints and an admin token into user endpoints; compare responses.
- **Test legacy API versions** — `/api/v1/admin`, `/api/v0.1/admin` — security controls are often added to the newest version only.

```
GET /api/admin/users
Authorization: Bearer <regular-user-token>
```

If you get back a user list, the admin check is missing or misapplied — vertical privilege escalation.

### Bypass Techniques

- **Referer header** — Some apps check the Referer header instead of proper authorization. Set `Referer: https://target.com/admin` when requesting restricted pages.
- **Easy credentials** — Try default/common credentials: `admin:admin`, `admin:password`, `admin:123456`, `test:test`, `test:password`, `root:root`, `administrator:administrator`, `guest:guest`.
- **Directory brute-force** — Use ffuf/gobuster/dirsearch to find unprotected pages within the admin directory that lack authentication checks.
- **IP allowlist bypass** — If admin is IP-restricted, try `X-Forwarded-For: 127.0.0.1`, `X-Real-IP: 127.0.0.1`, `X-Forwarded-Host: localhost`.
- **Parameter tampering** — Add `admin=true`, `role=admin`, `is_admin=1` to requests.
- **JS file inspection** — Admin panels often leak internal routes in JS bundles. Search for `/admin`, `/dashboard`, `/internal` in JS source maps.

## Checklist

- [ ] Brute-force common admin directory paths (/admin, /dashboard, /control-panel, /console)
- [ ] Test default/weak credentials (admin:admin, admin:password, test:test)
- [ ] Request admin paths unauthenticated — open access without login = misconfiguration finding
- [ ] Try Referer header manipulation
- [ ] Test IP spoofing headers (X-Forwarded-For, X-Real-IP)
- [ ] Inspect JS files for hidden admin routes
- [ ] Directory brute-force within known admin paths
- [ ] Test parameter tampering for role escalation

## Notes

- Open admin panel + default credentials is the classic "easy win" — always test before bypassing
- JS files are the best source of hidden admin endpoints — always extract routes from bundled JS
- Referer header bypass is surprisingly common in custom admin panels
- Directory brute-force may find pages that lack auth middleware even when the main admin page is protected
- For 403-specific bypass techniques (X-Original-URL, path manipulation, semicolon injection), see `Knowledge/Bypasses/403_Bypass.md`

## References

- https://book.hacktricks.xyz/pentesting-web/admin-panel-bypass

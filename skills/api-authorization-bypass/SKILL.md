---
name: "api-authorization-bypass"
version: "1.0"
category: "api"
subcategory: "authorization"
phase: "exploitation"
tags: ["bug-bounty", "api", "authorization", "bola", "mflac", "access-control", "forced-browsing", "verb-tampering", "broken-access-control", "privilege-escalation", "account-takeover", "auth", "bypass", "cloud", "cors", "exploitation", "fuzzing", "graphql", "idor", "iis", "information-disclosure", "js-recon", "mass-assignment", "mobile", "oauth", "path-traversal", "privesc", "session", "takeover", "token", "waf-bypass"]
tools: ["burp-suite", "mitmproxy", "postman", "ffuf", "dirsearch", "jwt_tool", "kiterunner", "arjun", "authz", "autorize", "paramalyzer", "parameth", "repeater", "zap", "curl"]
follow_up_skills: ["idor-detection-exploitation", "authorization-session-testing", "mass-assignment", "jwt-attacks", "http-parameter-pollution", "open-redirect", "403-bypass", "api-fuzzing", "admin-panel-bypass"]
description: "Bug bounty skill: api authorization bypass - exploitation phase, api category"
---
# API Authorization Bypasses

## Summary

APIs are built fast, and developers frequently rely on front-end controls or "nobody will find this" assumptions. Over 90% of web apps have dangerous API authorization flaws. This skill is the umbrella playbook for hunting broken object- and function-level authorization in APIs — BOLA, MFLAC, forced browsing, verb tampering, hidden endpoints, path/case normalization quirks, and replay attacks. Automated scanners miss these logic bugs, so manual, role-aware testing is mandatory. Each technique points to a dedicated skill for deep-dive material.

## Key Concepts

- **BOLA (Broken Object Level Authorization)**: The API fails authorization logic for object access — not just IDs. IDOR is object-reference misuse; BOLA is the broader failure of the authorization check itself (e.g., a "manager" can view all timesheets because the API never checks if this manager is scoped to that team).
- **MFLAC (Missing Function Level Access Control)**: The API checks "can this user see the object?" but not "can this user perform this action?". A regular user can DELETE/PUT records they can only view.
- **Forced Browsing**: Admin/internal endpoints exist server-side even when the UI never exposes them. Attackers spider API docs and guess routes.
- **Verb Tampering**: Authorization is often enforced per HTTP verb — `GET` locked down but `DELETE`/`PUT`/`PATCH`/`OPTIONS` open.
- **Hidden/Undocumented Endpoints**: `/debug`, `/backup`, `/export`, `/internal` and legacy API versions survive in production long after the UI drops them.
- **Path/Case Normalization**: Frameworks normalize `/api/Admin`, `/API/ADMIN`, `/api//admin`, `/api/../admin`, `/api/%61dmin` differently than the access-control matcher.
- **Replay**: Tokens, magic links, and payloads accepted more than once — no nonce, no invalidation, no timestamp check.
- **Role Confusion**: Authorization must be tested with tokens from EVERY role — anonymous, user, manager, admin — compared against the same endpoints.

## The 12 API Authorization Flaw Classes (Quick Map)

| # | Flaw | Where it's deep-dived |
|---|---|---|
| 1 | IDOR (insecure direct object reference) | `idor-detection-exploitation` |
| 2 | Mass Assignment (untrusted fields, `isAdmin: true`) | `mass-assignment` |
| 3 | BOLA (authorization logic failure on objects) | This skill + `idor-detection-exploitation` |
| 4 | Privilege Escalation via Forced Browsing | This skill + `admin-panel-bypass` |
| 5 | MFLAC (object ok, action not authorized) | This skill + `authorization-session-testing` |
| 6 | JWT Token Manipulation (`alg:none`, weak secret, role claim) | `jwt-attacks` |
| 7 | Hidden / Undocumented Endpoints | This skill + `api-fuzzing` |
| 8 | HTTP Verb Tampering | This skill + `api-fuzzing` |
| 9 | Parameter Pollution (query + body conflict) | `http-parameter-pollution` |
| 10 | Unvalidated Forwarding (open redirect in APIs) | `open-redirect` |
| 11 | Replay Attacks (magic links, purchases) | This skill + `authorization-session-testing` |
| 12 | Case Sensitivity / Path Manipulation | This skill + `403-bypass` |

## Battle-Tested Hunting Workflow

The article's core 6-step methodology — apply to every API scope:

1. **Map All Endpoints**
   - Proxy all traffic from web UI and mobile apps.
   - Scrape Swagger/OpenAPI docs (`/swagger.json`, `/openapi.json`, `/api-docs`).
   - Brute-force hidden routes with ffuf/dirsearch/Kiterunner.
   - Grep JS bundles and mobile app binaries for endpoints and route strings.

2. **Understand Roles and Permissions**
   - Gather tokens/cookies from different user types: anonymous, basic user, premium, manager, admin.
   - Compare endpoint responses for regular vs admin users (Autorize/Authz replay: browse as admin, replay with low-priv session).
   - Note which endpoints enforce checks only for some roles.

3. **Fuzz Everything**
   - Change IDs, verbs, and parameters in every request (numeric and UUID values).
   - Try mass-assignment fields and parameter pollution on every create/update endpoint.
   - Test both horizontal (user↔user) and vertical (user→admin) access.

4. **Replay and Reuse**
   - Attempt to reuse access tokens, magic links, and sensitive endpoints.
   - Replay state-changing requests after a delay or from another session.

5. **Check for Forgotten Endpoints**
   - Scan `/debug`, `/export`, `/internal`, `/backup`, odd API versions (`/api/v0.1/`, `/api/v1/`).
   - Test old API versions — security controls are often added to the newest version only.

6. **Mix and Match**
   - Combine bugs: use IDOR to find a user, then mass assignment to escalate their role.
   - Use an open redirect on a trusted domain to steal OAuth tokens via `redirect_uri`.

## BOLA — Broken Object Level Authorization

### The Scenario

A normal employee can fetch their own timesheet:

```
GET /api/timesheets/789
Authorization: Bearer <employee-token>
```

Change the ID to another employee's timesheet → if their payroll info comes back, that's BOLA.

### The Subtle Case (Horizontal Escalation via Role Scoping)

A "manager" role can view all timesheets — but the API forgets to check whether THIS manager is allowed on THIS team's data. Role is checked; scope/tenancy is not:

```java
if (user.role == 'manager') {
   // forgets to check if the timesheet belongs to the manager's team
   return db.findTimesheet(request.timesheetId)
}
```

### Pro Method

- Map all object IDs you can find (from list endpoints, responses, JS). Try swapping them in requests.
- Test with EVERY role — normal user, manager, admin — against the same object IDs.
- APIs often enforce checks on some endpoints but not all (list vs detail vs export). Mix it up.

## MFLAC — Missing Function Level Access Control

### The Core Check

APIs check "can user see this object?" but NOT "can user perform this action?":

1. You can `GET /api/products/232`.
2. Try `DELETE /api/products/232` or `PUT /api/products/232`.
3. If the action succeeds without admin privileges — MFLAC.

### Real Bug Bounty Case

An API where ANY logged-in user could reset ANYONE's password — the endpoint existed for admins but wasn't locked down. Always test cross-user privileged actions with a low-priv token.

### Quick Fix Mentality (for reporting)

Always check both **object** AND **action** permissions.

## Forced Browsing for Privilege Escalation

APIs may not expose admin endpoints in the UI, but the routes still exist:

### How Attackers Find Them

- Spider API docs (Swagger/OpenAPI) — look for admin tags.
- Guess common admin routes: `/api/admin/`, `/api/internal/`, `/api/users/all`.
- Check JavaScript files for hidden endpoints.

### Example Attack

```
GET /api/admin/users
Authorization: Bearer <regular-user>
```

If you get back a user list, the admin check is missing or misapplied.

### Pro Tip

- Always try endpoints meant for a "higher" privilege role.
- Use a proxy (Burp, mitmproxy) to rewrite tokens — swap your low-priv token into admin endpoints and vice versa.

## HTTP Verb Tampering

Some APIs handle permissions based on HTTP verbs but forget to verify the client should use those verbs:

- Take any `/api/resource/123` endpoint.
- Try `PUT`, `PATCH`, `DELETE`, even `OPTIONS`.
- A `GET` may be locked down while `DELETE` isn't.

```
DELETE /api/blogposts/42
Authorization: Bearer <regular-user>
```

Common developer failure — role check applied inside the handler for one verb only:

```java
if (user.role == 'admin') {
  // allow sensitive actions
}
// no check for other verbs
```

## Hidden / Undocumented Endpoints

- Brute-force common routes: `/debug`, `/backup`, `/export`, `/internal`.
- Grep through mobile app binaries or JavaScript bundles for route strings.
- Look for old API versions: `/api/v1/`, `/api/v0.1/`.

### Forgotten Export Endpoint Example

```
GET /api/export/allData
Authorization: Bearer <your-token>
```

If this dumps an entire database (customer PII), it's a critical find.

## Case Sensitivity & Path Manipulation

Frameworks sometimes normalize paths that access-control rules match literally:

- Case: `/api/admin` vs `/api/Admin` vs `/API/ADMIN`.
- Slashes/dots: `/api/../admin`, `/api//admin`.
- Encoded characters: `/api/%61dmin` (URL-encoded `a`).

```
GET /api/ADMIN/users
Authorization: Bearer <regular-user>
```

If this bypasses the route guard, privileged endpoints are exposed. See `403-bypass` for the full technique catalog.

## Replay Attacks

Some APIs accept the same token or payload multiple times — no nonces, no timestamps, no invalidation:

- A password reset link or magic login link accepted more than once.
- A purchase request replayed → same credit card charged multiple times (real-world case from the source).

### How to Test

- Intercept the request.
- Replay it after a delay or from another session.
- If it still works, the API isn't invalidating tokens or checking reuse.

## Unvalidated Forwarding (API Open Redirects)

APIs can redirect based on user input — SSO, payment, or generic `/api/redirect` flows — without validation:

```
POST /api/redirect
{
  "url": "https://evil.com/phish"
}
```

If the API issues a 302 to any URL, chain it for phishing or OAuth token theft (`redirect_uri`).

## Detection Commands

### Role comparison with curl
```bash
# Same endpoint, two tokens — compare
curl -s -H "Authorization: Bearer <user-token>" "https://target.com/api/orders/789"
curl -s -H "Authorization: Bearer <admin-token>" "https://target.com/api/orders/789"
```

### Verb tampering sweep
```bash
for verb in GET POST PUT PATCH DELETE OPTIONS; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X $verb \
    -H "Authorization: Bearer <low-priv-token>" "https://target.com/api/products/232")
  echo "$verb -> $code"
done
```

### Hidden endpoint discovery
```bash
for path in /debug /backup /export /internal /api/export/allData /api/admin/users /api/v1/admin /api/v0.1/admin; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer <low-priv-token>" "https://target.com$path")
  echo "$path -> $code"
done
```

### Path/case normalization bypasses
```bash
for path in /api/admin /api/Admin /API/ADMIN /api//admin /api/../admin /api/%61dmin /api/admin/.; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer <low-priv-token>" "https://target.com$path")
  echo "$path -> $code"
done
```

### Replay test
```bash
# Capture the original request, then replay after a delay / from a new session
curl -s -o /dev/null -w "%{http_code}" -X POST -H "Authorization: Bearer <token>" \
  -d '{"orderId":"789","confirm":true}' "https://target.com/api/orders/confirm"
sleep 60
curl -s -o /dev/null -w "%{http_code}" -X POST -H "Authorization: Bearer <token>" \
  -d '{"orderId":"789","confirm":true}' "https://target.com/api/orders/confirm"
```

### Parameter pollution (query vs body conflict)
```bash
curl -s -X POST -H "Authorization: Bearer <token>" \
  "https://target.com/api/users/update?userId=victim_id" \
  -H "Content-Type: application/json" \
  -d '{"userId":"attacker_id","name":"Hacker"}'
```

## Tools

| Tool | Purpose |
|------|---------|
| **Burp Suite** | Proxy, Repeater, Intruder; Autorize/Authz for role replay |
| **mitmproxy** | Proxy + token rewriting for mobile/API testing |
| **Postman** | Manual API poking, collections, role-switch testing |
| **ffuf / dirsearch** | Brute-forcing hidden endpoints and admin routes |
| **jwt-tool** | Decoding and tampering with JWTs |
| **Kiterunner** | API route discovery with assetnote wordlists |
| **Arjun / Parameth** | Hidden parameter discovery |
| **Paramalyzer** | Track all parameters sent to a host |

## Not a Finding If

- The endpoint returns 403/401 for every role-swapped, verb-swapped, and path-normalized variant.
- Object-level AND function-level checks are enforced server-side on every verb and endpoint.
- BOLA attempts return data only for the requesting user's own scope/tenant.
- Hidden endpoints return 404 and old API versions are decommissioned.
- Tokens/magic links are single-use with server-side invalidation.
- Redirect endpoints validate the destination against an allowlist.

## Notes

- Authorization bugs are logic bugs — automated scanners miss most of them. Manual role-aware testing is the differentiator.
- Always test mobile API versions separately from web APIs; mobile builds often use weaker or older endpoints.
- New features are tested less strictly than core features — pounce on them.
- Forced browsing + hidden endpoints is the classic "easy" critical: `/api/export/allData` with zero auth.
- JWT signing secrets have been found via a Google search for "JWT secret" — check for leaked/weak secrets before deep protocol attacks.
- When chaining: IDOR → find victim user → mass assignment → escalate role → access admin endpoints.

## References

- Very Lazy Tech — "Mastering API Authorization Bypasses: 12 Real Vulnerabilities Every Hacker Should Know" (Medium, July 2026): https://medium.verylazytech.com/mastering-api-authorization-bypasses-12-real-vulnerabilities-every-hacker-should-know-b84aa36eccd6
- https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/
- https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/api-endpoint

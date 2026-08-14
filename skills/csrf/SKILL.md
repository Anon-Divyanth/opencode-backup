---
name: "csrf"
version: "2.0"
category: "api"
subcategory: "csrf"
phase: "exploitation"
tags: ["bug-bounty", "csrf", "cross-site-request-forgery", "same-site", "token-bypass"]
tools: ["burp-suite", "csrf-generator"]
follow_up_skills: ["cors-misconfiguration", "html-injection", "http-parameter-pollution", "xss", "clickjacking-testing", "csrf"]
description: "Bug bounty skill: csrf - exploitation phase, api category"
---
# Cross-Site Request Forgery (CSRF)

## Summary

CSRF forces an authenticated user to execute unwanted actions on a web application in which they're logged in. Only Create, Update, and Delete forms should require CSRF tokens — read-only forms should not.

## Checklist

### Token Presence
- [ ] CSRF token is present on every form that performs state-changing operations (Create, Update, Delete)
- [ ] Read-only forms (search, view) do NOT have unnecessary CSRF tokens

### Token Validation
- [ ] Server validates the token length is correct (full vs partial length validation)
- [ ] Server checks the token parameter exists (not just the cookie)
- [ ] Server rejects requests with empty CSRF token parameter
- [ ] Server rejects requests sent without a CSRF token
- [ ] Token is properly bound to the session — verify that reusing one user's token with another user's session is rejected
- [ ] Compare CSRF tokens across multiple dummy accounts — if tokens are predictable or shared, the implementation is weak
- [ ] Test unused tokens — issue multiple tokens and use an older one; tokens should be single-use
- [ ] Replace CSRF token with an attacker-generated value — check if the server accepts arbitrary token values

### Bypass Techniques
- [ ] **Method Interchange** — Interchange POST with GET. If the server accepts GET requests for state-changing operations and doesn't validate the token on GET, CSRF is possible via `<img>` or `<link>` tags.
- [ ] **Remove Token Parameter** — Send the request without the CSRF token parameter entirely.
- [ ] **Blank Token Parameter** — Send the request with the CSRF token parameter set to an empty value (`csrf_token=`).
- [ ] **Tamper Token Characters** — Change or delete some characters of the CSRF token. If only partial validation is done, a mutated token may pass.
- [ ] **Use Token From Another Session** — Capture a CSRF token from one session and use it in a request for another user's session. Tokens must be cryptographically bound to the session.
- [ ] **Use Token From Another User** — Capture a CSRF token from a different user (e.g., attacker's account) and use it in the victim's session.
- [ ] **Content-Type Switch** — Change the `Content-Type` to `multipart/form-data` or `application/json`. Some frameworks only validate CSRF tokens for `application/x-www-form-urlencoded`.
- [ ] **Referer Manipulation** — Change the `Referer` header to test if the server validates it. Try removing it, setting it to a different origin, or changing the header name to `Referrer` (misspelling).
- [ ] **Host Header Manipulation** — Change the `Host` header value. Some legacy CSRF protections validate based on the Host header and can be bypassed by manipulating it.
- [ ] **CSRF + Clickjacking** — Test CSRF alongside clickjacking by loading the target page in an iframe. If the page can be framed, a CSRF attack can be combined with a clickjacking layer to trick the user into submitting the forged request.
- [ ] **XSS-Delivered CSRF (CSRF via XSS)** — If the app lacks CSRF tokens entirely, a stored XSS in a context the victim views delivers the CSRF: the payload runs in the victim's origin, the browser auto-attaches session cookies, and a same-origin `fetch`/POST with `credentials: 'include'` succeeds silently. Classic chain: **Self-XSS + missing CSRF** — CSRF forces the victim to save the attacker's Self-XSS payload into their own profile, where it later fires and provides full CSRF capability in their session. Payload pattern:
  ```javascript
  // script.js (hosted on attacker server) — injected via <script src> in a stored field
  fetch('/update_email.php', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type':'application/x-www-form-urlencoded'},
    body: 'email=pwnedadmin@evil.local&password=pwnedadmin'
  });
  ```
  Confirm the trigger via the attacker server's access log (`GET /script.js`). Even with HTTPOnly cookies (cookie theft blocked), targeting credential-change forms directly achieves session-equivalent impact. See `cross-site-scripting` and `exploitation-chaining` for the full chain.

## Methodology

1. Identify all state-changing forms (create, update, delete).
2. Confirm a CSRF token is present on each.
3. Test token validation:
   - Remove the token parameter entirely
   - Submit with an empty token value
   - Submit with a tampered/mutated token value
   - Submit with a token from another user's session
   - Compare tokens across multiple dummy accounts for patterns
4. Test bypass techniques:
   - Interchange POST with GET method
   - Change Content-Type to `multipart/form-data`
   - Manipulate Referer and Host headers
   - Test combined with clickjacking
5. Test for token reuse — use an old/stale token after a new one is issued.

## Not a Finding If

- **SameSite=Strict cookie without token**: If the cookie has `SameSite=Strict` and the action is a simple GET, CSRF may be mitigated — but this is not a complete replacement for tokens on state-changing operations.
- **Referer header present and matching**: A valid Referer header that matches the origin is not sufficient alone — token validation should still be enforced.
- **Token present but never validated server-side**: If the token field exists in the form but the server never checks it (only accepts its presence), this is still a finding. Confirm by sending a tampered token and observing if the action succeeds.

## Notes

- CSRF tokens must be cryptographically random and tied to the user's session
- Double-submit cookie pattern is weaker than session-bound tokens
- SameSite cookies (Strict/Lax) mitigate CSRF but are not a complete replacement for tokens
- Token leakage in Referer headers or URLs defeats the purpose
- Testing CSRF alongside clickjacking often reveals bypasses that neither alone would find
- Comparing CSRF tokens across multiple accounts can reveal weak RNG or static token values

## References

- https://portswigger.net/web-security/csrf
- https://owasp.org/www-community/attacks/csrf

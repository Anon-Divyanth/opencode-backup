---
name: "authorization-session-testing"
version: "2.1"
category: "privesc"
subcategory: "authorization"
phase: "exploitation"
tags: ["bug-bounty", "privesc", "authorization", "authentication", "session", "jwt", "otp", "brute-force", "access-control", "account-takeover", "api", "auth", "bypass", "cloud", "cors", "exploitation", "fuzzing", "graphql", "idor", "iis", "information-disclosure", "js-recon", "mass-assignment", "mobile", "oauth", "path-traversal", "takeover", "token", "waf-bypass"]
tools: ["burp-suite", "sqlmap", "ffuf", "curl", "jwt_tool", "arjun", "authz", "autorize", "burp", "graphqlmap", "grpcurl", "john", "kiterunner", "paramalyzer", "parameth", "repeater", "restler", "zap"]
follow_up_skills: ["idor-detection-exploitation", "information-disclosure-harvesting", "exploitation-chaining", "bug-bounty-reporting"]
description: "Bug bounty skill: authorization session testing - exploitation phase, privesc category"
---
# Authorization, Authentication & Session Management Testing

## Summary

Comprehensive checklist for testing authentication, authorization, and session management flaws — covering password-based login, brute-force protection, session handling, cookie security, JWT misconfigurations, and access control bypasses.

## Key Concepts

- **Authentication**: Verifying identity (who you are) — knowledge factors (passwords), possession factors (phone/token), inherence factors (biometrics)
- **Authorization**: Verifying permissions (what you can do) — occurs after authentication
- **Brute-force attacks**: Automated trial-and-error to guess valid credentials using wordlists
- **Username enumeration**: Changes in server behavior (status codes, error messages, response times) leak whether a username is valid
- **Credential stuffing**: Reusing breached username:password pairs from other sites — users frequently reuse credentials
- **Account locking**: Temporarily locking an account after N failed attempts; can be bypassed by attempting each of N passwords across many usernames
- **Rate limiting**: Blocking IP after too many requests; can be bypassed via IP rotation, X-Forwarded-For manipulation, or including valid logins in the wordlist
- **OTP (One-Time Password)**: Time-based or event-based codes used as a second factor; vulnerable to predictable values, null handling, reuse, and brute-force
- **Pre-account takeover**: Attacker registers with victim's email and enables 2FA before verification, locking the victim out of their own account
- **OAuth misbinding**: Linking an OAuth identity to an unverified account, granting the attacker persistent access when the real user later verifies

## Checklist

### Password-Based Login

- [ ] **Username enumeration** — Check for differences in status codes, error messages, and response times when submitting valid vs invalid usernames
  - Invalid: "Invalid username" vs Valid: "Invalid password" (error message text differs)
  - Status code differs on valid username
  - Response time longer for valid usernames (extra DB lookup or password verification step)
  - Registration message: "Email sent if account exists" (secure) vs "No account with that email" (leaks info)
  - API responses: `{"error": "user_not_found"}` vs `{"error": "invalid_password"}`
- [ ] **No rate limiting on login attempts** — Attempt many rapid logins; if none are blocked, brute-forcing is possible
- [ ] **Weak password policy** — Register with `12345678` as password; if accepted, the policy is weak
- [ ] **Weak password policy details** — Test minimum length (`a`, `ab`, `abcdefgh`), complexity (`password`, `password1`, `Password1!`), common weak passwords (`123456`, `password`, `qwerty`, `admin`), username as password (`admin/admin`, `test/test`)
- [ ] **Weak login credentials** — Test common/default credentials: `admin:admin`, `admin:password`, `root:root`, `test:test`
- [ ] **Credentials transmitted over HTTP** — Check if login form submits over `http://` (credentials sent in cleartext)
- [ ] **Accepts overly large passwords** — Submit a very long password (>1000 chars); may cause DoS or reveal buffer handling issues
- [ ] **PHP Type Juggling** — If PHP `==` is used instead of `===`, `"admin" == true` evaluates to true. Try `password=true` or similar type-coercion values.
- [ ] **Forced browsing** — Try accessing the internal dashboard or authenticated pages directly without logging in (e.g., `/dashboard`, `/admin`, `/profile`)
- [ ] **Username reuse during registration** — Register with an existing username; if the app returns "username taken," valid usernames can be enumerated
- [ ] **SQL injection in login** — Test login fields with SQLi payloads:
  ```
  ' OR '1'='1'; --
  ' or 1=1;--
  ' or '1'='1
  ' or 1=1;#
  ') or ('x'='x
  ' or 1=1 LIMIT 1;--
  admin' --
  admin'#
  admin'/*
  ' or 1=1--
  ' or 1=1#
  ') or ('1'='1--
  ' or 1/*
  */ =1 --
  admin' or 'a'='a
  '#
  ```
- [ ] **Capture login request and run sqlmap**:
  ```bash
  sqlmap -r login_request.txt --batch
  ```

### OTP & 2FA Testing

- [ ] **Predictable OTPs** — Test common OTP values: `000000`, `123456`, `111111`. If accepted, implementation is weak.
- [ ] **Null/Empty OTP** — Send empty or `null` OTP in the API. Some systems mishandle nulls and skip validation.
  ```json
  {"otp": null}
  {"otp": ""}
  ```
- [ ] **OTP Reuse** — OTP should be one-time only. Use a valid OTP, then resend it in a new request. If login succeeds again, OTP is not invalidated after use.
- [ ] **OTP Not Bound to User** — OTP must be tied to a specific user. Use an OTP from Account A to log into Account B. If it works, the system doesn't bind OTPs correctly.
- [ ] **OTP Brute-Force** — Send hundreds/thousands of OTP guesses rapidly. If there's no delay/blocking, brute-force is possible (4-digit OTP = 10,000 combos, 6-digit OTP = 1,000,000 combos).
- [ ] **OTP in Response Body** — Check response body and debug logs for exposed OTP. Sensitive info should never be exposed to the frontend.
  ```json
  {"status": "success", "otp": "482913", "message": "OTP sent"}
  ```
- [ ] **2FA Bypass via Password Reset** — Steps: Enable 2FA, log out, use password reset email, click reset link. If it logs in without OTP, that's a bypass.
- [ ] **2FA Bypass via OAuth/Social Login** — Steps: Enable 2FA on account, log out, use "Sign in with Google". If it skips the 2FA step, it's a serious flaw.
- [ ] **2FA Bypass via Response Manipulation** — Intercept server response using Burp/ZAP. Change response values:
  - `"status": "failed"` → `"status": "success"`
  - `"false"` → `"true"`
  - `403` → `200`
  - If client-side trusts the response blindly, it's vulnerable.
- [ ] **2FA Bypass via Direct URL Access** — Copy the URL of the dashboard page before entering OTP. Open it directly in a new tab or with curl. If it opens, 2FA isn't enforced server-side.
- [ ] **2FA Pre-Account Takeover** — Attacker creates an account with victim's email and enables 2FA before email is verified. Victim can't access their own account.
- [ ] **2FA Session Persistence** — Log in on multiple devices, enable 2FA from one, check if the other session still works. Old sessions should be killed or re-authenticated.
- [ ] **OTP Bombing (DoS)** — Spam the OTP send endpoint repeatedly. May lead to DoS or spam SMS/email attack. Should throttle excessive requests.
- [ ] **2FA Enforced on All Auth Paths** — Test 2FA from multiple angles: API vs UI, OAuth vs username/password, web vs mobile. Missing enforcement on any path is a bypass.
- [ ] **API Version Downgrade for OTP** — If newer API versions have rate limiting on OTP verification, try older versions:
  ```bash
  POST /api/v2/check-otp
  {"otp": "1234"}
  # Older API versions may lack security controls
  ```
- [ ] **Host Header Injection in Password Reset** — Modify the Host header to an attacker-controlled domain when requesting a password reset. The reset email may contain the attacker's domain in the reset link.
  ```bash
  POST /forgot-password HTTP/1.1
  Host: attacker.com
  email=victim@email.com
  ```

### Brute-Force & Credential Stuffing

- [ ] **Hydra brute force** — Use Hydra for form-based authentication:
  ```bash
  hydra -l admin -P /usr/share/wordlists/rockyou.txt \
    target.com http-post-form \
    "/login:username=^USER^&password=^PASS^:Invalid credentials"
  ```
- [ ] **Burp Intruder brute force** — Capture login request, send to Intruder, set payload position on password field, load wordlist, analyze response lengths/codes.
- [ ] **Account lockout threshold** — Determine after how many failed attempts lockout occurs, lockout duration, and whether lockout notification is sent.
- [ ] **Rate limiting scope** — Check if limiting is IP-based or account-based; test bypass via headers (`X-Forwarded-For`, `X-Real-IP`, `X-Originating-IP`, `X-Client-IP`, `X-Remote-IP`, `True-Client-IP`).
- [ ] **CAPTCHA bypass** — Check if CAPTCHA appears after failed attempts and if it's easily bypassed.
- [ ] **Credential stuffing** — Use known breached email:password pairs with Burp Intruder Pitchfork attack (set username and password as matched pair positions, load paired wordlist, analyze for successful logins).
- [ ] **Detection evasion** — Slow request rate, rotate source IPs, randomize user agents, add delays between attempts.
- [ ] **IP block bypass** — Include valid login credentials at regular intervals within the wordlist (e.g., every 10 attempts). Some implementations reset the failed-count on successful login.
- [ ] **Account lock bypass** — If the limit is 3 attempts before lockout, try only 3 passwords per username across many usernames rather than many passwords per one username.
- [ ] **Rate limit bypass via X-Forwarded-For** — Rotate the `X-Forwarded-For` header value with each request to simulate different IPs.
- [ ] **Multiple credentials per request** — Check if the app accepts JSON/XML arrays in a single request:
  ```json
  {"username":"admin","password":["pass1","pass2","pass3"]}
  ```
- [ ] **HTTP basic authentication brute-force** — Base64-encode `username:password` combinations and send in the `Authorization` header. Basic auth often lacks brute-force protection.

### Session Handling

- [ ] **Session ID Prediction** — Test if session tokens follow a predictable pattern (incrementing integers, timestamps, weak RNG). Collect a sample of issued session IDs and analyze for patterns.
  ```python
  import requests
  tokens = []
  for i in range(100):
      response = requests.get("https://target.com/login")
      token = response.cookies.get("SESSIONID")
      tokens.append(token)
  # Check for sequential increments, calculate entropy, look for timestamp components
  ```
- [ ] **Session Termination on Logout** — Verify the session is invalidated server-side after logout, not just removed client-side. Replay the old session cookie after logout.
- [ ] **Session After Closing Browser** — Close the browser completely, reopen it, and check if the session is still valid (non-session cookies persist across restarts).
- [ ] **Concurrent Login** — Test if multiple simultaneous sessions are allowed for the same user. Some apps enforce a single-session policy; others allow unlimited concurrent sessions. If allowed, test if old sessions remain valid after new login.
- [ ] **Old Session Persists After Password Change** — After changing passwords, the old session should be invalidated. Test by changing password in one browser and continuing to use the pre-change session token in another. Changing a password should trigger global session invalidation — all existing session identifiers (cookies, refresh tokens, JWTs) must be revoked.
  - CWE-613: Insufficient Session Expiration | OWASP A07:2021
- [ ] **Old Session Persists After 2FA Enabled** — Enable 2FA in one browser; test if sessions in other browsers remain authenticated. All pre-2FA sessions should require re-authentication with the second factor.
  - CWE-288: Authentication Bypass via Path/Condition | NIST SP 800-63B §7.2
- [ ] **Logout Does Not Invalidate Token Server-Side** — Capture a logged-in request (via Burp Repeater), log out, then replay the captured request. If it still succeeds, logout only clears client-side storage without invalidating the token server-side.
  - For JWT: implement short `exp` plus a `jti` blacklist on logout.
  - CWE-613: Insufficient Session Expiration | OWASP A07:2021
- [ ] **Password Reset Token Reuse After Password Change** — Request a password reset, change password, log out, then try to use the old reset link. Reset tokens should be single-use and invalidated after any password change or successful login.
  - CWE-640: Weak Account Recovery / Lockout Mechanism | NIST SP 800-63B §7.2.3
- [ ] **Lack of Session Validation on Sensitive Endpoints** — Check if sensitive endpoints (admin panels, account settings, payment) properly validate the session. Access them without a valid session or with another user's session cookie.
- [ ] **Session Fixation** — Test if the application accepts a session ID set by the attacker (via URL parameter or cookie) and does not regenerate it after login. Ensure new cookies are issued upon successful authentication.
  ```bash
  # Attacker workflow:
  # 1. Attacker visits site, gets session: SESSIONID=attacker_session
  # 2. Attacker sends link to victim with fixed session
  # 3. Victim logs in with attacker's session
  # 4. Attacker now has authenticated session
  curl -c cookies.txt https://target.com
  # Note the session ID from cookies.txt
  curl -b cookies.txt -c cookies.txt -X POST https://target.com/login -d "user=test&pass=test"
  # If the server didn't regenerate the session ID, it's vulnerable
  ```
- [ ] **Missing Session Rotation After Privilege Change** — After escalating privileges (e.g., from user to admin), the session ID should be rotated. Capture the session before and after privilege change and compare.
- [ ] **No Logout Functionality** — Verify the application provides a logout mechanism. Some apps lack logout entirely, making session termination impossible for the user.
- [ ] **Concurrent Session Limit Bypass** — If the app limits concurrent sessions, test if it can be bypassed by modifying headers, using different user agents, or altering session tokens.
- [ ] **Session Invalidation After Password Reset** — After password reset, all existing sessions should be invalidated:
  - Change password in one browser
  - Test if old session in another browser still works
  - Other devices should be logged out
  - New session should be generated after reset

### Session Timeout Testing

- [ ] **Idle timeout** — Login and note session cookie. Wait without activity (15, 30, 60 minutes). Attempt to reuse session to check if still valid.
- [ ] **Absolute timeout** — Login and continuously use session. Check if forced logout after a set period (8 hours, 24 hours).
- [ ] **Logout invalidation** — Login and note session. Click logout. Attempt to reuse old session cookie — should be invalidated server-side.

### Cookie Security

- [ ] **Missing Secure Flag** — Check if session cookies lack the `Secure` flag, allowing transmission over unencrypted HTTP. Ensure no Set-Cookie directive omits Secure.
- [ ] **Cookie Sent Over Unencrypted Channel** — Ensure no cookie operation (set, send, refresh) takes place over HTTP. Intercept traffic and verify cookies are never transmitted in cleartext.
- [ ] **Cookie Forced Over Unencrypted Channel** — Test if the cookie can be forced over HTTP by manipulating the request (e.g., downgrading HTTPS to HTTP, using `Strict-Transport-Security` bypass techniques). Apps without HSTS are especially vulnerable.
- [ ] **Missing HttpOnly Flag** — Check if session cookies lack the `HttpOnly` flag, making them accessible to JavaScript (XSS exploitation).
- [ ] **Missing SameSite Flag** — Check if cookies lack `SameSite` attribute, leaving them vulnerable to CSRF-based session usage.
- [ ] **Missing Path Attribute** — Check if cookies are set without a `Path` attribute. Without it, the cookie defaults to the request-URI path, which may be too broad or cause unexpected scoping.
- [ ] **Persistent Cookies** — Check if any cookies are set with a `Max-Age` or `Expires` directive. Persistent cookies remain valid across browser sessions and may outlive their intended lifetime.
- [ ] **Cookie Expiration** — Check session cookie expiration date/time. Overly long expiration windows increase the window of opportunity for session hijacking.
- [ ] **Cookie Domain Scope** — Identify the cookie's `Domain` attribute. A broad scope (e.g., `.example.com` instead of `app.example.com`) extends the cookie to all subdomains — any subdomain XSS compromises the session.
- [ ] **Session Token Leakage in URL** — Check if session tokens are transmitted via URL parameters or query strings. They may be logged by referer headers, proxies, or browser history.
- [ ] **User Data Stored in Cookie** — Test if user-identifying information (username, role, email) is stored directly in the cookie value. If so, tamper with another user's data and observe the effect.
- [ ] **Cookie Decoding** — Try decoding cookie values (Base64, Hex, URL encoding, etc.). Decoded values may reveal internal state, user identifiers, roles, or secrets.

### Cookie-Based Injection Vectors

Cookies are an often-overlooked injection surface. Test cookies for the same vulnerabilities as other parameters:

- **SQL Injection** — Inject SQL payloads into cookie values using the same syntax as GET/POST (order by, union, etc.). Use URL encoding for delimiters (`;`, `,`) that would otherwise break the cookie format.
- **Command Injection** — Inject OS command separators into cookie values. Python-based apps are especially prone to code injection via cookie deserialization.
- **Python Code Injection** — If the app uses `pickle`, `eval()`, or unsafe deserialization on cookie data, inject:
  ```
  eval(compile('for x in range(1):\n import time\n time.sleep(20)','a','single'))
  __import__('os').popen('COMMAND').read()
  ```
- **CRLF Injection** — Inject `%0d%0a` into cookie values to perform HTTP response splitting (see `CRLF_Injection.md`).
- **Parameter Pollution** — Send duplicate parameter names in cookies (`user_id=attacker&user_id=victim`). The server may process one over the other (see `HTTP_Parameter_Pollution.md`).
- **Buffer Overflow via Long Cookie** — Send an abnormally long cookie value. If the server has a fixed-size buffer for cookie processing, it may crash, leak stack traces, or be exploitable for code execution. For example, a very long cookie value with a NOP sled and shellcode may trigger a classic buffer overflow on legacy systems.

### Session Cookie Flags Reference

| Flag | Purpose | Vulnerability if Missing |
|------|---------|------------------------|
| HttpOnly | Prevent JS access | XSS can steal session |
| Secure | HTTPS only | Sent over HTTP |
| SameSite | CSRF protection | Cross-site requests allowed |
| Path | URL scope | Broader exposure |
| Domain | Domain scope | Subdomain access |
| Expires | Lifetime | Persistent sessions |

### Rate Limiting Bypass Headers

```http
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
```

### Exposed Session Variables

- [ ] **Encryption of Session Data** — Check if session data is encrypted on the server side. Plaintext storage of sensitive data (roles, balances, PII) in session variables is a finding.
- [ ] **Session ID in GET Request** — Check if the session ID is ever transmitted via GET request (URL parameter, query string). GET requests are more likely to be logged (referer, proxies, browser history).
- [ ] **Method Interchange** — Interchange POST with GET method for state-changing operations. If the server accepts GET and processes the session ID from the URL, the session is exposed via referer headers.
- [ ] **Session Leakage via GET/POST** — Compare responses between GET and POST for the same endpoint. If session data is exposed in the response to a GET request, it may be cached or logged.

### Session Puzzling

- [ ] **Identify Session Variables** — Map all session variables used by the application (user_id, role, csrf_token, etc.) by observing requests, responses, and client-side code.
- [ ] **Break Session Generation Flow** — Try to manipulate the order or value of session variables. For example, set a session variable before authentication and see if it persists after login, or overwrite one session variable with another via parameter pollution.

### Session Hijacking

- [ ] **HSTS Missing** — Test session hijacking on targets without HSTS enabled. Without HSTS, an active MITM can downgrade HTTPS to HTTP and steal the session cookie via tools like sslstrip.
- [ ] **Captured Cookie Login** — After capturing a session cookie (via XSS, network sniffing, or physical access), replay it in a different browser/IP. If the session is valid without additional checks (User-Agent, IP binding), it's hijackable.

### Registration & Email Verification

- [ ] **Unverified Email Access** — Register with an email without verifying it. If the app grants access or privileged features before verification, the verification is meaningless.
  - CWE-290: Authentication Bypass by Spoofing | NIST SP 800-63B
- [ ] **Token Reuse/Replay** — Confirmation links that don't expire or aren't invalidated after use are vulnerable to replay attacks. Use a verification token, then reuse it in a new request.
  - CWE-640: Weak Account Recovery Mechanism | OWASP A07:2021
- [ ] **Registration with Privileged Email** — Register using a privileged email (e.g., `support@target.com`, `admin@target.com`). If email ownership isn't verified, attackers can impersonate internal staff.
  - Real world: Bug bounty researcher registered with `support@target.com` and accessed internal moderation tools.
  - CWE-290: Authentication Bypass by Spoofing
- [ ] **OAuth Misbinding Before Verification** — Link an OAuth account (Google, GitHub) to an unverified email. If the real user later verifies that email, the attacker's OAuth identity remains bound.
  - Real world: Tester linked their Google account to `victim@gmail.com` before email confirmation, causing OAuth misbinding.
  - CWE-287: Improper Authentication | OWASP A07:2021
- [ ] **Account Merging Without Verification** — Native and federated accounts for the same email get merged without confirming the user's consent. An attacker's local account may be auto-verified when the victim logs in via Google.
  - CWE-287: Improper Authentication | OWASP A07:2021
- [ ] **Email Change OTP Sent to Old Email** — Verification for email change should target the new email. If OTP is sent to the old email, an attacker who compromised that email can approve changes.
  - CWE-302: Authentication Bypass by Assumed-Immutable Data | OWASP A07:2021
- [ ] **Verification Flag Not Reset on Email Change** — If verification status isn't reset when email changes back, attackers can mark an address as verified without proving control.
  - CWE-302 / CWE-862: Missing Authorization
- [ ] **Verifying Old Email via New Link** — When an unverified account changes its email then verifies the new one, some backends mistakenly mark the old email as verified.
  - CWE-302 / CWE-640 | OWASP A05:2021
- [ ] **Token Not Bound to Email** — If verification tokens aren't email-bound, attackers can change the email and misuse the token to verify the original (unauthorized) address.
  - CWE-302: Authentication Bypass by Assumed-Immutable Data | OWASP A05:2021

### Token & Authentication

- [ ] **Weak "Remember Me" Token Implementation** — Persist-login tokens should be random, single-use, and stored server-side. Test if the "Remember Me" token is predictable, persistent across regenerations, or can be replayed after use.
- [ ] **JWT Misconfigurations (Stateless Session Issues)** — Common JWT flaws:
  - `alg: none` — accept unsigned tokens
  - Secret is leaked somewhere (GitHub, client-side JS, public config files)
  - Server never checks the signature — tamper payload without changing the token
  - Weak HMAC secret — brute-force the signing key (weak passwords, common phrases)
  - Public key confusion — RS256 vs HS256 confusion attack
  - Expired token acceptance — JWT with `exp` in the past still validates
  - Missing signature validation — tamper payload without changing signature
- [ ] **Password Reset Token Sent Over HTTP** — Verify that password reset links use `https://` not `http://`. If sent over HTTP, the reset token can be intercepted via network sniffing (MITM) on the same network, leading to full account takeover. (Real-world: Mattermost, $750 bounty — reset links used HTTP, attacker on same Wi-Fi could sniff the token.)
- [ ] **Password Reset Token Persistence** — Request multiple password reset tokens and test if the old token remains valid after a new one is issued. Reset tokens should be single-use and expire on new request.

### Forgot Password Testing

- [ ] **User Enumeration** — Compare responses for valid vs invalid users:
  - Different error messages: "Email sent" (valid) vs "No account found" (invalid)
  - Response time differences (longer for valid users due to DB lookup)
  - Status code differences
- [ ] **Password Reset Token Testing**
  - Test token randomness (predictable patterns = vulnerable)
  - Test token length (short tokens = brute-forceable)
  - Test token expiration (wait and retry after expiry)
  - Test token reuse (use same token twice)
  - Test if old tokens remain valid after generating new one
  - Test if tokens are invalidated after password change
- [ ] **Token Leakage**
  - Check browser history for tokens in URLs
  - Check Referer header leakage to third-party sites
  - Check server logs exposure
  - Check third-party analytics leakage
- [ ] **Host Header Injection**
  ```
  POST /forgot-password HTTP/1.1
  Host: attacker.com
  email=victim@email.com
  ```
  Verify if reset links point to attacker-controlled domains.
  Also test: `X-Forwarded-Host: attacker.com`
- [ ] **Reset Link Expiration**
  - Verify expired tokens cannot be used
  - Verify used tokens cannot be reused
- [ ] **HTTP Parameter Pollution**
  ```
  email=victim@test.com&email=attacker@test.com
  ```
  Check which value is processed for reset link delivery.
- [ ] **Email Security**
  - Reset emails sent only to account owner
  - No sensitive information in emails (no password disclosure)
  - No token disclosure beyond intended use
- [ ] **Business Logic Testing**
  - Multiple active reset links allowed
  - Multiple active OTPs allowed
  - Password reset after account suspension
  - Password reset after account deletion
  - Reset flow bypasses
- [ ] **CSRF on Password Reset**
  - Reset request vulnerable to CSRF
  - Password change endpoint vulnerable to CSRF
  - Missing anti-CSRF tokens

### Access Control

- [ ] **Account Lockout Bypass** — Test if account lockout can be bypassed by rotating IP addresses, changing User-Agent headers, using different parameter names, or waiting for the lockout window to reset.
- [ ] **Back Refresh Attack (Browser Cache Weakness)** — After logout or password change, pressing the browser back button should not reveal cached sensitive pages. Test by logging out / changing password, then using browser back navigation. If cached pages are accessible, the app lacks proper cache-control headers (`Cache-Control: no-cache, no-store, must-revalidate`).
- [ ] **Broken Access Control (BAC)** — Test that higher-privilege functions cannot be executed by lower-privilege users:
  - Test ALL user levels (anonymous, basic user, premium, moderator, admin)
  - Test with Authorization/Autorize Burp extension — replay admin requests with low-privilege session
  - Check JS Functions via developer console — admin actions may be hidden but not server-protected
  - Copy and paste of URL — send admin-level URLs to low-privilege session
- [ ] **Missing Function Level Access Control (MFLAC)** — The API may check "can this user see the object?" but NOT "can this user perform this action?". Test state-changing verbs (PUT/PATCH/DELETE) on resources you can only GET:
  - `GET /api/products/232` works → try `DELETE /api/products/232` or `PUT /api/products/232` with a low-priv token
  - If the action succeeds without admin privileges, it's MFLAC
  - Real-world case: an API where ANY logged-in user could reset ANYONE's password — the endpoint existed for admins but wasn't locked down
  - Always check both **object** and **action** permissions
- [ ] **Privilege Escalation via Forced Browsing** — Admin/internal API endpoints often exist server-side even when the UI never exposes them:
  - Spider Swagger/OpenAPI docs and grep JS bundles for admin routes
  - Guess common API admin routes: `/api/admin/`, `/api/internal/`, `/api/users/all`
  - Replay admin endpoints with a regular-user token (Burp/mitmproxy token rewriting)
  - Test legacy API versions (`/api/v1/`, `/api/v0.1/`) — security controls are often added to the newest version only
- [ ] **Parameter Tampering for Authorization Bypass** — Modify parameters like `user_id`, `role`, `admin`, `is_admin`, `group`, or `account_type` in requests to access unauthorized resources.
  ```bash
  # Example: IDOR via parameter tampering
  GET /api/profile?user_id=123 → change to user_id=124
  POST /api/update_role {"role": "user"} → change to {"role": "admin"}
  ```
- [ ] **XSS in Logout Functionality** — Test the logout endpoint/URL for reflected XSS. If the logout message reflects user input or a redirect parameter, it may be exploitable.

### Replay Attacks

Some APIs accept the same token, magic link, or payload multiple times — no nonces, no timestamps, no server-side invalidation.

- [ ] **Magic Login Link / Password Reset Link Reuse** — Use a magic login or reset link once, then reuse it after a delay or from a different session/device. If it still authenticates, the token isn't invalidated after use.
- [ ] **Business-Logic Replay (Double-Charge)** — Intercept a state-changing request (purchase, transfer, order confirm) and replay it. Real-world case: an API allowed replaying purchase requests, charging the same credit card multiple times from a single intercepted request.
- [ ] **Token/Payload Replay Across Sessions** — Replay a captured authenticated request from another IP, browser, or after logout. If it still succeeds, the token isn't bound or invalidated.
- [ ] **Sensitive Endpoint Replay** — Replay requests to sensitive endpoints (password change, email change, 2FA disable) to verify they can't be re-executed without fresh authorization.

**How to test:**
- Intercept the request with Burp/mitmproxy.
- Replay it after a delay or from another session.
- If it still works, the API isn't invalidating tokens or checking for re-use.
- CWE-294: Authentication Bypass by Capture-replay | OWASP A07:2021

## Methodology

### Session Cookie Inspection

```bash
# Check cookie flags (Secure, HttpOnly, SameSite) via curl
curl -s -v https://target.com/login -d "user=test&pass=test" 2>&1 | grep -i 'set-cookie'

# Check SameSite support
curl -s -v https://target.com 2>&1 | grep -i 'set-cookie' | grep -i samesite
```

### JWT Testing

```bash
# Decode JWT payload (no secret needed)
echo "eyJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoidGVzdCJ9" | base64 -d 2>/dev/null

# Test alg:none
python3 -c "
import jwt
token = jwt.encode({'user':'admin'}, '', algorithm='none')
print(token)
"

# Test weak secret with john/hashcat
# jwt-cracker or jwt_tool for automated testing
python3 jwt_tool.py -t https://target.com -rh "Authorization: Bearer <token>" -M pb
```

### Session Fixation Test

```bash
# 1. Attacker obtains a session ID from the app before authentication
curl -c cookies.txt https://target.com
# Note the session ID from cookies.txt

# 2. Use that same session ID when authenticating
curl -b cookies.txt -c cookies.txt -X POST https://target.com/login -d "user=test&pass=test"

# 3. If the server didn't regenerate the session ID, it's vulnerable
```

## Tools

- **JWT_Tool** — JWT testing suite (algorithms, exploits, scanning)
- **jwt-cracker** — HMAC secret brute-force
- **Burp Suite Intruder** — Brute-force automation, username enumeration, payload positions
- **Burp Suite / Caido** — Session handling, cookie inspection, replay
- **Authorization plugin (Burp)** — Automated role/header tampering
- **Hydra** — Brute-force authentication
- **sqlmap** — Automated SQL injection detection in login forms
- **ffuf** — Fast brute-force fuzzing for login endpoints

## Troubleshooting

| Issue | Solutions |
|-------|-----------|
| Brute force too slow | Identify rate limit scope; IP rotation; add delays; use targeted wordlists |
| Session analysis inconclusive | Collect 1000+ tokens; use statistical tools; check for timestamps; compare accounts |
| MFA cannot be bypassed | Document as secure; test backup/recovery mechanisms; check MFA fatigue; verify enrollment |
| Account lockout prevents testing | Request multiple test accounts; test threshold first; use slower timing |

## Examples

### Example 1: Account Lockout Bypass

**Scenario:** Test if account lockout can be bypassed

```bash
# Step 1: Identify lockout threshold (try 5 wrong passwords)
# Result: "Account locked for 30 minutes"

# Step 2: Test bypass via IP rotation using X-Forwarded-For
POST /login HTTP/1.1
X-Forwarded-For: 192.168.1.1
username=admin&password=attempt1

# Increment IP for each attempt
X-Forwarded-For: 192.168.1.2

# Step 3: Test bypass via case manipulation
username=Admin  # vs admin — some systems treat these as different accounts
```

### Example 2: Password Reset Token Exploitation

```bash
# Step 1: Request reset for test account
POST /forgot-password
email=test@example.com

# Step 2: Capture reset link
https://target.com/reset?token=a1b2c3d4e5f6

# Step 3: Test token properties
# Reuse: Try using same token twice
# Expiration: Wait 24+ hours and retry
# Modification: Change characters in token

# Step 4: Test for user parameter manipulation
# Try changing the user/email parameter while using valid token
https://target.com/reset?token=a1b2c3d4e5f6&email=admin@example.com
```

## Notes

- Authentication bugs are among the highest reported critical-severity issues in bug bounty programs — credential access often leads to full account takeover
- Username enumeration via error message differences is the most common entry point for brute-force attacks
- For brute-force: try a small number of common passwords across many usernames instead of many passwords on one username (bypasses account lockout)
- JWT `alg: none` is the single most common JWT misconfiguration — always test it first
- Always check for cookie flags (Secure, HttpOnly, SameSite) — missing flags are frequent findings
- Parameter tampering for authorization bypass often pairs with IDOR — test user IDs, roles, group memberships
- Password reset token persistence is often overlooked — request multiple tokens and replay the first
- Credential stuffing attacks reuse breached credentials — if the app doesn't check HaveIBeenPwned/credential rotation, it's vulnerable
- HTTP basic auth sends credentials in every request as Base64 — not encrypted, trivially decoded
- OTP/2FA bypasses often hide in less-tested paths: API vs UI, OAuth vs password, web vs mobile — test all
- Default credentials are still common in IoT devices and CMS platforms: `admin:admin`, `root:root`, `admin:password`, `kali:kali`, `test:test`
- Login forms served over HTTP expose credentials to MITM on the same network — tools: Wireshark, mitmproxy, sslstrip
- A HackerOne report (ID #410451) highlighted credential stuffing via lack of rate limiting on password attempts
- At DEFCON 2016, researchers captured credentials from HTTP-based captive portals on public Wi-Fi
- OTP bombing (unlimited OTP requests) can lead to telecom providers blacklisting SMS from the app — real fintech case documented

## References

- https://portswigger.net/web-security/authentication
- https://portswigger.net/web-security/authentication/password-based
- https://portswigger.net/web-security/authentication/multi-factor
- https://portswigger.net/web-security/authentication/other-mechanisms
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/README
- https://calico-family-1b4.notion.site/Authentication-Vulnerability-2173ceb9662a809db4bfd479a585b8f5
- https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/613.html
- https://cwe.mitre.org/data/definitions/640.html
- https://cwe.mitre.org/data/definitions/307.html

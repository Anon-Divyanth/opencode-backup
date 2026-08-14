---
name: "captcha-bypass"
version: "2.0"
category: "auth"
subcategory: "captcha"
phase: "exploitation"
tags: ["bug-bounty", "auth", "captcha", "bypass", "rate-limiting", "automation", "access-control", "account-takeover", "api", "authorization", "cloud", "cors", "exploitation", "fuzzing", "graphql", "idor", "iis", "information-disclosure", "js-recon", "mass-assignment", "mobile", "oauth", "path-traversal", "privesc", "session", "takeover", "token", "waf-bypass"]
tools: ["curl", "burp-suite", "ffuf", "arjun", "authz", "autorize", "burp", "graphqlmap", "grpcurl", "john", "kiterunner", "paramalyzer", "parameth", "repeater", "restler", "zap"]
follow_up_skills: ["waf-bypass-headers", "csrf", "race-condition-testing"]
description: "Bug bounty skill: captcha bypass - exploitation phase, auth category"
---
# CAPTCHA Bypasses

## Summary

CAPTCHA controls can often be bypassed through method manipulation, parameter tampering, or logic flaws in how the application verifies the challenge.

## Methodology

### Bypass Techniques

1. **Change request method** — If the form uses POST with CAPTCHA, try GET (or vice versa). The server may only validate on one method.
2. **Remove the captcha parameter** — Remove the CAPTCHA parameter entirely from the request. Some apps only validate when the parameter is present.
3. **Leave parameter empty** — Submit the CAPTCHA field as an empty string. The server may skip validation if the field is blank.
4. **Fill in random value** — Submit any random value. Some implementations accept any value (client-side-only validation).
5. **Reuse old CAPTCHA tokens** — Check if a previously valid CAPTCHA response can be reused multiple times.
6. **Response header manipulation** — Some CAPTCHAs set a cookie/session flag after solving — test if you can set it manually.

## Checklist

- [ ] Change request method (POST ↔ GET)
- [ ] Remove captcha parameter entirely
- [ ] Submit empty captcha parameter
- [ ] Submit random/bogus captcha value
- [ ] Reuse a previously valid CAPTCHA token
- [ ] Check for client-side-only validation (disable JS and submit)

## Notes

- CAPTCHA bypasses are most impactful on: login, registration, password reset, comment forms, and voting/rating endpoints
- Rate limiting without CAPTCHA can often be bypassed via IP rotation or header manipulation
- reCAPTCHA v1 (audio challenge) has known bypasses; v2/v3 require more advanced techniques

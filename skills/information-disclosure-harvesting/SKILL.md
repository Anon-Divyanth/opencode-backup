---
name: "information-disclosure-harvesting"
version: "2.1"
category: "privesc"
subcategory: "info-disclosure"
phase: "reconnaissance"
tags: ["bug-bounty", "privesc", "information-disclosure", "recon", "secrets", "source-maps", "misconfiguration", "easy-wins", "directory-listing", "debug-mode", "access-control", "account-takeover", "api", "auth", "authorization", "bypass", "cloud", "cors", "exploitation", "fuzzing", "graphql", "idor", "iis", "js-recon", "mass-assignment", "mobile", "oauth", "path-traversal", "session", "takeover", "token", "waf-bypass"]
tools: ["curl", "ffuf", "burp-suite", "grpcurl", "nuclei", "git-dumper", "arjun", "authz", "autorize", "burp", "graphqlmap", "john", "kiterunner", "paramalyzer", "parameth", "repeater", "restler", "zap"]
follow_up_skills: ["idor-detection-exploitation", "authorization-session-testing", "cache-poisoning-deception", "exploitation-chaining", "bug-bounty-reporting"]
description: "Bug bounty skill: information disclosure harvesting - reconnaissance phase, privesc category"
---
# Information Disclosure / Information Leakage

## Summary

Information leaks accelerate exploitation by revealing code, configuration, identifiers, and trust boundaries. Treat every response byte, artifact, and header as potential intelligence. Minimize, normalize, and scope disclosure across all channels. Most misconfiguration bugs (debug mode, directory listing, exposed backups, unprotected dev endpoints) are information-disclosure findings in disguise — often the easiest wins in any engagement.

## Key Concepts

- **Differential Oracle**: Comparing owner vs non-owner vs anonymous responses for the same resource reveals existence and state through status codes, body length, ETags, and cache behavior
- **Cross-Channel Mirroring**: Information may be disclosed in one channel (REST, GraphQL, WebSocket, gRPC, SSR, CSR) but not others
- **Cache Key Bypass**: If CDN/proxy cache keys omit Authorization or tenant headers, cached responses leak across identity boundaries
- **Artifact Enumeration**: DVCS folders, backup files, config endpoints, source maps, and client bundles yield the fastest wins before payload-based testing
- **Triage Rubric**: Classify findings by exploitability — credentials/keys (Critical), versions with CVEs (High), internal paths/hosts (Medium), generic headers (Low)

## Technical Details

### Attack Surface

#### Errors and Exceptions

- SQL/ORM errors reveal table/column names, DBMS, query fragments
- Stack traces expose absolute paths, class/method names, framework versions, developer emails
- Template engine probes (`{{7*7}}`, `${7*7}`) identify templating stacks
- JSON/XML parsers — type mismatches leak internal model names

#### Debug and Env Modes

- Debug pages: Django DEBUG, Laravel Telescope, Rails error pages, Flask/Werkzeug debugger, ASP.NET customErrors Off
- Profiler endpoints: `/debug/pprof`, `/actuator`, `/_profiler`, custom `/debug` APIs
- Generic debug/status/log endpoints: `/debug`, `/status`, `/logs`, `/health`, `/metrics`, `/info` — often enabled in prod by mistake and may reveal env vars, versions, and internal paths
- Feature/config toggles exposed in JS or headers

#### Development / Staging / Test Endpoints

- `/dev`, `/staging`, `/test`, `/qa`, `/preprod`, `/uat` — dev instances are routinely less hardened, may run debug mode, use default creds, or connect to real production data stores
- Enumerate them with the same artifact checks as production (`.env`, backups, debug pages)
- Check `robots.txt`, DNS, CT logs, and JS bundles for staging hostnames (e.g., `staging.example.com`, `dev-api.example.com`)

#### DVCS and Backups

- DVCS: `/.git/` (HEAD, config, index, objects), `.svn/entries`, `.hg/store` → reconstruct source and secrets
- Backups/temp: `.bak/.old/~/.swp/.swo/.tmp/.orig`, db dumps, zipped deployments
- Classic backup file names: `/backup.zip`, `/backup.tar.gz`, `/config.bak`, `/site.zip`, `/db.sql`, `/dump.sql` — backup archives routinely contain full source trees, `.env` files, and database dumps
- Build artifacts: dist artifacts containing `.map`, env prints, internal URLs

#### Configs and Secrets

- Classic: `web.config`, `appsettings.json`, `settings.py`, `config.php`, `phpinfo.php`
- Containers/cloud: `Dockerfile`, `docker-compose.yml`, Kubernetes manifests, service account tokens
- Credentials and connection strings; internal hosts and ports; JWT secrets

#### API Schemas and Introspection

- OpenAPI/Swagger: `/swagger`, `/api-docs`, `/openapi.json` — enumerate hidden/privileged operations
- GraphQL: introspection enabled; field suggestions; error disclosure via invalid fields
- gRPC: server reflection exposing services/messages

#### Client Bundles and Maps

- Source maps (`.map`) reveal original sources, comments, and internal logic
- Client env leakage: `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_` variables; embedded secrets
- `__NEXT_DATA__` and pre-fetched JSON can include internal IDs, flags, or PII

#### Headers and Response Metadata

- Fingerprinting: `Server`, `X-Powered-By`, `X-AspNet-Version`
- Tracing: `X-Request-Id`, `traceparent`, `Server-Timing`, debug headers
- Caching oracles: `ETag`/`If-None-Match`, `Last-Modified`/`If-Modified-Since`, `Accept-Ranges`/`Range`

#### Storage and Exports

- Public object storage: S3/GCS/Azure blobs with world-readable ACLs or guessable keys
- Signed URLs: long-lived, weakly scoped, re-usable across tenants
- Export/report endpoints returning foreign data sets or unfiltered fields

#### Observability and Admin

- Metrics: Prometheus `/metrics` exposing internal hostnames, process args
- Health/config: `/actuator/health`, `/actuator/env`, Spring Boot info endpoints
- Tracing UIs: Jaeger/Zipkin/Kibana/Grafana exposed without auth

#### Cross-Origin Signals

- Referrer leakage: missing/weak referrer policy leading to path/query/token leaks to third parties
- CORS: overly permissive `Access-Control-Allow-Origin`/`Access-Control-Expose-Headers` revealing data cross-origin; preflight error shapes

#### File Metadata

- EXIF, PDF/Office properties: authors, paths, software versions, timestamps, embedded objects

#### Cloud Storage

- S3/GCS/Azure: anonymous listing disabled but object reads allowed; metadata headers leak owner/project identifiers
- Pre-signed URLs: audience not bound; observe key scope and lifetime in URL params

#### Internal Network Exposure

- **Tailscale/VPN IPs**: 100.x.x.x range in API responses (e.g., customer URLs)
- **Private DNS**: Internal hostnames in configuration responses
- **Service URLs**: Backend service endpoints with internal ports
- **Multi-tenant data**: Cross-tenant information in shared API endpoints

### Key Vulnerabilities

#### Differential Oracles

- Compare owner vs non-owner vs anonymous for the same resource
- Track: status, length, ETag, Last-Modified, Cache-Control
- HEAD vs GET: header-only differences can confirm existence
- Conditional requests: 304 vs 200 behaviors leak existence/state

#### CDN and Cache Keys

- Identity-agnostic caches: CDN/proxy keys missing Authorization/tenant headers
- Vary misconfiguration: user-agent/language vary without auth vary leaks content
- 206 partial content + stale caches leak object fragments

#### Cross-Channel Mirroring

- Inconsistent hardening between REST, GraphQL, WebSocket, and gRPC
- SSR vs CSR: server-rendered pages omit fields while JSON API includes them

#### Triage Rubric

- **Critical**: Credentials/keys; signed URL secrets; config dumps; unrestricted admin/observability panels
- **High**: Versions with reachable CVEs; cross-tenant data; caches serving cross-user content
- **Medium**: Internal paths/hosts enabling LFI/SSRF pivots; source maps revealing hidden endpoints
- **Low**: Generic headers, marketing versions, intended documentation without exploit path

## Methodology

1. **Build channel map** — Identify all channels: Web, API, GraphQL, WebSocket, gRPC, mobile, background jobs, exports, CDN. Map each channel's authentication model and data exposure surface.

2. **Establish diff harness** — Compare owner vs non-owner vs anonymous responses for the same resource. Normalize on status code, body length, ETag, and response headers. Use digest-based diffing to reduce noise.

3. **Trigger controlled failures** — Send malformed types, boundary values, missing params, and alternate content-types to provoke stack traces and error messages that leak internal state.

4. **Enumerate artifacts** — Check DVCS folders (`/.git/`, `/.svn/`, `/.hg/`), backup files (`.bak`, `.old`, `~`, `.swp`, `.swo`), config endpoints (`/actuator`, `/debug`, `/_profiler`), source maps, client bundles, and API documentation endpoints.

5. **Probe cache/CDN identity boundaries** — Send the same request with different identity contexts (cookie A vs cookie B, different tenants) and check for cached responses from other users. Verify that `Vary` includes Authorization or tenant-scoped headers.

6. **Mirror channels** — For each piece of information found in one channel (e.g., REST API), check if the same data is more exposed through another channel (GraphQL, WebSocket, SSR).

7. **Correlate to impact** — Map versions to known CVEs, internal paths to LFI/RCE chains, credentials to cloud access, and schema fields to auth bypass opportunities.

## Detection Commands

```bash
# Check for .git disclosure
curl -s -o /dev/null -w "%{http_code}" "https://target.com/.git/HEAD"

# Check for common config files
curl -s "https://target.com/.env" | head -20
curl -s "https://target.com/phpinfo.php" | grep -i "php version\|document_root"
curl -s "https://target.com/web.config" | head -20
curl -s "https://target.com/appsettings.json" | head -20

# Check for debug/actuator endpoints
curl -s "https://target.com/actuator/health" | jq .
curl -s "https://target.com/actuator/env" | jq .
curl -s "https://target.com/debug" | head -20
curl -s "https://target.com/_profiler" | head -20

# Check generic debug/status/log endpoints
curl -s -o /dev/null -w "%{http_code}" "https://target.com/status"
curl -s -o /dev/null -w "%{http_code}" "https://target.com/logs"
curl -s -o /dev/null -w "%{http_code}" "https://target.com/health"
curl -s -o /dev/null -w "%{http_code}" "https://target.com/info"

# Check common backup file names (often contain source + secrets)
for f in backup.zip backup.tar.gz config.bak site.zip db.sql dump.sql .env; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$f")
  [ "$code" != "404" ] && echo "[!] $f -> HTTP $code"
done

# Check dev/staging/test endpoints
for p in dev staging test qa preprod uat; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$p/")
  [ "$code" != "404" ] && echo "[!] /$p -> HTTP $code"
done

# Check for API schemas
curl -s "https://target.com/openapi.json" | jq '.paths' | head -50
curl -s "https://target.com/swagger/v1/swagger.json" | jq '.paths' | head -50

# Check for source maps
curl -s -o /dev/null -w "%{http_code}" "https://target.com/static/js/main.js.map"
curl -s -o /dev/null -w "%{http_code}" "https://target.com/_next/static/chunks/pages/index-*.js.map"

# Check for server header and fingerprinting
curl -sI "https://target.com/" | grep -iE "server|x-powered|x-aspnet|server-timing"

# Differential oracle — compare authenticated vs unauthenticated
curl -s -o /dev/null -w "%{http_code} %{size_download}" "https://target.com/api/profile"
curl -s -o /dev/null -w "%{http_code} %{size_download}" -H "Cookie: session=VALID" "https://target.com/api/profile"

# Check for directory listing
curl -s "https://target.com/uploads/" | head -20
curl -s "https://target.com/static/" | head -20

# HEAD vs GET differential
curl -sI "https://target.com/private/resource" | head -20
curl -s "https://target.com/private/resource" | head -20

# GraphQL introspection
curl -s -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}'

# Conditional request oracle
curl -sI -H 'If-None-Match: "etag-value"' "https://target.com/resource"

# Check for internal IP disclosure in API responses
curl -s -b "session=COOKIE" "https://target.com/api/catalog/customers" | grep -oP '100\.\d+\.\d+\.\d+'

# Check for customer/tenant data exposure
curl -s -b "session=COOKIE" "https://target.com/api/catalog/customers" | jq '.customers[].url'

# Decode session token for analysis
echo "eyJzaWQiOiAiZTY2..." | base64 -d 2>/dev/null || echo "eyJzaWQiOiAiZTY2..." | base64 -d -

# Check for internal service URLs
curl -s -b "session=COOKIE" "https://target.com/api/auth/me" | jq '.user.active_base_url'
```

## Exploitation Chains

### Credential Extraction

1. Enumerate DVCS/config endpoints (`.git`, `.env`, config files)
2. Extract credentials (DB, SMTP, JWT, cloud provider keys)
3. Use keys for cloud control plane access or lateral movement

### Version to CVE

1. Derive precise component versions from headers, errors, or client bundles
2. Map to known CVEs and confirm reachability in the target context
3. Execute minimal proof targeting the disclosed component version

### Path Disclosure to LFI

1. Collect absolute paths from stack traces, template errors, or source maps
2. Use the filesystem layout knowledge to guide LFI/traversal attempts
3. Fetch config files and keys via path traversal

### Schema to Auth Bypass

1. Enumerate hidden fields and endpoints via API schema (OpenAPI, GraphQL introspection, gRPC reflection)
2. Craft requests targeting those fields/operations
3. Confirm missing authorization on the discovered surface

## Commands

```bash
# Clone a git-revealing target
wget --mirror --include-directories=.git https://target.com/.git/

# Dump git objects
git checkout -- .

# GraphQL introspection dump
gql introspection https://target.com/graphql > schema.json

# Source map extraction
curl -s https://target.com/static/js/main.js.map | jq -r '.sources[]'
```

## Tools

- **git-dumper** — Reconstruct git repos from exposed `.git` folders
- **GraphQL Voyager / graphql-introspection** — Dump GraphQL schemas
- **Burp Suite** — Proxy for differential analysis and artifact enumeration
- **ffuf/gobuster** — Directory/file enumeration for backup and config files
- **LinkFinder / JSParser** — Extract endpoints from JavaScript bundles
- **SourceMapReader** — Decompile source maps to original code
- **gRPCurl** — gRPC reflection queries
- **Nuclei** — Template-based scanning for known disclosure endpoints

## Not a Finding If

- Intentional public documentation or non-sensitive metadata with no exploit path
- Generic error pages with no actionable details (no stack traces, paths, or versions)
- Redacted fields that do not change differential oracle behavior
- Version banners (e.g., `Server: nginx`) with no exposed vulnerable surface and no additional chain
- Owner-visible-only details that do not cross identity or tenant boundaries
- Publicly documented API fields returned in expected responses
- Standard headers with no version information or internal routing data

## Notes

- Start with artifacts (DVCS, backups, maps) before payloads; artifacts yield the fastest wins
- The "easy-wins" misconfiguration checklist is: debug/status endpoints, default credentials, open admin panels, directory listing, backup files, dev/staging endpoints — test these before any payload-based testing
- Normalize responses and diff by digest to reduce noise when comparing roles
- Hunt source maps and client data JSON; they often carry internal IDs and flags
- Probe caches/CDNs for identity-unaware keys; verify `Vary` includes Authorization/tenant scope
- Treat introspection and reflection as configuration findings across GraphQL/gRPC
- Mine observability endpoints last; they are noisy but high-yield in misconfigured setups
- Chain quickly to a concrete risk and stop — proof should be minimal and reversible

### Impact

- Accelerated exploitation of RCE/LFI/SSRF via precise versions and paths
- Credential/secret exposure leading to persistent external compromise
- Cross-tenant data disclosure through exports, caches, or mis-scoped signed URLs
- Privacy/regulatory violations and business intelligence leakage

## References

- https://portswigger.net/web-security/information-disclosure

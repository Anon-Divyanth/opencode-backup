---
name: "recon-attack-surface-mapping"
version: "2.0"
category: "recon"
subcategory: "attack-surface"
phase: "reconnaissance"
tags: ["bug-bounty", "recon", "attack-surface", "asn", "ct-logs", "cloud", "github-osint"]
tools: ["subfinder", "assetfinder", "amass", "puredns", "dnsx", "gau", "katana", "naabu", "httpx", "shodan", "censys", "massdns", "dnsgen", "securitytrails"]
follow_up_skills: ["js-recon-tricks", "subdomain-takeover", "ffuf-web-fuzzing", "api-fuzzing", "subdomain-enumeration-checklist"]
description: "Bug bounty skill: recon attack surface mapping - reconnaissance phase, recon category"
---
# Bug Bounty Recon Mastery — Advanced Reconnaissance and Attack Surface Mapping

## Summary

Complete reconnaissance workflow covering certificate analysis, subdomain enumeration (passive/active/permutation), ASN mapping, GitHub OSINT, historical data extraction, cloud asset discovery, and automated pipeline construction for authorized security testing.

## Key Concepts

- **Attack surface mapping**: Identifying all assets (subdomains, IPs, cloud resources, APIs) belonging to a target
- **CT logs**: Append-only public ledgers of every TLS certificate — the single most effective passive source for subdomains
- **Wildcard DNS**: `*.example.com` causes all non-existent subdomains to resolve, creating false positives — must be filtered
- **ASN enumeration**: Finding all IP ranges under the same ASN reveals shared infrastructure
- **Permutation attack**: Generating mutations of known subdomains (prefixes, suffixes, environment/region variants)
- **CSP leakage**: Content-Security-Policy headers often leak subdomains, CDN origins, and API endpoints
- **Cloudflare bypass**: Origin IPs hidden behind Cloudflare can be found via historical DNS, Shodan, non-proxied subdomains
- **GitHub dorking**: Searching code, commits, and config files for secrets, internal URLs, and credentials

## Technical Details

### TLS Certificate Deep Analysis

Certificate intelligence extraction:
- **Issuer CA**: Identifies CA provider (e.g., `WE1` = Google Trust Services)
- **Short validity (90 days)**: Suggests ACME automation (Certbot, Google managed TLS)
- **Subject Alt Names (SANs)**: Directly reveals associated domains/subdomains
- **Public key fingerprint**: Can track certificate reuse across different services to identify shared infrastructure

### Cloudflare Proxying Detection

A records resolving to `162.159.152.4` or `162.159.153.4` = Cloudflare edge IPs (AS13335). Implications:
- Origin IPs hidden behind Cloudflare
- WAF rules apply at edge
- Direct origin access requires historical DNS, Shodan, or Censys

### Subdomain Enumeration Phases

1. **CT log scraping** (crt.sh) — passive, foundational
2. **Multi-engine passive aggregation** — Subfinder, Assetfinder, Amass, Findomain, Sublist3r, Chaos
3. **DNS bruteforce** (active) — massdns, shuffledns, puredns with wildcard filtering
4. **Permutation attack** — dnsgen with smart prefix/suffix generation

### Wildcard DNS Filtering

`*.example.com` is critical — use tools with wildcard detection:
```sh
puredns bruteforce wordlist.txt example.com -r resolvers.txt --wildcard-batch 1000000 -o results.txt
cat subs.txt | dnsx -a -resp -wd example.com -o real_subs.txt
```

### CSP Subdomain Leakage

```http
Content-Security-Policy:
  default-src 'self';
  script-src 'self' cdn-client.example.com cdn-static-1.example.com *.cloudflare.com;
  img-src 'self' cdn-images-1.example.com cdn-images-2.example.com miro.example.com *.gravatar.com;
  connect-src 'self' api.example.com *.sentry.io;
  frame-src 'self' example.com *.example.com
```

### Cloudflare Origin IP Bypass Methods

1. Historical DNS records (SecurityTrails)
2. Pre-Cloudflare certificates in CT logs
3. Shodan search excluding Cloudflare: `ssl.cert.subject.cn:example.com -cloudflare`
4. Non-proxied subdomains (mail, gray cloud)
5. Direct-to-origin probes with Host header

## Methodology

### Phase 1: Certificate Analysis

```bash
openssl s_client -connect $DOMAIN:443 -servername $DOMAIN -showcerts </dev/null 2>/dev/null | openssl x509 -text -noout
openssl s_client -connect $DOMAIN:443 -servername $DOMAIN </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[] | "\(.name_value) | \(.not_before) → \(.not_after)"'
dig CAA $DOMAIN +short
```

### Phase 2: Multi-Engine Passive Subdomain Enumeration

```bash
subfinder -d example.com -all -recursive -silent -o subs_subfinder.txt
assetfinder --subs-only example.com > subs_assetfinder.txt
amass enum -passive -d example.com -o subs_amass.txt
findomain -t example.com -u subs_findomain.txt
sublist3r -d example.com -o subs_sublist3r.txt
chaos -d example.com -silent -o subs_chaos.txt
cat *_subs*.txt | grep -E '\.example\.com$' | sort -u > all_passive_subs.txt
```

### Phase 3: Active DNS Bruteforce

```bash
massdns -r resolvers.txt -t A -o S -w massdns_output.txt all_passive_subs.txt
grep -E " A " massdns_output.txt | awk '{print $1}' | sed 's/\.$//' > resolved_subs.txt

puredns bruteforce /usr/share/wordlists/SecLists/Discovery/DNS/deepmagic.com-prefixes-top50000.txt example.com -r resolvers.txt --wildcard-batch 1000000 -o puredns_results.txt
```

### Phase 4: Permutation Attack

```bash
pip3 install dnsgen
cat real_subs.txt | dnsgen - -w /usr/share/seclists/Discovery/DNS/permutations_list.txt > permutations.txt
cat permutations.txt | massdns -r resolvers.txt -t A -o S | grep -E " A " | awk '{print $1}' | sed 's/\.$//' > new_discovered.txt
```

### Phase 5: ASN Enumeration

```bash
# Find ASN from IP
whois -h whois.cymru.com " -c 162.159.152.4"
amass intel -org "example" -asn 13335

# Enumerate IP ranges
whois -h whois.radb.net -- '-i origin AS13335' | grep -oP '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+'
```

### Phase 6: GitHub Reconnaissance

```bash
# API code search
curl -s -H "Authorization: token YOUR_GITHUB_TOKEN" "https://api.github.com/search/code?q=example.com&per_page=100"
# Orgs
curl -s "https://api.github.com/orgs/example/public_members" | jq '.[].login'
# Commit search
curl -s -H "Authorization: token YOUR_GITHUB_TOKEN" "https://api.github.com/search/commits?q=example.com"
```

### Phase 7: Historical Data Extraction

```bash
echo $TARGET | gau --subs --providers wayback,commoncrawl,otx,urlscan > all_urls.txt
grep -E '\.js(\?|$)' all_urls.txt | sort -u > js_files.txt
grep -iE '(api|graphql|rest|v1|v2|internal)' all_urls.txt > api_endpoints.txt
grep -oP '\?[^ ]+' all_urls.txt | sed 's/\?//' | tr '&' '\n' | cut -d'=' -f1 | sort -u > parameters.txt
```

### Phase 8: Cloud Asset Discovery

```bash
# S3 buckets
for bucket in example example-assets example-static example-backup; do
  curl -s -o /dev/null -w "%{http_code}" "https://$bucket.s3.amazonaws.com"
done

# GCP buckets
curl -s -o /dev/null -w "%{http_code}" "https://storage.googleapis.com/$bucket/"

# Azure blobs
curl -s -o /dev/null -w "%{http_code}" "https://${blob}.blob.core.windows.net/"
```

## Payloads

No specific injection payloads — this is a recon methodology guide.

## Commands

### Certificate Analysis Script

```bash
#!/bin/bash
DOMAIN="example.com"
openssl s_client -connect $DOMAIN:443 -servername $DOMAIN -showcerts </dev/null 2>/dev/null | openssl x509 -text -noout > cert_full.txt
openssl s_client -connect $DOMAIN:443 -servername $DOMAIN </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName
openssl s_client -connect $DOMAIN:443 -servername $DOMAIN </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -fingerprint -pubkey
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[] | "\(.name_value) | \(.not_before) → \(.not_after) | \(.issuer_name)"' > ct_logs_full.txt
dig CAA $DOMAIN +short
```

### CT Log Advanced Search

```bash
# By Issuer CA
curl -s "https://crt.sh/?iCAID=286236&output=json" | jq -r '.[].name_value' | grep -E 'example\.com$' | sort -u
# By public key SHA-256 fingerprint (find shared hosting)
curl -s "https://crt.sh/?spkisha256=<sha256>&output=json" | jq -r '.[].name_value' | sort -u
# By serial number
curl -s "https://crt.sh/?serial=<serial>&output=json"
```

### Historical Reconnaissance Script

```bash
#!/bin/bash
TARGET="example.com"
echo $TARGET | gau --subs --providers wayback,commoncrawl,otx,urlscan > all_urls.txt
grep -E '\.js(\?|$)' all_urls.txt | sort -u > js_files.txt
grep -iE '(api|graphql|rest|v1|v2|v3|endpoint|internal)' all_urls.txt > api_endpoints.txt
grep -oP '\?[^ ]+' all_urls.txt | sed 's/\?//' | tr '&' '\n' | cut -d'=' -f1 | sort -u > parameters.txt
curl -s "http://web.archive.org/cdx/search/cdx?url=*.example.com/*&output=json&fl=original,timestamp,statuscode&limit=50000" > wayback_cdx.json
```

### JS Analysis

```bash
linkfinder.py -i $OUTPUT_DIR/js_downloads/ -o js_endpoints.json
cat *.js | jsluice -r > js_secrets.json
cat *.js | grep -oP '"(https?://[a-zA-Z0-9./_-]+)"' | sort -u > hardcoded_urls.txt
python3 SecretFinder.py -i *.js -o all_secrets.txt
katana -list js_files.txt -jc -o katana_output.txt
```

### DNS History

```bash
curl -s "https://api.securitytrails.com/v1/history/example.com/dns/a" -H "APIKEY: YOUR_KEY" | jq -r '.records[] | "\(.first_seen) → \(.last_seen): \(.values[].ip)"'
```

### ASN Pipeline

```bash
#!/bin/bash
TARGET="example.com"
IP=$(dig +short $TARGET | head -1)
ASN=$(whois -h whois.cymru.com " -c $IP" | tail -1 | awk '{print $1}')
whois -h whois.radb.net -- "-i origin AS$ASN" | grep -oP '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | sort -u > asn_ranges.txt
cat asn_ranges.txt | naabu -rate 500 -top-ports 1000 -silent -o naabu_ports.txt
cat naabu_ports.txt | httpx -silent -title -status-code -tech-detect -o fingerprint.txt
```

### Cloudflare Origin IP Discovery

```bash
curl -s "https://api.securitytrails.com/v1/history/example.com/dns/a" -H "APIKEY: YOUR_KEY"
shodan search "ssl.cert.subject.cn:example.com -cloudflare" --fields ip_str
dig +short url2204.mail.example.com
curl -H "Host: example.com" https://<origin-ip-candidate>
```

### GitHub Reconnaissance Script

```bash
#!/bin/bash
TARGET="example.com"
declare -a SECRET_PATTERNS=("example.*api.*key" "example.*secret" "example.*token" "AKIA[0-9A-Z]{16}" "sk_live_" "ghp_" "xox[bpsa]-")
for pattern in "${SECRET_PATTERNS[@]}"; do
  curl -s -H "Authorization: token YOUR_GITHUB_TOKEN" "https://api.github.com/search/code?q=$pattern+$TARGET&per_page=50" | jq '.items[] | {repo: .repository.full_name, path: .path, url: .html_url}'
done
curl -s "https://api.github.com/search/commits?q=example.com" | jq '.items[] | {repo: .repository.full_name, message: .commit.message, date: .commit.committer.date}'
curl -s "https://api.github.com/orgs/example/public_members" | jq '.[].login'
```

### GitHub Dorking Queries

```
"example.com" API key
"example.com" password
"example.com" .env
"example.com" "BEGIN RSA PRIVATE KEY"
"example.com" "aws_access_key_id"
"example.com" "db_password"
"example.com" filename:.env
"example.com" filename:credentials.json
"example.com" filename:terraform.tfvars
"example.com" filename:Kubeconfig
"@example.com" email
"@example.com" "git config"
```

### Cloud Bucket Discovery

```bash
# AWS S3
for bucket in example example-assets example-static example-uploads example-backup example-logs example-cdn example-prod example-staging example-dev; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://$bucket.s3.amazonaws.com")
  [ "$status" != "404" ] && echo "[!] FOUND: $bucket (HTTP $status)"
done

# GCP
for bucket in example example-assets example-static example-uploads example-backup; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://storage.googleapis.com/$bucket/")
  [ "$status" != "404" ] && echo "[!] GCP Bucket: $bucket"
done

# Azure
for blob in example example-assets example-static; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://${blob}.blob.core.windows.net/")
  [ "$status" != "404" ] && echo "[!] Azure Blob: $blob"
done
```

### MassDNS

```bash
git clone https://github.com/blechschmidt/massdns.git && cd massdns && make
wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt
./bin/massdns -r resolvers.txt -t A -w output.txt -o S -s 10000 wordlist.txt example.com
grep -E " A " output.txt | awk '{print $1}' | sed 's/\.$//' | sort -u > found.txt
```

### PureDNS

```bash
go install github.com/d3mondev/puredns/v2@latest
puredns bruteforce wordlist.txt example.com -r resolvers.txt --wildcard-batch 1000000 --wildcard-tests 10 --rate-limit 10000 -o results.txt
puredns resolve subs.txt -r resolvers.txt --wildcard-batch 1000000 -o resolved_real.txt
```

## Tools

- **subfinder** — Passive subdomain enumeration (40+ sources)
- **assetfinder** — Quick passive subdomain discovery
- **amass** — Advanced attack surface mapping (30+ integrations)
- **findomain** — Fast passive subdomain discovery
- **sublist3r** — Multi-engine subdomain enumeration (Google, Yahoo, Bing, Baidu, Netcraft, DNSDumpster)
- **chaos** — ProjectDiscovery's DNS dataset
- **massdns** — High-performance asynchronous DNS bruteforce
- **shuffledns** — Modern DNS bruteforce tool
- **puredns** — Wildcard-aware DNS resolver/bruteforcer
- **dnsx** — Multi-purpose DNS toolkit with wildcard filtering
- **dnsgen** — Subdomain permutation generator
- **httpx** — HTTP probing and fingerprinting
- **gau** — Get all URLs (Wayback, AlienVault, CommonCrawl, URLScan)
- **katana** — Web crawler for endpoint discovery
- **naabu** — Port scanner
- **LinkFinder** — Extract endpoints from JS
- **SecretFinder** — Extract secrets from JS
- **jsluice** — Extract secrets and endpoints from JS
- **S3Scanner** — AWS S3 bucket enumeration
- **cloud_enum** — Multi-cloud asset discovery
- **truffleHog** — Git secret scanning
- **ggshield** — Git secret scanning
- **Corsy** — CORS misconfiguration scanner
- **CORScanner** — CORS scanner
- **Shodan** — Internet device search engine
- **Censys** — Certificate and host search
- **BGPView** — ASN/IP intelligence
- **SecurityTrails** — DNS history and API
- **crt.sh** — Certificate Transparency log search

## Bypass Techniques

- **Cloudflare origin IP bypass**: Historical DNS (SecurityTrails), pre-Cloudflare CT logs, Shodan (-cloudflare filter), non-proxied mail subdomains, direct-to-origin Host header probes
- **Wildcard DNS filtering**: Use puredns or dnsx with `-wd` flag instead of naive massdns
- **Rate limiting evasion**: `--delay=2`, `--random-agent`, `--rate-limit` controls

## Notes

- CT logs are the single most effective passive source — even subdomains no longer in DNS or decommissioned appear here
- CSP headers leak subdomains not found by any other method — always extract CSP from live hosts
- `*.example.com` wildcard DNS creates massive false positives without proper tooling
- ASN enumeration reveals co-hosted domains sharing the same infrastructure
- GitHub commits often contain secrets that were removed from files but persist in git history
- Historical URLs (Wayback Machine) often reveal deleted endpoints, old API versions, and previously vulnerable pages
- Cloud assets (S3, GCP, Azure) are often named predictably after the target domain
- Always respect scope and have written authorization before brute-forcing or scanning

## References

- https://securitytalent.medium.com/bug-bounty-recon-mastery-advanced-reconnaissance-and-attack-surface-mapping-v2-c18e0a6738c9

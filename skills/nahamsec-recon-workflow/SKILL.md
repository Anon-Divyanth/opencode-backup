---
name: "nahamsec-recon-workflow"
version: "2.0"
category: "recon"
subcategory: "subdomain-enumeration"
phase: "reconnaissance"
tags: ["bug-bounty", "recon", "workflow", "subdomain-enumeration", "pipeline"]
tools: ["subfinder", "dnsx", "naabu", "httpx", "katana", "chaos", "ffuf", "gau", "waybackurls", "nuclei", "shuffledns"]
follow_up_skills: ["js-recon-tricks", "ffuf-web-fuzzing", "recon-attack-surface-mapping", "subdomain-enumeration-checklist"]
description: "Bug bounty skill: nahamsec recon workflow - reconnaissance phase, recon category"
---
# NahamSec Recon Methodology — "Free Recon Course and Methodology For Bug Bounty Hunters"

## Summary

NahamSec's (Ben Sadeghipour) practical, opinionated recon workflow combining passive subdomain enumeration, DNS bruteforce permutation, port scanning, HTTP probing, and JS crawling in a structured pipeline. Inspired by his YouTube course and live "Sunday Recon" sessions.

## Key Concepts

- **Three-stage mental model**: Asset Discovery (what exists) → Surface Analysis (what does it do) → Bug Discovery (where does it break). Most beginners skip straight to bug discovery; top hunters spend most time in stage 2.
- **Passive → Active → Analysis**: Never skip stages; progress in order

- **Passive → Active → Analysis**: Never skip stages; progress in order
- **Tool chaining**: Pipe output from one tool as input to the next for automation
- **API key configuration**: Subfinder, Amass, and SecurityTrails yield dramatically more results with free API keys configured
- **Alterx for permutations**: Generate domain name mutations from discovered subdomains rather than relying purely on wordlists
- **Chaos dataset**: ProjectDiscovery's DNS dataset often has ready-made subdomain lists for bug bounty programs
- **"Grep api" strategy**: Filter discovered subdomains for "api" then run permutations — API subdomains often follow predictable naming patterns

## Technical Details

### Passive Subdomain Enumeration (Phase 1)

The foundation — no packets sent to the target.

```bash
# Configure API keys first — critical for quality results
vim ~/.config/subfinder/provider-config.yaml

# Run subfinder
subfinder -d <domain> -silent | tee subfinder.txt

# Alternative/parallel tools
assetfinder --subs-only <domain> >> passive_subs.txt
amass enum -passive -d <domain> -o amass_subs.txt
```

### Active DNS Bruteforce (Phase 2)

Use shuffledns with a good wordlist and resolver list:

```bash
# Get fresh resolvers
wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt

# Bruteforce with shuffledns
shuffledns -d <domain> -w wordlist.txt -r resolvers.txt -mode bruteforce -silent | tee shuffledns_subs.txt
```

Recommended wordlists:
- [SecLists Discovery/DNS](https://github.com/danielmiessler/SecLists)
- [Assetnote wordlists](https://wordlists.assetnote.io)

### Permutation Attack (Phase 3)

Use alterx to generate domain permutations from already-discovered subdomains:

```bash
cat domains-from-shuffle.txt | alterx -silent | tee subdomains-alterx.txt
```

### DNS Resolution (Phase 4)

Verify which permuted domains actually resolve:

```bash
cat subdomains-alterx.txt | dnsx -silent -a -resp | tee resolved-subs.txt
```

### Port Scanning (Phase 5)

Scan top ports on resolved subdomains:

```bash
cat resolved-subs.txt | naabu -top-ports top 100 -silent | tee open-ports.txt
```

### HTTP Probing (Phase 6)

Fingerprint live web services:

```bash
cat open-ports.txt | httpx -silent -title -status-code -content-length -tech-detect | tee live-hosts.txt
```

### JS Crawling & Endpoint Discovery (Phase 7)

Crawl live hosts for JavaScript files and endpoints:

```bash
# Basic crawl
cat open-ports.txt | katana -silent -jsl | tee crawled-endpoints.txt

# Authenticated crawl (for private programs)
katana -u <domain> -H 'Cookie: <COOKIE-VALUE>' -xhr -jsl -aff -silent | tee auth-crawled.txt
```

## Methodology

### Full Automated Chain (NahamSec Style)

```bash
# 1. Passive subdomains
subfinder -d <domain> -silent -o subfinder.txt

# 2. DNS bruteforce
shuffledns -d <domain> -w /path/to/wordlist.txt -r resolvers.txt -mode bruteforce -o shuffledns.txt

# 3. Merge & dedupe
cat subfinder.txt shuffledns.txt | sort -u > all-subs.txt

# 4. Permutations
cat all-subs.txt | alterx -silent | dnsx -silent -a -resp | tee resolved-permutations.txt

# 5. Merge all resolved
cat all-subs.txt resolved-permutations.txt | sort -u > master-subs.txt

# 6. Port scan
cat master-subs.txt | naabu -top-ports top 100 -silent -o ports.txt

# 7. HTTP probe
cat ports.txt | httpx -silent -title -status-code -tech-detect -o live.txt

# 8. Crawl JS
cat ports.txt | katana -silent -jsl -o endpoints.txt
```

### Chaos-Client API Pipeline

A faster path for bug bounty programs in ProjectDiscovery's Chaos dataset:

```bash
chaos -d <domain> -silent | grep api | alterx -silent | dnsx -silent | naabu -top-ports top 100 -silent
```

Breakdown:
1. `chaos -d <domain>` — pull known subdomains from PD dataset
2. `grep api` — filter for API-related subdomains (often staging/dev)
3. `alterx` — generate permutations of those API subdomains (e.g., api-dev, api-staging, api-v2)
4. `dnsx` — check which permuted domains resolve
5. `naabu` — port scan the resolved IPs

This can then be piped into katana for JS crawling:

```bash
chaos -d <domain> -silent | grep api | alterx -silent | dnsx -silent | naabu -top-ports top 100 -silent | httpx -silent -title -status-code | katana -silent -jsl
```

### "It's the Little Things" Approach

NahamSec emphasizes automated, continuous recon using OSINT + standard tooling, checking for:
- New subdomains appearing over time
- New endpoints on existing hosts
- Changes in HTTP response headers/status codes
- New JS files exposing new endpoints

### Stage 2: Surface Analysis

This is where the money is. For every "interesting" subdomain (admin panels, API docs, login portals), perform content discovery, JS mining, parameter mining, and history analysis.

#### Content Discovery

```bash
# Common content fuzzing
ffuf -u https://target/FUZZ -w wordlist.txt -mc 200,204,301,302,401,403 \
     -ac -o content.json -of json

# Backup/sensitive extensions
ffuf -u https://target/FUZZ -w wordlist.txt -e .bak,.old,.zip,.tar.gz,.swp,.txt
```

Wordlists that matter: **SecLists** `Discovery/Web-Content/`, **assetnote** wordlists, Jhaddix's `all.txt`.

#### JavaScript Mining

Modern apps leak API endpoints, secrets, and feature flags in JS bundles.

```bash
# Pull every JS reference
katana -u https://target -d 5 -jc -kf all -o crawl.txt

# Extract endpoints from JS
cat crawl.txt | grep -E '\.js(\?|$)' | uniq > js_files.txt
xargs -I{} curl -s "{}" < js_files.txt | grep -Eo '"/[a-zA-Z0-9_/-]{4,}"' | sort -u

# Find secrets in JS
trufflehog filesystem ./downloaded_js/
```

#### Parameter Mining

```bash
# Hidden GET parameters
arjun -u https://target/api/users -t 50

# From request body
arjun -u https://target/api/users -m POST -d '{}' -t 50
```

#### History Analysis

Wayback and CommonCrawl URLs often reveal deprecated endpoints, old API versions, and forgotten files:

```bash
gau target.com | sort -u > history.txt
waybackurls target.com | sort -u >> history.txt
```

History reveals:
- Deprecated endpoints still serving live
- Parameters no longer in current code but still accepted
- Files that should have been deleted (backups, logs, configs)

### Stage 3: Bug Discovery

Only after completing surface analysis do you run targeted vulnerability scanners:

```bash
# Nuclei with curated templates
nuclei -l probed.txt -t ~/nuclei-templates/ -severity medium,high,critical -rate-limit 50

# Custom templates for the program's tech stack
nuclei -l probed.txt -t custom-templates/jira/ -t custom-templates/aws/
```

Nuclei is a force multiplier for known issues — it will never find a logic flaw, an IDOR, or a privilege escalation. Those come from manual testing of the surfaces discovered in Stage 2.

### Prioritization

With hundreds of candidate URLs from Stage 2, prioritize by:

1. **Authentication mismatches** — endpoints with both authenticated and unauthenticated handlers
2. **Admin/internal endpoints** leaked to public domains
3. **API endpoints with object IDs** — IDOR / BOLA candidates
4. **File upload / download** functionality
5. **Endpoints that accept URLs** — SSRF / open redirect candidates

### Common Mistakes

- **Recon-only loops** — collecting subdomains forever, never moving to analysis
- **No notes** — re-doing the same recon every session instead of building on previous work
- **Ignoring scope** — `*.target.com` doesn't always include `*.target-foo.com`
- **Running scanners without throttling** — getting banned and losing program access
- **Skipping to bug discovery** — running `nuclei -t cves/` immediately without understanding the surface

## Tools

| Tool | Phase | Purpose |
|------|-------|---------|
| **subfinder** | Passive enum | 40+ passive source aggregation |
| **assetfinder** | Passive enum | tomnomnom's passive subdomain tool |
| **amass** | Passive enum | Deep passive coverage with API keys |
| **shuffledns** | Active bruteforce | Modern DNS bruteforce with wildcard filtering |
| **alterx** | Permutations | Domain name mutation generation |
| **dnsx** | Resolution | Multi-purpose DNS toolkit |
| **naabu** | Port scan | Fast port scanning |
| **httpx** | HTTP probing | Live host fingerprinting (status, title, tech) |
| **katana** | Crawling | JS endpoint discovery and crawling |
| **chaos** | Dataset | ProjectDiscovery DNS dataset |
| **puredns** | Resolution | Wildcard-aware DNS resolver |
| **ffuf** | Content discovery | Web fuzzing for hidden directories/files |
| **gotator** | Permutations | Subdomain permutation generation |
| **arjun** | Parameter mining | HTTP parameter discovery |
| **gau** | History | Get all URLs (Wayback, AlienVault, CommonCrawl, URLScan) |
| **waybackurls** | History | Wayback Machine URL extractor |
| **trufflehog** | JS secrets | Git/JS secret scanning |
| **nuclei** | Bug discovery | Template-based vulnerability scanner |
| **nmap** | Port scanning | Full TCP service version scan |

## Bypass Techniques

- **Wildcard DNS filtering**: Use shuffledns/puredns/dnsx with wildcard detection flags instead of naive massdns
- **Rate limiting**: Add delay flags or use `--rate-limit` on naabu/httpx
- **API key configuration**: Free tiers of Shodan, VirusTotal, SecurityTrails massively improve passive enumeration results

## Notes

- The Chaos dataset only covers public bug bounty programs — not useful for private programs or pentests
- API subdomain naming patterns are highly predictable: api, api-dev, api-staging, api-v2, api-internal, api-admin
- Configure subfinder provider config before running for best results
- Authenticated crawling (katana with cookies) reveals more endpoints than unauthenticated
- NahamSec recommends watching live "Sunday Recon" streams to see the methodology applied to real targets
- Understanding why each tool is used matters more than the tool count — quality over quantity

## References

- https://www.youtube.com/watch?v=evyxNUzl-HA
- https://blog.zaakir.io/bugbounty-methodology
- https://www.nahamsec.com/getting-started-in-bug-bounty
- https://github.com/projectdiscovery/subfinder
- https://github.com/projectdiscovery/shuffledns
- https://github.com/projectdiscovery/chaos-client
- https://github.com/projectdiscovery/alterx
- https://cybersecurityelite.com/bug-bounty/bug-bounty-recon-methodology/

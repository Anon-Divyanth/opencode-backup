---
name: "subdomain-enumeration-checklist"
version: "2.0"
category: "recon"
subcategory: "subdomain-enumeration"
phase: "reconnaissance"
tags: ["bug-bounty", "recon", "subdomains", "checklist", "dns"]
tools: ["subfinder", "assetfinder", "findomain", "puredns", "amass", "ffuf", "waybackurls", "dnsx", "crt.sh"]
follow_up_skills: ["subdomain-takeover", "recon-attack-surface-mapping", "api-fuzzing", "ffuf-web-fuzzing", "sqli", "xss"]
description: "Bug bounty skill: subdomain enumeration checklist - reconnaissance phase, recon category"
---
# Subdomain Enumeration Checklist

## Summary

Actionable tick-box methodology for comprehensive subdomain discovery combining automated tools, public sources, and processing pipelines.

## 1.1 Automated Enumeration

- [ ] **Subfinder** — Passive discovery using 40+ data sources
  ```bash
  subfinder -d target.com -all -recursive -o subfinder.txt
  ```
- [ ] **Assetfinder** — tomnomnom's passive subdomain discovery
  ```bash
  assetfinder --subs-only target.com > assetfinder.txt
  ```
- [ ] **Findomain** — Cross-platform subdomain enumerator
  ```bash
  findomain -t target.com
  ```
- [ ] **Puredns** — Wildcard-aware DNS bruteforce with wordlists
  ```bash
  puredns bruteforce wordlist.txt example.com -r resolvers.txt -w bruteforce-results.txt
  puredns bruteforce subdomains_n0kovo_medium.txt xiotz.com -r resolvers.txt -w bruteforce-results.txt
  ```
- [ ] **Amass Passive** — OSINT-based discovery (30+ integrations)
  ```bash
  amass enum -passive -d target.com
  ```
- [ ] **Amass Active** — DNS resolution-based active discovery
  ```bash
  amass enum -active -d target.com
  ```

## 1.2 Public Sources

- [ ] **Certificate Transparency (crt.sh)** — Extract subdomains from CT logs
  ```bash
  curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > crtsh.txt
  ```
- [ ] **Wayback Machine (waybackurls)** — Historical subdomain discovery
  ```bash
  curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original&collapse=urlkey" | sort | sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' | sort -u > wayback.txt
  ```
- [ ] **AlienVault OTX** — Threat intelligence passive DNS data
  ```bash
  curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/target.com/passive_dns" | jq -r '.passive_dns[]?.hostname' | grep -E '^[a-zA-Z0-9.-]+\.target\.com$' | sort -u | tee alienvault_subs.txt
  ```
- [ ] **URLScan.io** — Indexed domains search
  ```bash
  curl -s "https://urlscan.io/api/v1/search/?q=domain:target.com&size=10000" | jq -r '.results[]?.page?.domain' | grep -E '^[a-zA-Z0-9.-]+\.target\.com$' | sort -u | tee urlscan_subs.txt
  ```
- [ ] **Subdomain Finder (c99.nl)** — Web-based subdomain lookup
  ```bash
  # Browse: https://subdomainfinder.c99.nl/
  ```
- [ ] **FFUF** — Subdomain bruteforce via DNS/fuzzing
  ```bash
  ffuf -w wordlist.txt -u https://FUZZ.target.com
  ```
- [ ] **VirusTotal** — Domain siblings and passive DNS lookup
  ```bash
  curl -s "https://www.virustotal.com/api/v3/domains/target.com/subdomains" -H "x-apikey: YOUR_KEY"
  ```
- [ ] **GitHub** — Search repositories for hardcoded subdomains
  ```bash
  curl -s -H "Authorization: token YOUR_GITHUB_TOKEN" "https://api.github.com/search/code?q=.target.com&per_page=100"
  ```

## 1.3 Subdomain Processing

- [ ] **Merge and Deduplicate** — Combine all subdomain files and remove duplicates
  ```bash
  cat *_subs*.txt crtsh.txt wayback.txt alienvault_subs.txt urlscan_subs.txt | sort -u > all_subs.txt
  ```
- [ ] **Resolve with Puredns** — Filter to live, resolvable subdomains (handles wildcards)
  ```bash
  cat all_subs.txt | puredns resolve -r resolvers.txt | tee resolved.txt
  ```

## Tools

| Tool | Type | Purpose |
|------|------|---------|
| Subfinder | Passive | Multi-source passive aggregation |
| Assetfinder | Passive | Lightweight passive discovery |
| Findomain | Passive | Cross-platform subdomain enum |
| Puredns | Active/Bruteforce | Wildcard-aware DNS bruteforce + resolution |
| Amass | Passive/Active | Deep OSINT + DNS resolution |
| crt.sh | Public source | Certificate Transparency logs |
| waybackurls | Public source | Wayback Machine historical data |
| AlienVault OTX | Public source | Threat intelligence passive DNS |
| URLScan.io | Public source | Indexed domain search |
| c99.nl | Public source | Web-based subdomain finder |
| FFUF | Fuzzing | Subdomain name fuzzing |
| VirusTotal | Public source | Domain passive DNS / siblings |
| GitHub | Public source | Code search for subdomains |

## Notes

- Configure API keys for Subfinder, Amass, VirusTotal, and GitHub before running for maximum results
- Always deduplicate before resolution to avoid redundant DNS queries
- Puredns handles wildcard DNS filtering automatically — prefer it over raw massdns
- Public sources (crt.sh, AlienVault, URLScan, Wayback) require no API keys and are a fast first pass
- GitHub search requires a personal access token — without it, rate limits are extremely restrictive

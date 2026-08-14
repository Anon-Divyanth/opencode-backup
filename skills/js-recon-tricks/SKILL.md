---
name: "js-recon-tricks"
version: "2.0"
category: "recon"
subcategory: "js-recon"
phase: "reconnaissance"
tags: ["bug-bounty", "recon", "javascript", "endpoint-discovery", "source-maps", "spa"]
tools: ["katana", "gau", "waybackurls", "linkfinder", "secretfinder", "sourcemapper"]
follow_up_skills: ["js-secret-hunting", "ffuf-web-fuzzing", "api-fuzzing"]
description: "Bug bounty skill: js recon tricks - reconnaissance phase, recon category"
---
# JavaScript Recon Tricks

## Summary

JavaScript files in modern web apps (React, Vue, Angular, Next.js) expose the developer's entire backend mental model — every API route, admin endpoint, feature flag, third-party integration, and accidental secret. This article covers 20 techniques for extracting hidden APIs, secrets, admin routes, and endpoints from JS files for bug bounty recon.

## Key Concepts

- **JS as Recon Source**: JS files contain routes, API URLs, and config that scanners never find.
- **Minified ≠ Safe**: Build tools compress code but the content (route strings, API URLs, env vars) remains.
- **Source Maps**: `.map` files can reconstruct the original unminified source code.
- **Historical JS**: Old JS files from Wayback Machine reveal zombie endpoints still active on the server.
- **Entropy Detection**: Catches secrets with no known regex pattern (high entropy = likely secret).

## Technical Details

### What JS Files Expose

- Hardcoded secrets — API keys, AWS credentials, tokens
- Hidden API endpoints — routes the UI never shows
- Admin routes — panels behind feature flags or role checks
- Internal domain names — staging servers, internal tools
- Feature flags — half-built features live but hidden
- GraphQL schemas — complete backend data model
- Version info — library versions mapping to CVEs
- Business logic — how the app makes decisions

### Phase 1: Find the JavaScript Files

**Trick #1 — Browser Bookmarklet to Extract All JS Files**

```javascript
javascript:(function(){
  var scripts = document.querySelectorAll('script[src]');
  var urls = Array.from(scripts).map(s => s.src).filter(Boolean);
  if(window.performance) {
    var entries = performance.getEntriesByType('resource');
    entries.forEach(e => {
      if(e.name.includes('.js') && !e.name.includes('.json')) {
        urls.push(e.name);
      }
    });
  }
  urls = [...new Set(urls)];
  var blob = new Blob([urls.join('\n')], {type:'text/plain'});
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'js_files.txt';
  document.body.appendChild(a);
  a.click();
  alert('Found ' + urls.length + ' JS files! Downloading...');
})();
```

Captures SPAs' lazy-loaded chunks that the HTML source never shows.

**Trick #2 — Katana Deep Crawl**

```bash
katana -u https://$TARGET -jc -jsl -d 5 -silent -o katana_js.txt
cat katana_js.txt | grep "\.js$\|\.js?" | sort -u | anew js_urls.txt
```

`-jc` enables JS crawling, `-jsl` parses JS source lists — catches JS files only referenced from other JS files.

**Trick #3 — Historical JS from Wayback Machine**

```bash
echo $TARGET | waybackurls | grep "\.js" | grep -v "\.json" | sort -u | anew wayback_js.txt
```

Old JS files reveal deprecated endpoints that may still be live and unprotected.

**Trick #4 — GAU Multi-Source Harvester**

```bash
gau $TARGET --subs --threads 10 | grep "\.js" | \
  grep -v "jquery\|bootstrap\|analytics\|gtag\|facebook\|twitter\|linkedin" | \
  sort -u | anew all_js_urls.txt
```

Queries Wayback Machine + CommonCrawl + URLScan + OTX simultaneously.

**Trick #5 — Download All JS Files for Offline Analysis**

```bash
mkdir -p js_files
cat all_js_urls.txt | while read url; do
  filename=$(echo "$url" | md5sum | cut -d' ' -f1).js
  curl -s --connect-timeout 10 "$url" -o "js_files/$filename" 2>/dev/null && \
    echo "# $url" >> "js_files/$filename" && \
    echo "[+] Downloaded: $url"
done
```

### Phase 2: Extract Hidden Endpoints and API Routes

**Trick #6 — LinkFinder**

```bash
for file in js_files/*.js; do
  python3 LinkFinder/linkfinder.py -i "$file" -o cli 2>/dev/null
done | sort -u | anew endpoints.txt

cat endpoints.txt | grep -E "^/api|^/v[0-9]|^/admin|^/internal|^/graphql|^/webhook"
```

**Trick #7 — Webpack Chunk Name Analysis**

```bash
curl -s "https://$TARGET" | grep -oE 'src="[^"]*\.js"' | head -5
curl -s "https://$TARGET/static/js/main.abc123.js" | \
  grep -oE '"[a-z]+\.(admin|billing|settings|user|api|dashboard|reports|config|internal|webhook|payment)[^"]*"' | \
  sort -u
```

Chunks like `chunk-admin.d4e5f6.js` contain admin panel routing and API calls — even if the UI hides the admin panel.

```bash
curl -s "https://$TARGET/static/js/chunk-admin.d4e5f6.js" | \
  python3 LinkFinder/linkfinder.py -i - -o cli
```

**Trick #8 — GraphQL Schema Extraction**

```bash
grep -r "graphql\|/gql\|__schema\|IntrospectionQuery" js_files/ | \
  grep -oE '"[^"]*graphql[^"]*"' | sort -u

curl -s -X POST "https://$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}' | jq '.data.__schema.types[].name'
```

Full introspection maps every query and mutation including admin-only ones.

**Trick #9 — Feature Flag and Hidden Route Discovery**

```bash
grep -r "featureFlag\|feature_flag\|isAdmin\|isBeta\|isInternal\|isDev\|canAccess\|hasPermission" \
  js_files/ | grep -oE '"[^"]*"' | sort -u | head -30

grep -rE '["'"'"'][/a-zA-Z0-9_-]*(admin|internal|debug|test|staff|superuser|moderator)[/a-zA-Z0-9_-]*["'"'"']' \
  js_files/ | grep -oE '"[^"]*"' | sort -u
```

**Trick #10 — API Version Enumeration**

```bash
grep -roh '["'"'"']/v[0-9][^"'"'"']*["'"'"']' js_files/ | tr -d '"'"'" | sort -u | anew api_versions.txt

cat api_versions.txt | while read endpoint; do
  v1_endpoint=$(echo "$endpoint" | sed 's/v[2-9]/v1/g')
  v2_endpoint=$(echo "$endpoint" | sed 's/v[3-9]/v2/g')
  echo "[Test] $v1_endpoint"
  echo "[Test] $v2_endpoint"
done
```

Older API versions often have weaker auth — zombie endpoints.

### Phase 3: Hunt for Secrets

**Trick #11 — SecretFinder**

```bash
python3 SecretFinder/SecretFinder.py -i "js_files/" -o cli -r 2>/dev/null | anew secrets_found.txt
cat secrets_found.txt | grep -E "AWS|sk-|api_key|firebase|stripe|twilio|sendgrid|private_key"
```

| Pattern | Example |
|---------|---------|
| OpenAI key | `sk-proj-abc123...` |
| AWS Access Key | `AKIAIOSFODNN7EXAMPLE` |
| AWS Secret Key | `wJalrXUtnFEMI/K7MDENG/bPxRfiCYExample` |
| Google API Key | `AIzaSyDxx...` |
| Firebase Config | `apiKey: "AIza..."` |
| Stripe Key | `sk_live_abc...` or `pk_live_abc...` |
| JWT Secret | `secret: "myJwtSecret"` |
| SendGrid Key | `SG.xxx...` |
| Twilio Auth | `AC...` + token pair |

**Trick #12 — Entropy-Based Secret Detection**

```python
python3 - << 'EOF'
import math, re, sys, os

def entropy(s):
    if not s: return 0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    return -sum((v/len(s)) * math.log2(v/len(s)) for v in counts.values())

for root, dirs, files in os.walk('js_files'):
    for fname in files:
        if not fname.endswith('.js'): continue
        fpath = os.path.join(root, fname)
        try:
            content = open(fpath, encoding='utf-8', errors='ignore').read()
            strings = re.findall(r'["\']([A-Za-z0-9+/=_\-]{20,})["\']', content)
            for s in strings:
                e = entropy(s)
                if e > 4.5:
                    print(f"[HIGH ENTROPY {e:.2f}] {s[:80]} | File: {fpath}")
        except: pass
EOF
```

Catches custom internal tokens and base64-encoded credentials that regex misses.

**Trick #13 — Base64 Secret Decoder**

```bash
grep -roh '[A-Za-z0-9+/]\{40,\}=*' js_files/ | while read b64; do
  decoded=$(echo "$b64" | base64 -d 2>/dev/null)
  if echo "$decoded" | grep -qE "[a-zA-Z]{4,}"; then
    echo "ENCODED: $b64"
    echo "DECODED: $decoded"
    echo "---"
  fi
done | head -100
```

Finds encoded connection strings like `mongodb://admin:password@cluster.mongodb.net/db`.

### Phase 4: Source Maps

**Trick #14 — Discover Exposed Source Maps**

```bash
curl -si "https://$TARGET/static/js/main.abc.js.map" | head -5
curl -si "https://$TARGET/app.min.js.map" | head -5

cat js_urls.txt | while read js_url; do
  map_url="${js_url}.map"
  status=$(curl -s -o /dev/null -w "%{http_code}" "$map_url")
  if [ "$status" = "200" ]; then
    echo "[EXPOSED SOURCE MAP] $map_url"
  fi
done
```

**Trick #15 — Reconstruct Source Code from Map Files**

```bash
go install github.com/denandz/sourcemapper@latest
sourcemapper -url "https://$TARGET/static/js/main.abc.js.map" \
  -output ./reconstructed_source/

ls reconstructed_source/src/
# → components/ pages/ api/ utils/ config/ admin/ ...

grep -r "admin\|password\|secret\|apiKey\|token\|internal" reconstructed_source/ | \
  grep -v "node_modules\|test\|spec" | head -50
```

**Trick #16 — Source Map Endpoint Goldmine**

```bash
grep -rE "fetch\(|axios\.(get|post|put|delete|patch)\(|\.request\(" reconstructed_source/ | \
  grep -oE '"[^"]*"' | grep -E "^/|^http" | sort -u | anew endpoints_from_source.txt

grep -rE "path:\s*['\"]|route\(['\"]|router\.(get|post|put)\(['\"]" reconstructed_source/ | \
  grep -oE '["\'][/a-zA-Z0-9:_-]+["\']' | tr -d '"'"'" | sort -u
```

### Phase 5: Advanced Tricks

**Trick #17 — JS Diff Monitoring**

```bash
#!/bin/bash
TARGET_JS_URL="https://$TARGET/static/js/main.abc123.js"
HASH_FILE="js_hash.txt"
PREV_ENDPOINTS="prev_endpoints.txt"
CURR_ENDPOINTS="curr_endpoints.txt"

curl -s "$TARGET_JS_URL" -o current.js
current_hash=$(md5sum current.js | cut -d' ' -f1)
prev_hash=$(cat "$HASH_FILE" 2>/dev/null || echo "none")
if [ "$current_hash" != "$prev_hash" ]; then
  echo "[!] JS CHANGED! New hash: $current_hash"
  python3 LinkFinder/linkfinder.py -i current.js -o cli 2>/dev/null | sort -u > "$CURR_ENDPOINTS"
  echo "[+] NEW ENDPOINTS SINCE LAST CHECK:"
  diff "$PREV_ENDPOINTS" "$CURR_ENDPOINTS" 2>/dev/null | grep "^>" | sed 's/^> //'
  echo "$current_hash" > "$HASH_FILE"
  cp "$CURR_ENDPOINTS" "$PREV_ENDPOINTS"
fi
(crontab -l; echo "0 * * * * /bin/bash /path/to/monitor_js.sh >> /tmp/js_monitor.log 2>&1") | crontab -
```

**Trick #18 — Find Internal Domains and Staging Servers**

```bash
grep -roh 'https\?://[a-zA-Z0-9.-]*\.[a-zA-Z]\{2,\}[^"'"'"' ]*' js_files/ | \
  sort -u | grep -v "cdn\|static\|jquery\|google\|facebook\|twitter\|linkedin\|github\|cloudflare" | \
  anew internal_domains.txt

grep -roh 'localhost:[0-9]\+\|127\.0\.0\.1\|10\.[0-9]\+\.[0-9]\+\|192\.168\.[0-9]\+\|172\.[0-9]\+\.[0-9]\+' \
  js_files/ | sort -u

grep -roh '[a-zA-Z0-9-]*\.\(staging\|dev\|test\|internal\|local\|beta\|uat\)\.[a-zA-Z]\{2,\}' \
  js_files/ | sort -u
```

**Trick #19 — Environment Variable and Config Object Extraction**

```bash
grep -roh 'REACT_APP_[A-Z_]*\s*[:=]\s*["\'][^"'"'"']*["\']' js_files/ | sort -u
grep -roh 'VITE_[A-Z_]*\s*[:=]\s*["\'][^"'"'"']*["\']' js_files/ | sort -u
grep -roh 'process\.env\.[A-Z_]*' js_files/ | sort -u

grep -roh 'config\s*=\s*{[^}]*}' js_files/ | head -20

grep -roh 'apiKey\s*:\s*"[^"]*"\|authDomain\s*:\s*"[^"]*"\|projectId\s*:\s*"[^"]*"' \
  js_files/ | sort -u

grep -roh 'pk_live_[a-zA-Z0-9]*\|pk_test_[a-zA-Z0-9]*\|sk_live_[a-zA-Z0-9]*' \
  js_files/ | sort -u
```

**Trick #20 — Full Automated Pipeline (JSHawk)**

```bash
jshawk $TARGET \
  --wayback --source-maps --validate --html \
  --threads 30 --output ./jshawk_report/
```

Or manual pipeline:

```bash
echo "=== PHASE 1: Collect JS URLs ===" && \
  katana -u "https://$TARGET" -jc -d 5 -silent | grep "\.js" | sort -u | anew all_js_urls.txt && \
echo "=== PHASE 2: Historical JS ===" && \
  gau $TARGET | grep "\.js" | grep -v "jquery\|bootstrap\|google" | sort -u | anew all_js_urls.txt && \
echo "=== PHASE 3: Download Files ===" && \
  mkdir -p js_files && \
  cat all_js_urls.txt | xargs -P 10 -I {} curl -s --connect-timeout 5 {} -o "js_files/$(echo {} | md5sum | cut -d' ' -f1).js" && \
echo "=== PHASE 4: Extract Endpoints ===" && \
  for f in js_files/*.js; do python3 LinkFinder/linkfinder.py -i "$f" -o cli 2>/dev/null; done | sort -u | anew endpoints.txt && \
echo "=== PHASE 5: Hunt Secrets ===" && \
  python3 SecretFinder/SecretFinder.py -i "js_files/" -o cli -r 2>/dev/null | anew secrets.txt && \
echo "=== PHASE 6: Check Source Maps ===" && \
  cat all_js_urls.txt | while read u; do status=$(curl -s -o /dev/null -w "%{http_code}" "${u}.map"); [ "$status" = "200" ] && echo "[EXPOSED MAP] ${u}.map"; done && \
echo "=== DONE ==="
```

## Methodology

1. **Phase 1 — Find JS Files**: Bookmarklet, Katana crawl, Wayback/GAU historical, download for offline analysis.
2. **Phase 2 — Extract Endpoints**: LinkFinder, Webpack chunk analysis, GraphQL introspection, feature flag discovery, API version enumeration.
3. **Phase 3 — Hunt Secrets**: SecretFinder (regex), entropy detection, base64 decoding.
4. **Phase 4 — Source Maps**: Discover `.map` files, reconstruct original source with sourcemapper, grep for endpoints and secrets.
5. **Phase 5 — Advanced**: JS diff monitoring (cron), internal domain discovery, env var extraction, full pipeline automation.

### What to Do With Findings

- **Hidden API endpoint**: Try unauthenticated, test with lower-privilege session, test IDOR, mass assignment, excessive data exposure.
- **Secret/API key**: Identify service, verify read-only, screenshot proof, report immediately.
- **Admin route**: Try as regular user, header tricks (X-Original-URL, X-Rewrite-URL), path traversal.
- **Internal domain**: DNS resolution, subdomain enum, cookie scope test, CORS misconfiguration.

## Commands

```bash
# Setup tools
git clone https://github.com/GerbenJavado/LinkFinder.git
git clone https://github.com/m4ll0k/SecretFinder.git
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/tomnomnom/anew@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
npm install -g source-map-explorer
pip3 install trufflehog

# Set target
export TARGET="example.com"
```

## Tools

- **LinkFinder** — Endpoint extraction from JS (regex-based URL finding)
- **SecretFinder** — Secret detection in JS (regex patterns for API keys, tokens)
- **JSHawk** — Advanced JS security scanner (automated pipeline)
- **sourcemapper** — Source map reconstruction (denandz/sourcemapper)
- **Katana** — ProjectDiscovery web crawler with JS crawling flags
- **GAU** — Multi-source URL harvester (Wayback, CommonCrawl, URLScan, OTX)
- **waybackurls** — Historical URLs from Wayback Machine
- **anew** — Append unique lines to file
- **httpx** — HTTP probing toolkit
- **source-map-explorer** — Node tool for source map analysis
- **TruffleHog** — Secret scanning (pip)
- **De4JS** — Online JS deobfuscator

## Bypass Techniques

- **Header tricks for admin access**: `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For`
- **Path traversal**: `/users/../admin/users`
- **API version downgrade**: Replace `/v2/` with `/v1/` to access older, weaker endpoints
- **Cookie scope**: Test if main domain session cookie works on internal/staging subdomains

## Notes

- Most hunters skip JS recon — doing it gives you an asymmetric advantage.
- Always filter out third-party JS (jQuery, Bootstrap, analytics) to reduce noise.
- Source maps are the nuclear option — they give you the original developer source code.
- Old JS files from Wayback Machine are the most reliable source of zombie endpoints.
- JS diff monitoring finds new endpoints before any other hunter sees them.

## References

- https://systemweakness.com/20-javascript-recon-tricks-to-find-hidden-apis-secrets-admin-routes-and-bug-bounty-targets-8a8d0eee64a5
- https://github.com/GerbenJavado/LinkFinder
- https://github.com/m4ll0k/SecretFinder
- https://github.com/Mah3Sec/JSHawk
- https://github.com/denandz/sourcemapper
- https://github.com/projectdiscovery/katana
- https://github.com/lc/gau/v2

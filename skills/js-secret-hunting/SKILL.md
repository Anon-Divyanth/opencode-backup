---
name: "js-secret-hunting"
version: "2.0"
category: "recon"
subcategory: "js-recon"
phase: "reconnaissance"
tags: ["bug-bounty", "recon", "javascript", "secrets", "credentials", "api-keys", "access-control", "account-takeover", "api", "auth", "authorization", "bypass", "cloud", "cors", "exploitation", "fuzzing", "graphql", "idor", "iis", "information-disclosure", "js-recon", "mass-assignment", "mobile", "oauth", "path-traversal", "privesc", "session", "takeover", "token", "waf-bypass"]
tools: ["nuclei", "trufflehog", "grep", "mantra", "js-beautify", "gitleaks", "arjun", "authz", "autorize", "burp", "graphqlmap", "grpcurl", "john", "kiterunner", "paramalyzer", "parameth", "repeater", "restler", "zap"]
follow_up_skills: ["api-fuzzing", "json-auth-fuzzing"]
prerequisite_skills: ["js-recon-tricks"]
description: "Bug bounty skill: js secret hunting - reconnaissance phase, recon category"
---
# JavaScript Secret Hunting

## Summary

11 methods for systematically extracting secrets (API keys, tokens, credentials, database URLs) from JavaScript files. Combines automated tools (Nuclei, Mantra, JSSecret) with manual analysis (deobfuscation, comment archaeology, source maps, dynamic browser analysis).

## Key Concepts

- **Client-Side Secrets**: JS files in SPAs contain API keys, Firebase configs, OAuth secrets, Stripe keys, AWS credentials, and database connection strings — all accessible to anyone.
- **Entropy Detection**: Statistical measurement of randomness — secrets have high entropy, human text has low entropy.
- **Configuration Objects**: Developers consistently use `config`, `init`, `setup`, `credentials` objects — prime hunting targets.
- **Comment Archaeology**: TODO/FIXME/debug comments often contain hardcoded credentials left by developers.

## Technical Details

### Method 1: Automated Mass Scanning with Nuclei

```bash
nuclei -l js_files.txt -tags exposure,javascript
```

Nuclei's exposure templates cover AWS keys, Google API keys, Firebase configs, OAuth secrets, database connection strings, and third-party credentials.

### Method 2: Specialized Analysis with Mantra

```bash
cat javascript_files.txt | mantra -d | grep "+"
```

Context-aware JS analysis with confidence scoring and entropy analysis. The `-d` flag enables detailed output; `grep "+"` filters high-confidence findings.

### Method 3: Entropy-Based Detection with JSSecret

```bash
cat javascript_files.txt | jsecret
```

Language-agnostic entropy detection — finds secrets from any service regardless of format.

### Method 4: Dynamic Browser Analysis

**Sources Tab**: `Ctrl+Shift+F` to search across all loaded JS for `key`, `secret`, `config`, `token`, `auth`.

**Network Tab**: Monitor XHR/Fetch calls — inspect `Authorization`, `X-API-Key` headers, query parameters, and WebSocket connections.

### Method 5: Code Deobfuscation with js-beautify

```bash
npm install -g js-beautify
js-beautify uglified-file.js > readable-file.js

# Batch process
for file in *.min.js; do
    js-beautify "$file" > "beautified_${file}"
done
```

Before:
```javascript
var e={apiKey:"AIzaSyDxVlWcaGdKEtm9gQc7OaNioj05RuF3a8s",authDomain:"myapp.firebaseapp.com"};
```

After:
```javascript
var config = {
    apiKey: "AIzaSyDxVlWcaGdKEtm9gQc7OaNioj05RuF3a8s",
    authDomain: "myapp.firebaseapp.com",
    databaseURL: "https://myapp.firebaseio.com",
    projectId: "myapp-12345"
};
```

### Method 6: Configuration Object Mining

```bash
grep -ri "config\|init\|setup\|credentials\|env\|settings" *.js
grep -r "const config = {\|var settings = {\|let credentials = {" *.js
grep -r "window\.config\|window\.settings" *.js
```

**Firebase Config**:
```javascript
const firebaseConfig = {
    apiKey: "AIzaSyDxVlWcaGdKEtm9gQc7OaNioj05RuF3a8s",
    authDomain: "myapp.firebaseapp.com",
    databaseURL: "https://myapp.firebaseio.com",
    projectId: "myapp-12345",
    storageBucket: "myapp-12345.appspot.com"
};
```

**OAuth Config**:
```javascript
const authConfig = {
    clientId: "1234567890.apps.googleusercontent.com",
    clientSecret: "GOCSPX-abcdefghijklmnopqrstuvwxyz",
    redirectUri: "https://myapp.com/oauth/callback"
};
```

**Third-Party Services**:
```javascript
const serviceConfig = {
    stripePublishableKey: "pk_live_abcdefghijklmnopqrstuvwxyz",
    sendgridApiKey: "SG.abcdefghijklmnopqrstuvwxyz.1234567890",
    twilioAccountSid: "AC1234567890abcdefghijklmnopqrstuvwxyz"
};
```

### Method 7: Source Map Exploitation

```bash
curl https://target.com/js/app.js.map
curl https://target.com/static/bundle.js.map
ffuf -w js_files.txt:FUZZ -u https://target.com/FUZZ.map
```

Source maps contain original variable names, comments, full code structure — often including secrets removed from production builds.

### Method 8: Comment Archaeology

```bash
grep -i "todo\|fixme\|pass\|key\|secret\|hack\|temp\|debug" *.js
grep -A 10 -B 2 "/\*.*\(config\|credential\|key\)" *.js
grep "//.*\(api\|key\|token\|secret\)" *.js
```

**TODO with credentials**:
```javascript
// TODO: Replace with production API key before deploy
const apiKey = "AIzaSyDxVlWcaGdKEtm9gQc7OaNioj05RuF3a8s";
// TODO: Remove test database connection
// const dbUrl = "mongodb://admin:password123@prod-db.company.com:27017/app";
```

**Debug comments**:
```javascript
// Debug: using admin key for testing
console.log("API Key:", "sk_live_abcdefghijklmnopqrstuvwxyz");
```

**Commented-out configs**:
```javascript
/*
Old production config - keeping for reference
const prodConfig = {
    dbPassword: "SuperSecretPassword123!",
    apiKey: "prod_api_key_abcdefghijklmnop",
    webhookSecret: "whsec_1234567890abcdefghijklmnop"
};
*/
```

### Method 9: Service-Specific Pattern Recognition

**Google**:
```bash
grep -r "AIza[0-9A-Za-z_-]{35}" *.js
grep -r "[0-9]+-[0-9a-z]{32}\.apps\.googleusercontent\.com" *.js
```

**AWS**:
```bash
grep -r "AKIA[0-9A-Z]{16}" *.js
grep -r "ASIA[0-9A-Z]{16}" *.js
grep -r "[A-Za-z0-9/+]{40}" *.js
```

**Stripe**:
```bash
grep -r "pk_live_[0-9a-zA-Z]{24}" *.js
grep -r "sk_live_[0-9a-zA-Z]{24}" *.js
```

**Firebase**: `grep -r "firebaseConfig\|firebase.*apiKey" *.js`
**Slack**: `grep -r "xoxb-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}" *.js`
**JWT**: `grep -r "eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*" *.js`

### Method 10: Sensitive Discoverer (Burp Extension)

Install via BApp Store. Automatically analyzes all HTTP responses for secrets in JS, HTML, etc. Provides confidence ratings and supports custom organization-specific patterns.

### Method 11: Verification & Impact Assessment

```bash
# Test Firebase database access
curl "https://PROJECT-ID.firebaseio.com/.json"
# Google API scope testing
curl "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=YOUR_TOKEN"
# AWS permission enumeration
aws sts get-caller-identity --aws-access-key-id YOUR_KEY
```

**Impact Documentation**: Include vulnerability description, step-by-step reproduction, PoC screenshots, business impact, and remediation recommendations.

## Methodology

### Full Secret Hunting Workflow

```bash
# 1. Broad automated scanning
nuclei -l js_files.txt -tags exposure,javascript
# 2. Specialized JavaScript analysis
cat js_files.txt | mantra -d | grep "+"
# 3. Entropy-based detection
cat js_files.txt | jsecret
# 4. Manual verification of all findings
# 5. Dynamic analysis in browser (DevTools)
# 6. Deobfuscation of interesting files (js-beautify)
```

### Verification Framework
1. **Scope verification**: Confirm the secret is within the program scope.
2. **Permission testing**: Minimal read-only test to confirm validity.
3. **Rate limit analysis**: Production keys have higher rate limits.
4. **Documentation**: Screenshots, API responses, business impact.

## Payloads

```
# Firebase config pattern
apiKey: "AIzaSy..."
authDomain: "*.firebaseapp.com"
databaseURL: "https://*.firebaseio.com"

# OAuth config
clientId: "*.apps.googleusercontent.com"
clientSecret: "GOCSPX-*"

# Stripe
sk_live_*
pk_live_*

# AWS
AKIA*
ASIA*
```

## Commands

```bash
# Nuclei exposure scan
nuclei -l js_files.txt -tags exposure,javascript

# Mantra analysis
cat javascript_files.txt | mantra -d | grep "+"

# JSSecret entropy scan
cat javascript_files.txt | jsecret

# Deobfuscation
npm install -g js-beautify
js-beautify minified.js > readable.js

# Config hunting
grep -ri "config\|init\|setup\|credentials\|env\|settings" *.js

# Comment archaeology
grep -i "todo\|fixme\|pass\|key\|secret\|hack\|temp\|debug" *.js

# Service-specific patterns
grep -r "AIza[0-9A-Za-z_-]\{35\}" *.js
grep -r "AKIA[0-9A-Z]\{16\}" *.js
grep -r "sk_live_\|pk_live_" *.js
grep -r "eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*" *.js

# Verification
curl "https://PROJECT-ID.firebaseio.com/.json"
aws sts get-caller-identity --aws-access-key-id YOUR_KEY
```

## Tools

- **Nuclei** — Automated scanning with exposure templates
- **Mantra** — JS-specific context-aware secret analysis
- **JSSecret** — Entropy-based secret detection
- **js-beautify** — JS deobfuscation and formatting
- **Sensitive Discoverer** — Burp Suite extension for automated secret detection
- **Browser DevTools** — Dynamic analysis (Sources, Network tabs)
- **grep / regex** — Targeted pattern searching
- **curl / wget / aws-cli** — API verification and testing

## Bypass Techniques

- **Minification**: Use js-beautify to restore readable structure.
- **Obfuscation**: Even obfuscated code contains string literals with secrets.
- **Missing Source Maps**: Check via ffuf enumeration (`<url>.map`), Wayback Machine for old versions.
- **Dynamic Loading**: Use browser DevTools to capture runtime-loaded JS.

## Notes

- Nuclei exposure templates are constantly updated — always run latest version.
- Mantra's context-aware analysis significantly reduces false positives compared to regex-only tools.
- Entropy detection (JSSecret) catches secrets from services you don't know to look for.
- Comment archaeology is one of the most overlooked but productive methods.
- Always verify secrets with minimal read-only tests — never write or spend.
- Firepup650's Firebase `.json` access test is a quick win for Firebase config exposure.
- Historical JS files (Wayback Machine) may contain secrets since removed from production.

## References

- https://infosecwriteups.com/javascript-secret-hunting-11-methods-bug-bounty-hunters-use-to-extract-hidden-treasures-6950df4cc42e
- https://github.com/projectdiscovery/nuclei
- https://github.com/MrEmpy/mantra
- https://github.com/d3monw0lf/JSSecret
- https://github.com/beautify-web/js-beautify
- https://portswigger.net/bappstore/ (Sensitive Discoverer)

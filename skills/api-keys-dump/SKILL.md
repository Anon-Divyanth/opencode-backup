---
name: "api-keys-dump"
version: "1.0"
category: "recon"
subcategory: "js-recon"
phase: "reconnaissance"
tags: ["bug-bounty", "recon", "javascript", "js-recon", "secrets", "api-keys", "credentials", "tokens", "hashes", "passwords", "database-connections", "devtools", "console", "trufflehog", "reghex"]
tools: ["browser", "devtools", "console", "fetch", "curl", "burp", "trufflehog", "gitleaks"]
follow_up_skills: ["js-secret-hunting", "js-recon-tricks", "information-disclosure-harvesting", "exploitation-chaining"]
prerequisite_skills: ["recon-attack-surface-mapping"]
description: "Bug bounty skill: api keys dump - reconnaissance phase, recon category. Use when you need to hunt for hardcoded API keys, secrets, tokens, credentials, password hashes, and database connection strings inside a web app's inline and external JavaScript by running the secrets_scanner console script after loading all pages in the browser."
---
# API Keys Dump (secrets_scanner)

## Summary

Browser-console secret hunter for **JS-heavy web apps**. Companion tool to `paths-dump` (paths ≠ secrets — this one finds the **keys, tokens, credentials, hashes, and connection strings** baked into JavaScript).

Same precondition as paths-dump: navigate every page/route (authenticated if possible) so all JS chunks load, then run the script in the Console. The scanner:

1. Scans all **inline scripts** in the live DOM.
2. Fetches every **same-domain external `.js` file** (from `<script src>` + the Performance API resource list) with concurrency-limited batching.
3. Runs **~150 regex patterns** sourced from **RegHex / trufflehog** definitions against every source, grouped into categories:
   - **Hashed Passwords** (`$apr1$`, `$1$`, `$6$`, `$P$`, `$H$`, `$2y$`, Drupal `$S$`, Joomla `hash:salt`, Apache `{SHA}`, …)
   - **Raw Hashes** (MD5 / SHA1 / SHA256 / SHA512 hex blobs)
   - **APIs** (A–Z: AWS, Google, Stripe, GitHub, Slack, Twilio, SendGrid, OpenAI, Discord, Telegram, private keys, JWTs, …)
   - **Database Connections** (MySQL / PostgreSQL / MongoDB / Redis / MSSQL / JDBC connection strings)
   - **Generic** (named env-var-style keys like `API_KEY`, `CLIENT_SECRET`, `JWT_SECRET`, `S3_SECRET_KEY`, …)
   - **Misc** (IPs, emails, `net user` lines)
4. Dedupes, groups by category, prints an **expandable grouped console report**, and **auto-downloads `secrets_<domain>_<timestamp>.txt`** containing the full report + raw JSON.

## Key Concepts

- **Same-domain guard**: only `.js` resources on the exact hostname or its registrable base domain are fetched — no cross-origin noise.
- **Pattern provenance**: regexes mirror trufflehog/RegHex definitions, so coverage matches industry-standard secret detection (with the added benefit of running client-side on authenticated app JS that public scanners can't see).
- **Grouped output**: results are bucketed `category → patternName → [values]`, deduped and sorted, so you can triage high-value (API keys) vs noise (IPs/emails) instantly.
- **Console-first**: results render as collapsible console groups — fastest way to eyeball hits without leaving DevTools.

## Methodology

### Step 1 — Load the whole app (precondition)

- DevTools **Network tab**, **Preserve log** on.
- **Log in / reach max auth state** — secrets in protected routes only appear in those chunks.
- Click through **every route, tab, modal, feature** so lazy-loaded bundles hit the network.
- Let background fetches settle.

### Step 2 — Run the scanner

Paste the script into the Console on the target page and run it:

```javascript
(async () => {
    /* ============================================================
     secrets_scanner.js
     Scans inline + same-domain external JS for hardcoded secrets.
     Patterns sourced from RegHex / trufflehog YAML definitions.
     Categories:
       - Hashed Passwords
       - Raw Hashes
       - Named Service API Keys (A–Z)
       - Generic / Misc Secrets
       - IPs & Emails
  ============================================================ */

    var domain = location.hostname;
    var baseDomain = domain.split('.').slice(-2).join('.');
    var results = {};
    // { category: { patternName: Set<value> } }

    // ── Same-domain guard ──────────────────────────────────────────────────────
    function isSameDomain(url) {
        try {
            var h = new URL(url).hostname;
            return h === domain || h.endsWith('.' + baseDomain);
        } catch (e) {
            return false;
        }
    }

    // ── Store match ────────────────────────────────────────────────────────────
    function storeMatch(category, name, val) {
        if (!val || val.trim().length < 4 || val.trim().length > 2000)
            return;
        val = val.trim();
        if (!results[category])
            results[category] = {};
        if (!results[category][name])
            results[category][name] = new Set();
        results[category][name].add(val);
    }

    // ── All pattern definitions ────────────────────────────────────────────────
    var PATTERNS = [
    // ── HASHED PASSWORDS ──────────────────────────────────────────────────
    {
        cat: 'Hashed Passwords',
        name: 'Apr1 MD5',
        regex: /\$apr1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}/g
    }, {
        cat: 'Hashed Passwords',
        name: 'Apache SHA',
        regex: /\{SHA\}[0-9a-zA-Z/_=]{10,}/g
    }, {
        cat: 'Hashed Passwords',
        name: 'Blowfish',
        regex: /\$2[abxyz]?\$[0-9]{2}\$[a-zA-Z0-9_/\.]*/g
    }, {
        cat: 'Hashed Passwords',
        name: 'Drupal',
        regex: /\$S\$[a-zA-Z0-9_/\.]{52}/g
    }, {
        cat: 'Hashed Passwords',
        name: 'Joomla/vBulletin',
        regex: /[0-9a-zA-Z]{32}:[a-zA-Z0-9_]{16,32}/g
    }, {
        cat: 'Hashed Passwords',
        name: 'Linux MD5',
        regex: /\$1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}/g
    }, {
        cat: 'Hashed Passwords',
        name: 'phpBB3',
        regex: /\$H\$[a-zA-Z0-9_/\.]{31}/g
    }, {
        cat: 'Hashed Passwords',
        name: 'sha512crypt',
        regex: /\$6\$[a-zA-Z0-9_/\.]{16}\$[a-zA-Z0-9_/\.]{86}/g
    }, {
        cat: 'Hashed Passwords',
        name: 'WordPress Hash',
        regex: /\$P\$[a-zA-Z0-9_/\.]{31}/g
    },
    // ── RAW HASHES ────────────────────────────────────────────────────────
    {
        cat: 'Raw Hashes',
        name: 'MD5',
        regex: /(^|[^a-zA-Z0-9])[a-fA-F0-9]{32}([^a-zA-Z0-9]|$)/g
    }, {
        cat: 'Raw Hashes',
        name: 'SHA1',
        regex: /(^|[^a-zA-Z0-9])[a-fA-F0-9]{40}([^a-zA-Z0-9]|$)/g
    }, {
        cat: 'Raw Hashes',
        name: 'SHA256',
        regex: /(^|[^a-zA-Z0-9])[a-fA-F0-9]{64}([^a-zA-Z0-9]|$)/g
    }, {
        cat: 'Raw Hashes',
        name: 'SHA512',
        regex: /(^|[^a-zA-Z0-9])[a-fA-F0-9]{128}([^a-zA-Z0-9]|$)/g
    },
    // ── APIs — A ──────────────────────────────────────────────────────────
    {
        cat: 'APIs',
        name: 'Artifactory API Token',
        regex: /AKC[a-zA-Z0-9]{10,}/g
    }, {
        cat: 'APIs',
        name: 'Artifactory Password',
        regex: /AP[0-9ABCDEF][a-zA-Z0-9]{8,}/g
    }, {
        cat: 'APIs',
        name: 'Authorization Basic',
        regex: /basic [a-zA-Z0-9_:\.=\-]+/gi
    }, {
        cat: 'APIs',
        name: 'Authorization Bearer',
        regex: /bearer [a-zA-Z0-9_\.=\-]+/gi
    }, {
        cat: 'APIs',
        name: 'Adobe Client ID',
        regex: /(adobe[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-f0-9]{32})['"]/gi
    }, {
        cat: 'APIs',
        name: 'Adobe Client Secret',
        regex: /p8e-[a-z0-9]{32}/gi
    }, {
        cat: 'APIs',
        name: 'Age Secret Key',
        regex: /AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}/g
    }, {
        cat: 'APIs',
        name: 'Alibaba Access Key ID',
        regex: /LTAI[a-z0-9]{20}/gi
    }, {
        cat: 'APIs',
        name: 'Alibaba Secret Key',
        regex: /(alibaba[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-z0-9]{30})['"]/gi
    }, {
        cat: 'APIs',
        name: 'Alchemi API Key',
        regex: /(alchemi[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-zA-Z0-9\-]{32})['"]/gi
    }, {
        cat: 'APIs',
        name: 'Asana Client ID',
        regex: /((asana[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([0-9]{16}|[a-z0-9]{32})['"]) /gi
    }, {
        cat: 'APIs',
        name: 'Atlassian API Key',
        regex: /(atlassian[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-z0-9]{24})['"]/gi
    }, {
        cat: 'APIs',
        name: 'AWS Access Key ID',
        regex: /(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g
    }, {
        cat: 'APIs',
        name: 'AWS MWS Key',
        regex: /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g
    }, {
        cat: 'APIs',
        name: 'AWS Secret Key',
        regex: /aws(.{0,20})?['"][0-9a-zA-Z\/+]{40}['"]/g
    }, {
        cat: 'APIs',
        name: 'AWS AppSync GraphQL Key',
        regex: /da2-[a-z0-9]{26}/g
    },
    // ── APIs — B ──────────────────────────────────────────────────────────
    {
        cat: 'APIs',
        name: 'Basic Auth Credentials',
        regex: /:\/\/[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+/g
    }, {
        cat: 'APIs',
        name: 'Beamer Client Secret',
        regex: /(beamer[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"](b_[a-z0-9=_\-]{44})['"]/gi
    }, {
        cat: 'APIs',
        name: 'Binance API Key',
        regex: /(binance[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-zA-Z0-9]{64})['"]/gi
    }, {
        cat: 'APIs',
        name: 'Bitbucket Client ID',
        regex: /(bitbucket[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-z0-9]{32})['"]/gi
    }, {
        cat: 'APIs',
        name: 'Bitbucket Client Secret',
        regex: /(bitbucket[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-z0-9_\-]{64})['"]/gi
    }, {
        cat: 'APIs',
        name: 'BitcoinAverage API Key',
        regex: /(bitcoin.?average[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-zA-Z0-9]{43})['"]/gi
    }, {
        cat: 'APIs',
        name: 'Bitquery API Key',
        regex: /(bitquery[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([A-Za-z0-9]{32})['"]/gi
    }, {
        cat: 'APIs',
        name: 'Bitrise API Key',
        regex: /(bitrise[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-zA-Z0-9_\-]{86})['"]/gi
    }, {
        cat: 'APIs',
        name: 'Block API Key',
        regex: /(block[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})['"]/gi
    }, {
        cat: 'APIs',
        name: 'Blockchain API Key',
        regex: /mainnet[a-zA-Z0-9]{32}|testnet[a-zA-Z0-9]{32}|ipfs[a-zA-Z0-9]{32}/g
    }, {
        cat: 'APIs',
        name: 'Blockfrost API Key',
        regex: /(blockchain[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[0-9a-f]{12})['"]/gi
    }, {
        cat: 'APIs',
        name: 'Box API Key',
        regex: /(box[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-zA-Z0-9]{32})['"]/gi
    }, {
        cat: 'APIs',
        name: 'Bravenewcoin API Key',
        regex: /(bravenewcoin[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-z0-9]{50})['"]/gi
    },
    // ── APIs — C ──────────────────────────────────────────────────────────
    {
        cat: 'APIs',
        name: 'Clearbit API Key',
        regex: /sk_[a-z0-9]{32}/g
    }, {
        cat: 'APIs',
        name: 'Clojars API Key',
        regex: /CLOJARS_[a-zA-Z0-9]{60}/g
    }, {
        cat: 'APIs',
        name: 'Cloudinary Basic Auth',
        regex: /cloudinary:\/\/[0-9]{15}:[0-9A-Za-z]+@[a-z]+/g
    }, {
        cat: 'APIs',
        name: 'Coinlayer API Key',
        regex: /(coinlayer[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-z0-9]{32})['"]/gi
    }, {
        cat: 'APIs',
        name: 'Coinlib API Key',
        regex: /(coinlib[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-z0-9]{16})['"]/gi
    }, {
        cat: 'APIs',
        name: 'Contentful API Key',
        regex: /(contentful[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-z0-9=_\-]{43})['"]/gi
    }, {
        cat: 'APIs',
        name: 'Covalent API Key',
        regex: /ckey_[a-z0-9]{27}/g
    },
    // ── APIs — D ──────────────────────────────────────────────────────────
    {
        cat: 'APIs',
        name: 'Databricks API Key',
        regex: /dapi[a-h0-9]{32}/g
    }, {
        cat: 'APIs',
        name: 'Defined Networking API Token',
        regex: /dnkey-[a-z0-9=_\-]{26}-[a-z0-9=_\-]{52}/g
    }, {
        cat: 'APIs',
        name: 'Discord API Key',
        regex: /(discord[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-h0-9]{64}|[0-9]{18}|[a-z0-9=_\-]{32})['"]/gi
    }, {
        cat: 'APIs',
        name: 'Discord Bot Token',
        regex: /[MN][A-Za-z\d]{23}\.[a-zA-Z0-9_\-]{6}\.[a-zA-Z0-9_\-]{27}/g
    }, {
        cat: 'APIs',
        name: 'Discord Webhook',
        regex: /https:\/\/discord\.com\/api\/webhooks\/[0-9]{18}\/[a-zA-Z0-9_\-]{68}/g
    }, {
        cat: 'APIs',
        name: 'Doppler API Key',
        regex: /dp\.pt\.[a-zA-Z0-9]{43}/g
    }, {
        cat: 'APIs',
        name: 'Dropbox API Key',
        regex: /sl\.[a-zA-Z0-9_\-]{136}/g
    }, {
        cat: 'APIs',
        name: 'Duffel API Key',
        regex: /duffel_(test|live)_[a-zA-Z0-9_\-]{43}/g
    }, {
        cat: 'APIs',
        name: 'Dynatrace API Key',
        regex: /dt0c01\.[a-zA-Z0-9]{24}\.[a-z0-9]{64}/g
    },
    // ── APIs — E ──────────────────────────────────────────────────────────
    {
        cat: 'APIs',
        name: 'EasyPost API Key',
        regex: /EZAK[a-zA-Z0-9]{54}/g
    }, {
        cat: 'APIs',
        name: 'EasyPost Test API Key',
        regex: /EZTK[a-zA-Z0-9]{54}/g
    }, {
        cat: 'APIs',
        name: 'Etherscan API Key',
        regex: /(etherscan[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([A-Z0-9]{34})['"]/gi
    },
    // ── APIs — F ──────────────────────────────────────────────────────────
    {
        cat: 'APIs',
        name: 'Facebook Access Token',
        regex: /EAACEdEose0cBA[0-9A-Za-z]+/g
    }, {
        cat: 'APIs',
        name: 'Facebook Client ID',
        regex: /([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['"][0-9]{13,17}/g
    }, {
        cat: 'APIs',
        name: 'Facebook Oauth',
        regex: /[fF][aA][cC][eE][bB][oO][oO][kK].*['"][0-9a-f]{32}['"]/g
    }, {
        cat: 'APIs',
        name: 'Facebook Secret Key',
        regex: /([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?['"][0-9a-f]{32}/g
    }, {
        cat: 'APIs',
        name: 'Fastly API Key',
        regex: /(fastly[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-z0-9=_\-]{32})['"]/gi
    }, {
        cat: 'APIs',
        name: 'Finicity API Key',
        regex: /(finicity[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-f0-9]{32}|[a-z0-9]{20})['"]/gi
    }, {
        cat: 'APIs',
        name: 'Flutterwave Keys',
        regex: /FLWPUBK_TEST-[a-hA-H0-9]{32}-X|FLWSECK_TEST-[a-hA-H0-9]{32}-X|FLWSECK_TEST[a-hA-H0-9]{12}/g
    }, {
        cat: 'APIs',
        name: 'Frame.io API Key',
        regex: /fio-u-[a-zA-Z0-9_=\-]{64}/g
    },
    // ── APIs — G ──────────────────────────────────────────────────────────
    {
        cat: 'APIs',
        name: 'GitHub Token (generic)',
        regex: /github(.{0,20})?['"][0-9a-zA-Z]{35,40}/g
    }, {
        cat: 'APIs',
        name: 'GitHub App Token',
        regex: /(ghu|ghs)_[0-9a-zA-Z]{36}/g
    }, {
        cat: 'APIs',
        name: 'GitHub OAuth Token',
        regex: /gho_[0-9a-zA-Z]{36}/g
    }, {
        cat: 'APIs',
        name: 'GitHub PAT',
        regex: /ghp_[0-9a-zA-Z]{36}/g
    }, {
        cat: 'APIs',
        name: 'GitHub Refresh Token',
        regex: /ghr_[0-9a-zA-Z]{76}/g
    }, {
        cat: 'APIs',
        name: 'GitHub Fine-Grained PAT',
        regex: /github_pat_[0-9a-zA-Z_]{82}/g
    }, {
        cat: 'APIs',
        name: 'GitLab PAT',
        regex: /glpat-[0-9a-zA-Z\-]{20}/g
    }, {
        cat: 'APIs',
        name: 'GitLab Pipeline Token',
        regex: /glptt-[0-9a-f]{40}/g
    }, {
        cat: 'APIs',
        name: 'GitLab Runner Token',
        regex: /GR1348941[0-9a-zA-Z_\-]{20}/g
    }, {
        cat: 'APIs',
        name: 'GoCardless API Key',
        regex: /live_[a-zA-Z0-9_=\-]{40}/g
    }, {
        cat: 'APIs',
        name: 'Google API Key',
        regex: /AIza[0-9A-Za-z_\-]{35}/g
    }, {
        cat: 'APIs',
        name: 'Google Cloud Platform Key',
        regex: /(google|gcp|youtube|drive|yt)(.{0,20})?['"](AIza[0-9a-z_\-]{35})['"]/gi
    }, {
        cat: 'APIs',
        name: 'Google Drive OAuth',
        regex: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g
    }, {
        cat: 'APIs',
        name: 'Google OAuth Token',
        regex: /ya29\.[0-9A-Za-z_\-]+/g
    }, {
        cat: 'APIs',
        name: 'Google Service Account',
        regex: /"type"[^:]*:[^"]*"service_account"/g
    }, {
        cat: 'APIs',
        name: 'Google Analytics UA',
        regex: /UA-[0-9]{4,9}-[0-9]{1,4}/g
    }, {
        cat: 'APIs',
        name: 'Google Analytics GA4',
        regex: /G-[A-Z0-9]{10}/g
    }, {
        cat: 'APIs',
        name: 'Google reCAPTCHA',
        regex: /6L[0-9A-Za-z_\-]{38}/g
    }, {
        cat: 'APIs',
        name: 'Grafana API Key',
        regex: /eyJrIjoi[a-z0-9_=\-]{72,92}/gi
    }, {
        cat: 'APIs',
        name: 'Grafana Cloud Token',
        regex: /glc_[A-Za-z0-9+/]{32,}={0,2}/g
    }, {
        cat: 'APIs',
        name: 'Grafana Service Account',
        regex: /glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}/g
    },
    // ── APIs — H ──────────────────────────────────────────────────────────
    {
        cat: 'APIs',
        name: 'Hashicorp Terraform Key',
        regex: /[a-z0-9]{14}\.atlasv1\.[a-z0-9_=\-]{60,70}/g
    }, {
        cat: 'APIs',
        name: 'Heroku API Key',
        regex: /[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/g
    }, {
        cat: 'APIs',
        name: 'HubSpot API Key',
        regex: /['"][a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12}['"]/gi
    },
    // ── APIs — I ──────────────────────────────────────────────────────────
    {
        cat: 'APIs',
        name: 'Instatus API Key',
        regex: /(instatus[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-z0-9]{32})['"]/gi
    }, {
        cat: 'APIs',
        name: 'Intercom API Key',
        regex: /(intercom[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-z0-9=_]{60}|[a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['"]/gi
    }, {
        cat: 'APIs',
        name: 'Ionic API Key',
        regex: /(ionic[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"](ion_[a-z0-9]{42})['"]/gi
    },
    // ── APIs — J ──────────────────────────────────────────────────────────
    {
        cat: 'APIs',
        name: 'Jenkins Credentials',
        regex: /<[a-zA-Z]*>\{[a-zA-Z0-9=+/]*\}</g
    }, {
        cat: 'APIs',
        name: 'JSON Web Token (JWT)',
        regex: /ey[0-9a-z]{30,34}\.ey[0-9a-z\/_\-]{30,}\.[0-9a-zA-Z\/_\-]{10,}={0,2}/gi
    }, {
        cat: 'APIs',
        name: 'Firebase URL',
        regex: /https:\/\/[a-z0-9\-]+\.firebaseio\.com/g
    },
    // ── APIs — L ──────────────────────────────────────────────────────────
    {
        cat: 'APIs',
        name: 'Linear API Key',
        regex: /lin_api_[a-zA-Z0-9]{40}/g
    }, {
        cat: 'APIs',
        name: 'Linear Client Secret',
        regex: /(linear[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-f0-9]{32})['"]/gi
    }, {
        cat: 'APIs',
        name: 'LinkedIn Client ID',
        regex: /linkedin(.{0,20})?['"][0-9a-z]{12}['"]/g
    }, {
        cat: 'APIs',
        name: 'LinkedIn Secret Key',
        regex: /linkedin(.{0,20})?['"][0-9a-z]{16}['"]/g
    }, {
        cat: 'APIs',
        name: 'Lob API Key',
        regex: /(lob[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]((live|test)_[a-f0-9]{35}|(test|live)_pub_[a-f0-9]{31})['"]/gi
    },
    // ── APIs — M ──────────────────────────────────────────────────────────
    {
        cat: 'APIs',
        name: 'Mailchimp API Key',
        regex: /[0-9a-f]{32}-us[0-9]{1,2}/g
    }, {
        cat: 'APIs',
        name: 'Mailgun API Key',
        regex: /key-[0-9a-zA-Z]{32}/g
    }, {
        cat: 'APIs',
        name: 'Mailgun Pub Validation Key',
        regex: /pubkey-[a-f0-9]{32}/g
    }, {
        cat: 'APIs',
        name: 'Mailgun Webhook Key',
        regex: /[a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8}/g
    }, {
        cat: 'APIs',
        name: 'Mandrill API Key',
        regex: /md-[A-Za-z0-9]{22}/g
    }, {
        cat: 'APIs',
        name: 'Mapbox API Key',
        regex: /pk\.[a-z0-9]{60}\.[a-z0-9]{22}/gi
    }, {
        cat: 'APIs',
        name: 'MessageBird API Key',
        regex: /(messagebird[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-z0-9]{25}|[a-h0-9]{8}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{4}-[a-h0-9]{12})['"]/gi
    }, {
        cat: 'APIs',
        name: 'Microsoft Teams Webhook',
        regex: /https:\/\/[a-z0-9]+\.webhook\.office\.com\/webhookb2\/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}\/IncomingWebhook\/[a-z0-9]{32}\/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}/g
    },
    // ── APIs — N ──────────────────────────────────────────────────────────
    {
        cat: 'APIs',
        name: 'New Relic Key',
        regex: /NRAK-[A-Z0-9]{27}|NRJS-[a-f0-9]{19}/g
    }, {
        cat: 'APIs',
        name: 'npm Access Token',
        regex: /npm_[a-zA-Z0-9]{36}/g
    },
    // ── APIs — O ──────────────────────────────────────────────────────────
    {
        cat: 'APIs',
        name: 'OpenAI API Token',
        regex: /sk-[A-Za-z0-9]{48}/g
    },
    // ── APIs — P ──────────────────────────────────────────────────────────
    {
        cat: 'APIs',
        name: 'PayPal Braintree Token',
        regex: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/g
    }, {
        cat: 'APIs',
        name: 'Picatic API Key',
        regex: /sk_live_[0-9a-z]{32}/g
    }, {
        cat: 'APIs',
        name: 'Planetscale API Key',
        regex: /pscale_tkn_[a-zA-Z0-9_\.\-]{43}/g
    }, {
        cat: 'APIs',
        name: 'Planetscale OAuth Token',
        regex: /pscale_oauth_[a-zA-Z0-9_\.\-]{32,64}/g
    }, {
        cat: 'APIs',
        name: 'Planetscale Password',
        regex: /pscale_pw_[a-zA-Z0-9_\.\-]{43}/g
    }, {
        cat: 'APIs',
        name: 'Plaid API Token',
        regex: /access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g
    }, {
        cat: 'APIs',
        name: 'Postman API Key',
        regex: /PMAK-[a-fA-F0-9]{24}-[a-fA-F0-9]{34}/g
    }, {
        cat: 'APIs',
        name: 'Prefect API Token',
        regex: /pnu_[a-z0-9]{36}/g
    }, {
        cat: 'APIs',
        name: 'Private Key (RSA)',
        regex: /-----BEGIN RSA PRIVATE KEY-----/g
    }, {
        cat: 'APIs',
        name: 'Private Key (DSA)',
        regex: /-----BEGIN DSA PRIVATE KEY-----/g
    }, {
        cat: 'APIs',
        name: 'Private Key (EC)',
        regex: /-----BEGIN EC PRIVATE KEY-----/g
    }, {
        cat: 'APIs',
        name: 'Private Key (PGP)',
        regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g
    }, {
        cat: 'APIs',
        name: 'Private Key (OpenSSH)',
        regex: /-----BEGIN OPENSSH PRIVATE KEY-----/g
    }, {
        cat: 'APIs',
        name: 'Private Key (PKCS8)',
        regex: /-----BEGIN PRIVATE KEY-----/g
    }, {
        cat: 'APIs',
        name: 'Private Key (Encrypted)',
        regex: /-----BEGIN ENCRYPTED PRIVATE KEY-----/g
    }, {
        cat: 'APIs',
        name: 'Pulumi API Key',
        regex: /pul-[a-f0-9]{40}/g
    }, {
        cat: 'APIs',
        name: 'PyPI Upload Token',
        regex: /pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}/g
    },
    // ── APIs — R ──────────────────────────────────────────────────────────
    {
        cat: 'APIs',
        name: 'Readme API Token',
        regex: /rdme_[a-z0-9]{70}/g
    }, {
        cat: 'APIs',
        name: 'Rubygem API Key',
        regex: /rubygems_[a-f0-9]{48}/g
    },
    // ── APIs — S ──────────────────────────────────────────────────────────
    {
        cat: 'APIs',
        name: 'Sendgrid API Key',
        regex: /SG\.[a-zA-Z0-9_\.\-]{66}/g
    }, {
        cat: 'APIs',
        name: 'Sendinblue API Key',
        regex: /xkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}/g
    }, {
        cat: 'APIs',
        name: 'Shippo API Key',
        regex: /shippo_(live|test)_[a-f0-9]{40}/g
    }, {
        cat: 'APIs',
        name: 'Shopify Access Token',
        regex: /shpat_[a-fA-F0-9]{32}/g
    }, {
        cat: 'APIs',
        name: 'Shopify Custom App Token',
        regex: /shpca_[a-fA-F0-9]{32}/g
    }, {
        cat: 'APIs',
        name: 'Shopify Private App Token',
        regex: /shppa_[a-fA-F0-9]{32}/g
    }, {
        cat: 'APIs',
        name: 'Shopify Shared Secret',
        regex: /shpss_[a-fA-F0-9]{32}/g
    }, {
        cat: 'APIs',
        name: 'Slack Token',
        regex: /xox[baprs]-([0-9a-zA-Z]{10,48})?/g
    }, {
        cat: 'APIs',
        name: 'Slack Webhook',
        regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{10}\/B[a-zA-Z0-9_]{10}\/[a-zA-Z0-9_]{24}/g
    }, {
        cat: 'APIs',
        name: 'Square Access Token',
        regex: /sqOatp-[0-9A-Za-z_\-]{22}/g
    }, {
        cat: 'APIs',
        name: 'Square API Key',
        regex: /EAAAE[a-zA-Z0-9_\-]{59}/g
    }, {
        cat: 'APIs',
        name: 'Square OAuth Secret',
        regex: /sq0csp-[0-9A-Za-z_\- ]{43}/g
    }, {
        cat: 'APIs',
        name: 'Stripe API Key',
        regex: /(sk|pk)_(test|live)_[0-9a-z]{10,32}|k_live_[0-9a-zA-Z]{24}/gi
    },
    // ── APIs — T ──────────────────────────────────────────────────────────
    {
        cat: 'APIs',
        name: 'Telegram Bot Token',
        regex: /[0-9]+:AA[0-9A-Za-z\-_]{33}/g
    }, {
        cat: 'APIs',
        name: 'Trello API Key',
        regex: /(trello[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([0-9a-z]{32})['"]/gi
    }, {
        cat: 'APIs',
        name: 'Twilio API Key',
        regex: /SK[0-9a-fA-F]{32}/g
    }, {
        cat: 'APIs',
        name: 'Twilio Account SID',
        regex: /\bAC[a-zA-Z0-9]{32}\b/g
    }, {
        cat: 'APIs',
        name: 'Twitch API Key',
        regex: /(twitch[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([a-z0-9]{30})['"]/gi
    }, {
        cat: 'APIs',
        name: 'Twitter Bearer Token',
        regex: /A{22}[a-zA-Z0-9%]{80,100}/g
    }, {
        cat: 'APIs',
        name: 'Twitter OAuth',
        regex: /[tT][wW][iI][tT][tT][eE][rR].{0,30}['"\\s][0-9a-zA-Z]{35,44}['"\\s]/g
    }, {
        cat: 'APIs',
        name: 'Twitter Secret Key',
        regex: /[tT][wW][iI][tT][tT][eE][rR](.{0,20})?['"][0-9a-z]{35,44}/g
    }, {
        cat: 'APIs',
        name: 'Typeform API Key',
        regex: /tfp_[a-z0-9_\.=\-]{59}/g
    },
    // ── APIs — Y / W / Z ──────────────────────────────────────────────────
    {
        cat: 'APIs',
        name: 'Yandex Access Token',
        regex: /t1\.[A-Z0-9a-z_\-]+[=]{0,2}\.[A-Z0-9a-z_\-]{86}[=]{0,2}/g
    }, {
        cat: 'APIs',
        name: 'Yandex API Key',
        regex: /AQVN[A-Za-z0-9_\-]{35,38}/g
    }, {
        cat: 'APIs',
        name: 'Web3 API Key',
        regex: /(web3[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([A-Za-z0-9_=\-]+\.[A-Za-z0-9_=\-]+\.?[A-Za-z0-9_.+/=\-]*)['"]/gi
    }, {
        cat: 'APIs',
        name: 'Zendesk Secret Key (generic)',
        regex: /([a-z0-9]{40})/g
    }, // broad — flagged
    {
        cat: 'APIs',
        name: 'Azure Storage Connection',
        regex: /DefaultEndpointsProtocol=https;AccountName=[a-zA-Z0-9]+;AccountKey=[a-zA-Z0-9+\/=]{88};/g
    }, {
        cat: 'APIs',
        name: 'DigitalOcean Token',
        regex: /dop_v1_[a-f0-9]{64}/g
    }, {
        cat: 'APIs',
        name: 'DigitalOcean OAuth',
        regex: /doo_v1_[a-f0-9]{64}/g
    }, {
        cat: 'APIs',
        name: 'Artifactory Token/Password',
        regex: /["']AKC[a-zA-Z0-9]{10,}["']|["']AP[0-9ABCDEF][a-zA-Z0-9]{8,}["']/g
    }, {
        cat: 'APIs',
        name: 'Vault Token',
        regex: /[sb]\.[a-zA-Z0-9]{24}/g
    },
    // ── DB CONNECTIONS ────────────────────────────────────────────────────
    {
        cat: 'Database Connections',
        name: 'MySQL',
        regex: /mysql:\/\/[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-!@#$%^&*()]+@[a-zA-Z0-9.\-]+(?::[0-9]+)?\/[a-zA-Z0-9_\-]+/g
    }, {
        cat: 'Database Connections',
        name: 'PostgreSQL',
        regex: /postgres(?:ql)?:\/\/[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-!@#$%^&*()]+@[a-zA-Z0-9.\-]+(?::[0-9]+)?\/[a-zA-Z0-9_\-]+/g
    }, {
        cat: 'Database Connections',
        name: 'MongoDB',
        regex: /mongodb(?:\+srv)?:\/\/[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-!@#$%^&*()]+@[a-zA-Z0-9.\-:,\/?=&]+/g
    }, {
        cat: 'Database Connections',
        name: 'Redis',
        regex: /redis:\/\/[a-zA-Z0-9_\-]*:?[a-zA-Z0-9_\-!@#$%^&*()]*@?[a-zA-Z0-9.\-]+(?::[0-9]+)?(?:\/[0-9]+)?/g
    }, {
        cat: 'Database Connections',
        name: 'MSSQL',
        regex: /(?:Server|Data Source)=[a-zA-Z0-9.\-,]+;(?:.*)?(?:Password|Pwd)=[^;]+/g
    }, {
        cat: 'Database Connections',
        name: 'JDBC/ODBC',
        regex: /(?:jdbc|odbc):(?:mysql|postgres|oracle|sqlserver|mariadb):\/\/[^\s]+/g
    },
    // ── GENERIC / MISC ────────────────────────────────────────────────────
    {
        cat: 'Generic',
        name: 'Generic API Key',
        regex: /((key|api|token|secret|password)[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([0-9a-zA-Z_=\-]{8,64})['"]/gi
    }, {
        cat: 'Generic',
        name: 'Generic Secret',
        regex: /[sS][eE][cC][rR][eE][tT].*['"][0-9a-zA-Z]{32,45}['"]/g
    }, {
        cat: 'Generic',
        name: 'PHP Defined Password',
        regex: /define ?\(['"]((\w*pass|\w*pwd|\w*user|\w*datab))/gi
    }, {
        cat: 'Generic',
        name: 'Password Assignment',
        regex: /(pwd|passwd|password|PASSWD|PASSWORD|dbuser|dbpass|pass').*[=:].+/g
    }, {
        cat: 'Generic',
        name: 'Simple Password',
        regex: /passw.*[=:].+/g
    }, {
        cat: 'Generic',
        name: 'JWT Secret',
        regex: /(?:jwt[_-]?secret)\s*[=:]\s*['"]?([a-zA-Z0-9_\-\.]{20,})['"]?/gi
    }, {
        cat: 'Generic',
        name: 'OAuth Client ID',
        regex: /(?:client[_-]?id)\s*[=:]\s*['"]?([a-zA-Z0-9_\-\.]{20,})['"]?/gi
    }, {
        cat: 'Generic',
        name: 'OAuth Client Secret',
        regex: /(?:client[_-]?secret)\s*[=:]\s*['"]?([a-zA-Z0-9_\-\.]{20,})['"]?/gi
    }, {
        cat: 'Generic',
        name: 'AES Key',
        regex: /(?:aes[_-]?key|encryption[_-]?key)\s*[=:]\s*['"]?([a-fA-F0-9]{32,})['"]?/gi
    }, {
        cat: 'Generic',
        name: 'Pusher Key/Secret',
        regex: /pusher[_\-\s]*(?:app[_\-\s]*)?(?:key|secret)\s*[:=]\s*['"]?([a-f0-9]{20})['"]?/gi
    }, {
        cat: 'Generic',
        name: 'Algolia Key',
        regex: /(?:algolia|application)_?key['":\s=]+[a-zA-Z0-9]{10,}/gi
    }, {
        cat: 'Generic',
        name: 'Datadog API Key',
        regex: /(?:dd[_-]api[_-]key|datadog[_-]api[_-]key)\s*[:=]\s*['"]?([a-f0-9]{32})['"]?/gi
    }, {
        cat: 'Generic',
        name: 'Datadog App Key',
        regex: /(?:dd[_-]app[_-]key|datadog[_-]app[_-]key)\s*[:=]\s*['"]?([a-f0-9]{40})['"]?/gi
    }, {
        cat: 'Generic',
        name: 'Generic Tokens A–C',
        regex: /(access_key|access_token|account_sid|admin_pass|admin_user|algolia_admin_key|algolia_api_key|amazon_secret_access_key|anaconda_token|api_key|api_key_secret|api_secret|apikey|app_key|app_secret|app_token|artifactory_key|aws_access_key|aws_access_key_id|aws_key|aws_secret|aws_secret_access_key|AWSSecretKey|b2_app_key|bintray_api_key|bintray_token|bluemix_api_key|cache_s3_secret_key|cattle_access_key|cattle_secret_key|chrome_client_secret|ci_deploy_password|client_secret|cloud_api_key|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|codecov_token|conekta_apikey|consumer_key|consumer_secret|contentful_access_token)[a-z0-9_ .,<\-]{0,25}(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([0-9a-zA-Z_=\-]{8,64})['"]/gi
    }, {
        cat: 'Generic',
        name: 'Generic Tokens D–H',
        regex: /(datadog_api_key|datadog_app_key|db_password|db_user|deploy_password|deploy_token|digitalocean_access_token|docker_hub_password|docker_pass|docker_password|docker_token|dropbox_oauth_bearer|elastic_cloud_auth|elasticsearch_password|encryption_key|encryption_password|env_heroku_api_key|firebase_api_token|firebase_key|firebase_token|flask_secret_key|flickr_api_key|flickr_api_secret|gcloud_service_key|gh_api_key|gh_oauth_token|gh_token|github_access_token|github_api_key|github_api_token|github_client_secret|github_oauth|github_oauth_token|github_password|github_token|google_client_secret|google_maps_api_key|google_private_key|gradle_publish_key|gradle_publish_secret|heroku_api_key|heroku_token)[a-z0-9_ .,<\-]{0,25}(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([0-9a-zA-Z_=\-]{8,64})['"]/gi
    }, {
        cat: 'Generic',
        name: 'Generic Tokens I–R',
        regex: /(integration_test_api_key|jwt_secret|kafka_admin_url|keystore_pass|lighthouse_api_key|lottie_s3_secret_key|mail_password|mailchimp_api_key|mailchimp_key|mailgun_api_key|mailgun_password|mailgun_priv_key|manage_key|manage_secret|mapbox_access_token|mapbox_api_token|mg_api_key|mysql_password|mysql_root_password|netlify_api_key|nexus_password|ngrok_auth_token|npm_api_key|npm_api_token|npm_auth_token|npm_secret_key|npm_token|oauth_token|okta_client_token|okta_oauth2_client_secret|onesignal_api_key|packagecloud_token|pagerduty_apikey|paypal_client_secret|percy_token|personal_key|personal_secret|postgresql_pass|private_signing_password|pypi_passowrd|rabbitmq_password|redis_stunnel_urls|refresh_token|release_token|rest_api_key)[a-z0-9_ .,<\-]{0,25}(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([0-9a-zA-Z_=\-]{8,64})['"]/gi
    }, {
        cat: 'Generic',
        name: 'Generic Tokens S–Z',
        regex: /(s3_access_key|s3_key|s3_secret_key|sauce_access_key|secret_key_base|secretaccesskey|sendgrid_api_key|sendgrid_key|sendgrid_password|sentry_auth_token|sentry_key|sentry_secret|service_account_secret|ses_access_key|ses_secret_key|signing_key|signing_key_secret|slack_token|snyk_api_token|snyk_token|sonar_token|sonatype_nexus_password|sonatype_password|spaces_access_key_id|spaces_secret_access_key|spotify_api_client_secret|spring_mail_password|square_reader_sdk_repository_password|stripe_private|stripe_public|surge_token|travis_access_token|travis_api_token|travis_token|twilio_api_key|twilio_api_secret|twilio_token|twitter_consumer_key|twitter_consumer_secret|unity_password|user_assets_secret_access_key|virustotal_apikey|wakatime_api_key|watson_password|wordpress_db_password|wpt_report_api_key|yt_api_key|yt_client_secret|yt_server_api_key)[a-z0-9_ .,<\-]{0,25}(=|>|:=|\|\|:|<=|=>|:).{0,5}['"]([0-9a-zA-Z_=\-]{8,64})['"]/gi
    },
    // ── MISC ──────────────────────────────────────────────────────────────
    {
        cat: 'Misc',
        name: 'IP Address',
        regex: /(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/g
    }, {
        cat: 'Misc',
        name: 'Email Address',
        regex: /[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,6}/g
    }, {
        cat: 'Misc',
        name: 'Net User Add',
        regex: /net user .+ \/add/g
    }, ];

    // ── Run all patterns on a text blob ───────────────────────────────────────
    function scanText(text) {
        for (var i = 0; i < PATTERNS.length; i++) {
            var p = PATTERNS[i];
            var r = new RegExp(p.regex.source,p.regex.flags);
            var m;
            while ((m = r.exec(text)) !== null) {
                // Prefer capture group 1 or last non-empty group, else full match
                var val = m[0];
                for (var g = m.length - 1; g >= 1; g--) {
                    if (m[g] && m[g].trim().length >= 4) {
                        val = m[g];
                        break;
                    }
                }
                storeMatch(p.cat, p.name, val);
            }
        }
    }

    // ── Concurrency-limited fetch ─────────────────────────────────────────────
    async function fetchBatch(urls, size) {
        var out = [];
        for (var i = 0; i < urls.length; i += size) {
            var batch = urls.slice(i, i + size);
            var settled = await Promise.allSettled(batch.map(function(u) {
                return fetch(u, {
                    credentials: 'omit'
                }).then(function(r) {
                    return r.text();
                }).then(function(t) {
                    return {
                        url: u,
                        text: t
                    };
                });
            }));
            settled.forEach(function(r) {
                if (r.status === 'fulfilled')
                    out.push(r.value);
                else
                    console.warn('[secrets] fetch failed:', r.reason);
            });
            if (i + size < urls.length)
                await new Promise(function(res) {
                    setTimeout(res, 150);
                }
                );
        }
        return out;
    }

    // ── Collect sources ───────────────────────────────────────────────────────
    var sources = [];

    // Inline scripts
    var inlines = document.querySelectorAll('script:not([src])');
    for (var s = 0; s < inlines.length; s++) {
        sources.push({
            label: 'inline#' + s,
            text: inlines[s].textContent
        });
    }

    // Same-domain external JS
    var allUrls = new Set();
    document.querySelectorAll('script[src]').forEach(function(el) {
        allUrls.add(el.src);
    });
    performance.getEntriesByType('resource').forEach(function(e) {
        allUrls.add(e.name);
    });

    var jsUrls = [...allUrls].filter(function(u) {
        return u && /\.js(\?|$)/.test(u) && isSameDomain(u);
    });

    console.log('[secrets] inline:', inlines.length, '| external JS:', jsUrls.length);

    var fetched = await fetchBatch(jsUrls, 8);
    fetched.forEach(function(f) {
        sources.push({
            label: f.url,
            text: f.text
        });
    });

    console.log('[secrets] scanning', sources.length, 'sources...');
    sources.forEach(function(s) {
        scanText(s.text);
    });

    // ── Build final de-duped output ───────────────────────────────────────────
    var final = {};
    Object.keys(results).forEach(function(cat) {
        Object.keys(results[cat]).forEach(function(name) {
            var vals = [...results[cat][name]];
            if (vals.length) {
                if (!final[cat])
                    final[cat] = {};
                final[cat][name] = vals.sort();
            }
        });
    });

    // ── Console output ─────────────────────────────────────────────────────────
    console.group('%c secrets_scanner — ' + domain, 'font-weight:bold;color:#D85A30;font-size:14px');
    Object.keys(final).forEach(function(cat) {
        var catColor = cat === 'APIs' ? '#D85A30' : cat === 'Hashed Passwords' ? '#C0392B' : cat === 'Database Connections' ? '#8E44AD' : cat === 'Generic' ? '#E67E22' : '#7F8C8D';
        console.groupCollapsed('%c [' + cat + ']', 'font-weight:bold;color:' + catColor);
        Object.keys(final[cat]).forEach(function(name) {
            console.groupCollapsed(name + ' (' + final[cat][name].length + ')');
            final[cat][name].forEach(function(v) {
                console.log(v);
            });
            console.groupEnd();
        });
        console.groupEnd();
    });
    console.groupEnd();

    // ── Build .txt report ──────────────────────────────────────────────────────
    var sep = '='.repeat(60) + '\n';
    var dash = '-'.repeat(40) + '\n';
    var out = sep;
    out += '  secrets_scanner — ' + domain + '\n';
    out += '  Generated  : ' + new Date().toISOString() + '\n';
    out += '  Target     : ' + location.href + '\n';
    out += '  Sources    : ' + sources.length + ' (' + inlines.length + ' inline + ' + jsUrls.length + ' external)\n';
    out += sep + '\n';

    Object.keys(final).forEach(function(cat) {
        out += '\n' + sep + '  ' + cat.toUpperCase() + '\n' + sep;
        Object.keys(final[cat]).forEach(function(name) {
            out += '\n[' + name + ']  (' + final[cat][name].length + ' found)\n' + dash;
            final[cat][name].forEach(function(v) {
                out += '  ' + v + '\n';
            });
        });
    });

    out += '\n\n' + sep + '  RAW JSON\n' + sep;
    out += JSON.stringify(final, null, 2);

    var blob = new Blob([out],{
        type: 'text/plain;charset=utf-8'
    });
    var fileUrl = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = fileUrl;
    a.download = 'secrets_' + domain + '_' + Date.now() + '.txt';
    document.body.appendChild(a);
    a.click();
    setTimeout(function() {
        document.body.removeChild(a);
        URL.revokeObjectURL(fileUrl);
    }, 1000);

    console.log('%c[+] Saved: ' + a.download, 'color:#1D9E75;font-weight:bold');
    return final;
}
)();
```

### Step 3 — Triage the results

- Console shows collapsible groups per category; **APIs** (orange) is the high-value bucket.
- The `.txt` report contains everything + raw JSON at the bottom.
- **Prioritize**: live-looking service keys (AWS `AKIA…`, Google `AIza…`, Stripe `sk_live…`, GitHub `ghp_…`, SendGrid `SG.…`, Twilio, Slack `xox…`), private key blocks, DB connection strings.
- **De-prioritize**: IPs, emails, `UA-…`/`G-…` analytics IDs, reCAPTCHA site keys, Firebase URLs, JWTs (may be ephemeral/legit client tokens).

### Step 4 — Verify (minimal, read-only, scope-compliant)

```bash
# AWS: does the key resolve? (sts get-caller-identity is read-only)
aws sts get-caller-identity --aws-access-key-id AKIA... --aws-secret-access-key ... 

# Google API key: probe a benign endpoint
curl -s "https://maps.googleapis.com/maps/api/geocode/json?address=test&key=AIza..."

# Stripe: check key validity (read-only /v1/balance)
curl -s https://api.stripe.com/v1/balance -u sk_live_...:

# SendGrid: verify sender identity (read-only)
curl -s -X GET "https://api.sendgrid.com/v3/verified_senders" -H "Authorization: Bearer SG...."

# GitHub PAT: read-only GET on the user endpoint
curl -s -H "Authorization: token ghp_..." https://api.github.com/user

# Discord webhook: confirm it exists WITHOUT posting
curl -s -I https://discord.com/api/webhooks/... 
```

**Never** spend money, send messages, mutate data, or run anything destructive to validate. If a key turns out valid, report it — don't weaponize it.

## Commands

```bash
# Save the harvested secrets report for later analysis (the script downloads it,
# but keep a copy outside the browser if needed)
# For non-browser validation of the SAME patterns offline:
cat target.js | trufflehog filesystem .
gitleaks detect --source . --no-git
```

## Tools

- **Browser DevTools Console + Network** — the runtime for the scanner.
- **Performance API** — resource list source for external JS discovery.
- **curl / aws-cli** — read-only verification of candidate secrets.
- **trufflehog / gitleaks** — offline equivalents of the same RegHex-derived patterns for files you've already downloaded.

## Edge Cases / Notes

- **Auth-gated secrets**: run logged-in, at max privilege, after clicking through every route — protected chunks are where the good stuff lives.
- **`credentials: 'omit'`**: fetched JS won't send cookies, but JS files are almost always unauthenticated static assets — fine.
- **CORS**: only same-domain JS is fetched; cross-origin CDN scripts (e.g., analytics) are skipped to avoid failures. If a key app chunk lives on a CDN subdomain, add it manually via `fetch()` if needed — be mindful of scope.
- **False positives**: the `Zendesk Secret Key (generic)` and `Raw Hashes` patterns are intentionally broad — expect noise; the report groups them so you can skip them fast.
- **Rate limits**: batches of 8 with 150ms delays; stay inside program rate-limit rules. Only run against in-scope targets.
- **Diff with paths-dump**: `paths-dump` = route/endpoint wordlist. `api-keys-dump` = secrets/credentials. Run both, combine for full attack surface.
- **Source maps**: if `.map` files are served, pull them and re-run — original sources often contain secrets stripped from minified builds (see `js-secret-hunting`).

## Agent / MCP Execution Notes

When an agent (e.g., the hunter agent) runs this scanner through the chrome-devtools MCP `evaluate_script`, apply these adaptations — the raw console script alone will time out or produce no usable output:

1. **Wrap the script** so it can be evaluated and its result returned:
   ```javascript
   async () => await ((async () => { /* scanner body, minus the Blob/a.click download */ return final; })())
   ```
2. **Return values, not downloads.** `evaluate_script` can't see the `a.click()` Blob download. Remove/replace the download block and `return` the `final` result object (grouped `category → patternName → [values]`) — the MCP returns it as JSON.
3. **MCP ~10s timeout — use the FAST PATH on heavy pages.** The full fetch-scan loop over every same-domain `.js` file exceeds the MCP's default ~10s `evaluate_script` timeout on SPA pages with hundreds of scripts. Fast path (completes in ~1s): scan ONLY inline scripts + `performance.getEntriesByType('resource')`/DOM `<script src>` URLs for secret-looking strings via the same `PATTERNS` regexes, WITHOUT the fetch loop. Use the full fetch-based scan only on lightweight pages with few JS resources.
4. **Per-page execution.** `performance.getEntriesByType('resource')` resets on every navigation, so run the scanner on EACH page/route you visit (authenticated) and merge results across pages — secrets in protected chunks only appear when you click through those routes.
5. **Save outputs to disk** yourself: write the returned JSON to a file (e.g., `/tmp/opencode/<page>_secrets.txt`), then triage: prioritize live-looking service keys (AWS `AKIA…`, Google `AIza…`, Stripe `sk_live…`, GitHub `ghp_…`, SendGrid `SG.…`, Twilio, Slack `xox…`), private key blocks, and DB connection strings. Verify read-only if in scope.

## References

- trufflehog (pattern provenance): https://github.com/trufflesecurity/trufflehog
- RegHex (regex corpus): https://github.com/RegHex/RegexHub
- gitleaks: https://github.com/gitleaks/gitleaks
- Companion skill: `js-secret-hunting`, `paths-dump`
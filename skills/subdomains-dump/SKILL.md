---
name: "subdomains-dump"
version: "1.0"
category: "recon"
subcategory: "js-recon"
phase: "reconnaissance"
tags: ["bug-bounty", "recon", "javascript", "js-recon", "subdomains", "domains", "hostnames", "devtools", "console", "attack-surface", "enumeration", "wildcards", "source-maps"]
tools: ["browser", "devtools", "console", "fetch", "dnsx", "httpx", "subfinder", "burp"]
follow_up_skills: ["subdomain-enumeration-checklist", "recon-attack-surface-mapping", "paths-dump", "api-keys-dump", "subdomain-takeover"]
prerequisite_skills: ["recon-attack-surface-mapping"]
description: "Bug bounty skill: subdomains dump - reconnaissance phase, recon category. Use when you need to harvest subdomains and hostnames of the target from every file the browser has loaded (Network tab resources, inline scripts, external JS/HTML/JSON/XML/CSS/MAP/TXT content, source maps, sitemap/robots) by running the subdomain_dump console script after loading all pages."
---
# Subdomains Dump (subdomain_dump)

## Summary

Browser-console subdomain harvester. Third tool in the loaded-files trio:

| Skill | Finds |
|---|---|
| `paths-dump` | paths / endpoints |
| `api-keys-dump` | API keys / secrets |
| **`subdomains-dump`** | **subdomains / hostnames** |

Same precondition as the others: navigate every page/route (authenticated if possible) so all chunks load, then run the script in the Console. It harvests subdomains from:

1. **Live network traffic** — the current page host + every resource URL in the Network tab (via the Performance API) + server-timing names. These are **observed-live**.
2. **Inline scripts + DOM attributes** (`href`, `src`, `action`, `data-*`).
3. **Same-domain external text resources** (`.js|html|htm|json|xml|css|map|txt`) — fetched and regex-scanned.
4. **Source maps** — `sources[]` arrays parsed from `.map` JSON, plus `webpack://host/...` prefixes.
5. **Well-known files** — `robots.txt`, `sitemap.xml`, `sitemap_index.xml`, `.well-known/security.txt`, `humans.txt`.

Extraction passes: URL hosts (`http/https/ws/wss` + protocol-relative `//`), bare hostnames (root-suffix guarded with lookarounds to avoid `example.com.evil.com` false positives), email domains, **obfuscated forms** (`sub[.]example[.]com`, `sub(.)example(.)com`, `sub\.example\.com`, `sub{.}example{.}com`), **wildcards** (`*.sub.example.com`, `%sub%.example.com`, `sub.*.example.com`), cookie `Domain=` refs, and source-map prefixes.

Output: console summary + auto-downloaded **`subdomains_<root>_<timestamp>.txt`** with `OBSERVED LIVE` and `ALL CANDIDATES` sections.

## Key Concepts

- **Root-domain guard**: everything is filtered against the target's registrable root (eTLD+1 heuristic with a multi-part-TLD list — `co.uk`, `com.au`, etc. — plus manual override). Cross-origin noise (analytics CDNs, S3 buckets) is dropped.
- **Live vs referenced**: hosts actually seen in network traffic are separated from hostnames only found inside file strings. Live = confirmed to exist; referenced = fuzz candidates.
- **False-positive control**: lookbehind/lookahead boundaries stop suffix-spoofing matches (`foo.example.com.evil.com` does NOT yield `example.com`); IPs and hash-like labels are rejected.
- **Wildcard decoding**: `*.api.example.com` → `api.example.com`; `%env%.internal.example.com` → `env.internal.example.com` **and** `internal.example.com`; `sub.*.example.com` → `sub.example.com`.

## Methodology

### Step 1 — Load the whole app (precondition)

- DevTools **Network tab**, **Preserve log** on, page at max auth state.
- Navigate every route/tab/feature so lazy-loaded chunks and API calls all hit the network.
- Let background fetches settle.

### Step 2 — Run the harvester

Paste the script into the Console on the target page and run it:

```javascript
(async () => {
    /* ============================================================
     subdomain_dump.js
     Grabs subdomains from every file the application has loaded.
     Sources:
       - current page host + every resource in the Network tab (Performance API)
       - inline scripts + DOM attribute references
       - same-domain external JS/HTML/JSON/XML/CSS/MAP/TXT content
       - source-map `sources` arrays
       - well-known files (robots.txt, sitemap.xml, security.txt)
     Extraction passes:
       - URL hosts (http/https/ws/wss + protocol-relative)
       - bare hostnames (root-suffix guarded)
       - email domains
       - obfuscated forms: sub[.]example[.]com / sub(.)example(.)com / sub\.example\.com
       - wildcard refs: *.sub.example.com / %sub%.example.com / sub.*.example.com
       - cookie domains: Domain=.sub.example.com
       - source-map prefixes: webpack://sub.example.com/...
     Output: console summary + auto-downloaded subdomains_<root>_<ts>.txt
     (observed-live subdomains are separated from string-referenced candidates)
  ============================================================ */

    var domain = location.hostname;

    // ── Root-domain detection (override below if the guess is wrong) ─────────
    var ROOT = (function () {
        var parts = domain.split('.');
        var multi = ['co.uk','com.au','org.uk','co.in','com.br','co.jp','co.nz','com.sg','com.hk','com.mx','com.tr','co.za','net.au','org.au','com.cn','co.id'];
        if (parts.length > 2 && multi.indexOf(parts.slice(-2).join('.')) !== -1) {
            return parts.slice(-3).join('.');
        }
        return parts.slice(-2).join('.');
    })();
    // Manual override if needed:
    // var ROOT = 'example.com';

    var PROBE = false; // OPT-IN: HEAD-check each candidate for HTTPS liveness (generates traffic!)

    if (!ROOT || ROOT.indexOf('.') === -1) {
        console.warn('[subs] odd hostname, root-domain guess is:', ROOT);
    }

    var rootEsc = ROOT.replace(/\./g, '\\.');
    var subs = new Set();  // every candidate under ROOT
    var live = new Set();  // subdomains observed in actual network traffic

    function isSubOf(host) {
        host = String(host).toLowerCase().replace(/\.$/, '');
        return host === ROOT || host.slice(-(ROOT.length + 1)) === '.' + ROOT;
    }

    function cleanHost(val) {
        if (!val || typeof val !== 'string') return null;
        var h = val.trim().toLowerCase();
        if (/^[a-z][a-z0-9+.-]*:\/\//i.test(h)) {
            try { h = new URL(h).hostname; } catch (e) { return null; }
        }
        h = h.replace(/^\/\//, '').split('/')[0].split(':')[0].split('?')[0].replace(/\.$/, '');
        h = h.replace(/\[\.\]|\(\.\)|\{\.\}|\\\./g, '.');  // deobfuscate
        if (h.length < 4 || h.length > 253) return null;
        if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(h)) return null;
        if (h.indexOf('.') === -1 || !/[a-z]/.test(h)) return null;  // no IPs
        return isSubOf(h) ? h : null;
    }

    function addSub(val) {
        var h = cleanHost(val);
        if (h) subs.add(h);
    }

    function addLive(val) {
        var h = cleanHost(val);
        if (h) { subs.add(h); live.add(h); }
    }

    // ── Regex passes ─────────────────────────────────────────────────────────
    function scanText(text) {
        if (!text || typeof text !== 'string') return;
        var m;

        // 1) URL hosts
        var urlRx = new RegExp('(?:https?://|wss?://|//)([a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)*' + rootEsc + ')(?![\\w.])', 'gi');
        while ((m = urlRx.exec(text)) !== null) if (m[1]) addSub(m[1]);

        // 2) Bare hostnames
        var bareRx = new RegExp('(?<![a-z0-9.-])([a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)*' + rootEsc + ')(?![\\w.])', 'gi');
        while ((m = bareRx.exec(text)) !== null) if (m[1]) addSub(m[1]);

        // 3) Emails
        var emailRx = new RegExp('[a-z0-9._%+-]+@([a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)*' + rootEsc + ')(?![\\w.])', 'gi');
        while ((m = emailRx.exec(text)) !== null) if (m[1]) addSub(m[1]);

        // 4) Obfuscated hosts: sub[.]example[.]com etc.
        var obsRx = /[a-z0-9][a-z0-9-]*(?:\[\.\]|\(\.\)|\\\.)[a-z0-9][a-z0-9-]*(?:(?:\[\.\]|\(\.\)|\\\.)[a-z0-9][a-z0-9-]*)*/gi;
        while ((m = obsRx.exec(text)) !== null) addSub(m[0]);

        // 5) Wildcards
        var starRx = new RegExp('\\*\\.([a-z0-9][a-z0-9-]*\\.(?:[a-z0-9][a-z0-9-]*\\.)*' + rootEsc + ')', 'gi');
        while ((m = starRx.exec(text)) !== null) if (m[1]) addSub(m[1]);
        var pctRx = new RegExp('%([a-z0-9_-]+)%\\.([a-z0-9][a-z0-9-]*\\.(?:[a-z0-9][a-z0-9-]*\\.)*' + rootEsc + ')', 'gi');
        while ((m = pctRx.exec(text)) !== null) if (m[2]) { addSub(m[2]); addSub(m[1] + '.' + m[2]); }
        var midRx = new RegExp('([a-z0-9][a-z0-9-]*)\\.\\*\\.(?:[a-z0-9][a-z0-9-]*\\.)*' + rootEsc, 'gi');
        while ((m = midRx.exec(text)) !== null) if (m[1]) addSub(m[1] + '.' + ROOT);

        // 6) Cookie / CORS domains
        var domRx = new RegExp('(?:Domain|domain)\\s*=\\s*\\.?([a-z0-9][a-z0-9-]*\\.(?:[a-z0-9][a-z0-9-]*\\.)*' + rootEsc + ')', 'gi');
        while ((m = domRx.exec(text)) !== null) if (m[1]) addSub(m[1]);

        // 7) Source-map prefixes
        var smRx = new RegExp('(?:webpack://|https?://)([a-z0-9][a-z0-9-]*\\.(?:[a-z0-9][a-z0-9-]*\\.)*' + rootEsc + ')', 'gi');
        while ((m = smRx.exec(text)) !== null) if (m[1]) addSub(m[1]);
    }

    function tryJsonMap(text) {
        if (!text || text.charAt(0) !== '{') return;
        try {
            var j = JSON.parse(text);
            if (j && Object.prototype.toString.call(j.sources) === '[object Array]') {
                j.sources.forEach(function (src) { if (typeof src === 'string') addSub(src); });
            }
        } catch (e) {}
    }

    function isSameDomain(url) {
        try {
            var h = new URL(url).hostname;
            return h === domain || h.slice(-(ROOT.length + 1)) === '.' + ROOT;
        } catch (e) { return false; }
    }

    // ── Live hosts from the Network tab / DOM ────────────────────────────────
    addLive(location.hostname);
    performance.getEntriesByType('resource').forEach(function (e) {
        addLive(e.name);
        try {
            if (e.serverTiming) e.serverTiming.forEach(function (st) { addSub(st.name); });
        } catch (err) {}
    });
    document.querySelectorAll('*').forEach(function (el) {
        ['href','src','action','data-url','data-src','data-href','data-host','data-api','data-domain'].forEach(function (attr) {
            var v = el.getAttribute(attr);
            if (v) addSub(v);
        });
    });

    // inline scripts + current page markup
    document.querySelectorAll('script:not([src])').forEach(function (s) { scanText(s.textContent); });
    scanText(document.documentElement.outerHTML);

    // ── Fetchable same-domain text resources ─────────────────────────────────
    var toFetch = new Set();
    document.querySelectorAll('script[src]').forEach(function (s) { if (s.src) toFetch.add(s.src); });
    document.querySelectorAll('link[href]').forEach(function (l) { if (l.href) toFetch.add(l.href); });
    performance.getEntriesByType('resource').forEach(function (e) { toFetch.add(e.name); });

    var fetchable = [...toFetch].filter(function (u) {
        return /\.(js|html|htm|json|xml|css|map|txt)(\?|$)/i.test(u) && isSameDomain(u);
    });

    console.log('[subs] live hosts:', live.size, '| fetchable resources:', fetchable.length);

    for (var i = 0; i < fetchable.length; i += 8) {
        var batch = fetchable.slice(i, i + 8);
        await Promise.allSettled(batch.map(function (url) {
            return fetch(url, { credentials: 'omit' })
                .then(function (r) {
                    var ct = r.headers.get('content-type') || '';
                    if (/image|font|audio|video|octet-stream|woff|ttf|eot/.test(ct)) return null;
                    return r.ok ? r.text() : null;
                })
                .then(function (t) { if (t) { scanText(t); tryJsonMap(t); } })
                .catch(function () {});
        }));
        if (i + 8 < fetchable.length) await new Promise(function (r) { setTimeout(r, 120); });
    }

    // ── Well-known probes ────────────────────────────────────────────────────
    var wellKnown = ['/robots.txt', '/sitemap.xml', '/sitemap_index.xml', '/.well-known/security.txt', '/humans.txt'];
    await Promise.allSettled(wellKnown.map(function (p) {
        return fetch(location.origin + p, { credentials: 'omit' })
            .then(function (r) { return r.ok ? r.text() : null; })
            .then(function (t) { if (t) scanText(t); })
            .catch(function () {});
    }));

    // ── Optional liveness probe (opt-in) ─────────────────────────────────────
    var all = [...subs].sort();
    if (PROBE) {
        var probeOut = {};
        for (var p = 0; p < all.length; p += 6) {
            var chunk = all.slice(p, p + 6);
            await Promise.allSettled(chunk.map(function (sub) {
                return fetch('https://' + sub + '/', { method: 'HEAD', mode: 'no-cors', cache: 'no-store' })
                    .then(function () { probeOut[sub] = 'reachable'; })
                    .catch(function () { probeOut[sub] = 'unreachable'; });
            }));
            if (p + 6 < all.length) await new Promise(function (r) { setTimeout(r, 200); });
        }
        console.log('[subs] probe results:', probeOut);
    }

    var liveList = [...live].sort();

    // ── Report + download ────────────────────────────────────────────────────
    var sep = '='.repeat(60) + '\n';
    var out = sep;
    out += '  subdomain_dump — ' + ROOT + '\n';
    out += '  Generated : ' + new Date().toISOString() + '\n';
    out += '  Target    : ' + location.href + '\n';
    out += '  Total     : ' + all.length + ' candidates (' + liveList.length + ' observed live)\n';
    out += sep + '\n\n';
    out += '## OBSERVED LIVE (' + liveList.length + ')\n';
    out += liveList.join('\n') + '\n\n';
    out += '## ALL CANDIDATES (' + all.length + ')\n';
    out += all.join('\n') + '\n';

    var blob = new Blob([out], { type: 'text/plain;charset=utf-8' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'subdomains_' + ROOT + '_' + Date.now() + '.txt';
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { document.body.removeChild(a); URL.revokeObjectURL(a.href); }, 1000);

    console.log('[subs] total candidates:', all.length, '| observed live:', liveList.length);
    console.log('[subs] saved:', a.download);
    return { root: ROOT, live: liveList, candidates: all };
})();
```

### Step 3 — Triage the harvest

- **`OBSERVED LIVE`** section = hosts the app actually talked to — highest confidence, prioritize these.
- **`ALL CANDIDATES`** = everything referenced in code (API, staging, internal, admin hosts hidden in bundles). Great fuzz seeds.
- Wildcard refs (`*.api...`, `%env%...`) already produce concrete guesses; expand `env.`/`staging.`/`dev.` style prefixes yourself with `altdns`/`dnsgen` style mutation if desired.

### Step 4 — Validate with DNS + HTTP

```bash
# Resolve & filter live hosts
cat subdomains_example.com_*.txt | sort -u | dnsx -silent -a -resp-only > resolved.txt

# Probe for HTTP services (status + title)
cat resolved.txt | httpx -silent -mc 200,301,302,401,403 -title -tech-detect

# Cross-check against passive sources
subfinder -d example.com -silent | sort -u | comm -23 - <(sort resolved.txt)
```

## Commands

```bash
# Dedupe + resolve
sort -u subdomains_*.txt | dnsx -silent -a

# Liveness probe over https
cat resolved.txt | httpx -silent -mc 200,401,403 -title

# Mutation of discovered prefixes (optional)
cat resolved.txt | dnsgen - | dnsx -silent -a
```

## Tools

- **Browser DevTools Console + Network** — runtime for the harvester.
- **Performance API + server-timing** — source of observed-live hostnames.
- **dnsx** — DNS resolution of harvested candidates.
- **httpx** — HTTP liveness/title/tech fingerprinting.
- **subfinder** — passive cross-check to spot harvest-only hosts.
- **dnsgen / altdns** — optional prefix mutation from wildcard-style refs.

## Edge Cases / Notes

- **Auth-gated hosts**: run logged-in at max privilege — internal/API hosts referenced by protected chunks only appear then.
- **Cross-origin exclusion**: resources on other roots (analytics, CDNs, S3) are intentionally ignored — they're not target subdomains.
- **`credentials: 'omit'`**: fetched static assets don't need cookies; protected API responses aren't readable but their hostnames still come from the Network tab.
- **Apex exclusion**: the bare root (e.g., `example.com`) is never emitted — it's implied and always in scope. `www`/`app`/etc. are harvested normally.
- **False-positive shaping**: lookarounds prevent suffix-spoof matches (`foo.example.com.evil.com`); IP addresses and hex-hash labels are dropped.
- **Opt-in `PROBE`**: set `PROBE = true` to HEAD-check every candidate (generates traffic — respect scope + rate limits).
- **ROOT override**: for unusual TLDs or multi-part ccSLDs not in the built-in list, uncomment `var ROOT = '...'` at the top.
- **Combine tools**: run `paths-dump` + `api-keys-dump` + `subdomains-dump` on the same loaded pages for the full attack surface; follow with `subdomain-takeover` checks on dead/unclaimed candidates.

## Agent / MCP Execution Notes

When an agent (e.g., the hunter agent) runs this harvester through the chrome-devtools MCP `evaluate_script`, apply these adaptations — the raw console script alone will time out or produce no usable output:

1. **Wrap the script** so it can be evaluated and its result returned:
   ```javascript
   async () => await ((async () => { /* harvester body, minus the Blob/a.click download */ return { root: ROOT, live: liveList, candidates: all }; })())
   ```
2. **Return values, not downloads.** `evaluate_script` can't see the `a.click()` Blob download. Remove/replace the download block and `return` the result object (`{ root, live, candidates }`) — the MCP returns it as JSON.
3. **MCP ~10s timeout — use the FAST PATH on heavy pages.** The full fetch-scan loop over every same-domain resource exceeds the MCP's default ~10s `evaluate_script` timeout on SPA pages with hundreds of resources. Fast path (completes in ~1s): extract hostnames from the live DOM + `performance.getEntriesByType('resource')` + inline scripts + `document.documentElement.outerHTML` only, WITHOUT the fetch crawl. Use the full harvest on lightweight pages.
4. **Per-page execution.** `performance.getEntriesByType('resource')` resets on every navigation, so run the harvester on EACH page/route you visit (authenticated) and merge `live`/`candidates` across pages.
5. **Save outputs to disk** yourself: write the returned JSON to a file (e.g., `/tmp/opencode/<page>_subs.txt`), then validate with `dnsx -silent -a` and `httpx -title -tech-detect`, and cross-check with `subfinder`. `OBSERVED LIVE` hosts are highest confidence.

## References

- Companion skills: `paths-dump`, `api-keys-dump`, `subdomain-enumeration-checklist`
- ProjectDiscovery dnsx: https://github.com/projectdiscovery/dnsx
- ProjectDiscovery httpx: https://github.com/projectdiscovery/httpx
- subfinder: https://github.com/projectdiscovery/subfinder

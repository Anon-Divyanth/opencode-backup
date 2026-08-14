---
name: "paths-dump"
version: "1.0"
category: "recon"
subcategory: "js-recon"
phase: "reconnaissance"
tags: ["bug-bounty", "recon", "javascript", "js-recon", "paths", "endpoints", "content-discovery", "network-tab", "devtools", "linkfinder", "attack-surface", "api", "spa"]
tools: ["browser", "devtools", "console", "fetch", "ffuf", "httpx", "burp"]
follow_up_skills: ["api-fuzzing", "ffuf-web-fuzzing", "js-secret-hunting", "js-recon-tricks", "recon-attack-surface-mapping"]
prerequisite_skills: ["recon-attack-surface-mapping"]
description: "Bug bounty skill: paths dump - reconnaissance phase, recon category. Use when you need to enumerate all application paths/endpoints by running the paths-dump JavaScript in the browser console after loading every page so all JS/chunk/asset files are cached, then crawl all downloaded resources for paths."
---
# Paths Dump

## Summary

Browser-console recon technique for **attack surface mapping of SPAs and JS-heavy apps**. The prerequisite: walk every page/route of the target application so the browser's Network tab has loaded **all** JS chunks, bundles, CSS, JSON, and other assets into cache. You then run a single console script that:

1. Scans the live DOM (href/src/action/data-* attributes, inline scripts).
2. Reads the Performance API resource list (everything the page actually fetched).
3. **Fetches every same-domain `.js|html|htm|json|xml|css|map|txt` resource it can find** and regex-crawls each file's contents for quoted paths (linkfinder-style) and URL-like strings.
4. Probes well-known files (`robots.txt`, `sitemap.xml`, `.well-known/security.txt`, `manifest.json`, `sw.js`, etc.).
5. Aggressively **validates, dedupes, sorts**, and **auto-downloads** a clean list of paths as `paths_<domain>_<timestamp>.txt`.

The output is a ready-made wordlist for `ffuf`/`kiterunner`/content-discovery, and a map of hidden API/route endpoints hidden inside bundle strings.

## Key Concepts

- **SPA chunk caching**: A single page load only fetches the chunks for that route. To see the whole app, you must navigate every route first (login, settings, admin, dashboards) — ideally authenticated — so all lazy-loaded bundles hit the Network tab / HTTP cache.
- **Linkfinder-style regex**: quoted string literals in JS (`"/api/users"`, `'/admin'`) reveal routes that never appear in the DOM.
- **Path hygiene**: the script rejects hashes, base64 blobs, pure-number segments, paths with spaces/control chars, and over-long segments — so the output is fuzz-ready, not junk.
- **Same-origin scoping**: only resources on the exact hostname or its registrable base domain are fetched, avoiding cross-origin noise and CORS failures.

## Methodology

### Step 1 — Load the whole app (precondition)

- Open DevTools (**Network tab**), tick **Preserve log**, and disable cache only if you want cold fetches.
- Log in / reach the maximum-authorized state (paths behind auth are the valuable ones).
- Navigate **every route, tab, modal, and feature** you can reach. Click through pagination, open dashboards, trigger file uploads, hit settings — anything that lazy-loads a chunk.
- Let the page idle so background fetches settle. Confirm the Network tab shows the app's JS/CSS/JSON assets.

### Step 2 — Run the dump script

Paste the script below into the Console (on the target page) and run it:

```javascript
(async () => {
  const paths = new Set();
  const domain = location.hostname;
  const baseDomain = domain.split('.').slice(-2).join('.');

  // ── Strict path validator ─────────────────────────────────────────────────
  const isValidPath = (p) => {
    if (!p || p.length < 2 || p.length > 200) return false;
    if (!p.startsWith('/')) return false;
    if (p === '/') return false;
    // Only ASCII printable, no spaces
    if (/[^\x20-\x7E]/.test(p)) return false;
    // No spaces at all
    if (/\s/.test(p)) return false;
    // Must contain only URL-safe characters
    if (!/^\/[a-zA-Z0-9_\-\/\.\~]+$/.test(p)) return false;
    // No segment longer than 80 chars (catches base64/hashes)
    if (p.split('/').some(seg => seg.length > 80)) return false;
    // Must have at least one letter (filters out pure number/symbol paths)
    if (!/[a-zA-Z]/.test(p)) return false;
    // Filter obvious junk: random-looking strings (high entropy segments)
    const segments = p.split('/').filter(Boolean);
    for (const seg of segments) {
      if (seg.length > 40) return false;
      // If segment is >20 chars and has no vowels or no pattern, likely a hash
      if (seg.length > 20) {
        const hasVowel = /[aeiouAEIOU]/.test(seg);
        const looksRandom = /^[a-f0-9]{20,}$/i.test(seg); // hex hash
        const isBase64Like = /^[A-Za-z0-9+\/]{20,}={0,2}$/.test(seg);
        if (!hasVowel || looksRandom || isBase64Like) return false;
      }
    }
    return true;
  };

  const addPath = (val) => {
    if (!val || typeof val !== 'string') return;
    try {
      if (/^https?:\/\//i.test(val)) {
        const u = new URL(val);
        const p = u.pathname;
        if (isValidPath(p)) paths.add(p);
        return;
      }
      const cleaned = val.replace(/^(\.\.\/|\.\/)+/, '/').split(/[?#]/)[0].trimEnd();
      if (isValidPath(cleaned)) paths.add(cleaned);
    } catch (e) {}
  };

  // ── Linkfinder regex (catches quoted paths in JS) ─────────────────────────
  const linkfinderRx = new RegExp(
    '(?:"|\')'
    + '('
    + '(?:[a-zA-Z]{1,10}://|//)[^"\'/ ]{1,}\\.[a-zA-Z]{2,}[^"\']+'
    + '|(?:/|\\.\\./|\\./)[^"\'><,;| *()(%%$^\\\\]+'
    + '|[a-zA-Z0-9_\\-/]+/[a-zA-Z0-9_\\-/]+\\.(?:[a-zA-Z]{1,4}|action)(?:[?#][^"\']*)?'
    + ')'
    + '(?:"|\')',
    'g'
  );

  // ── Broad URL regex ───────────────────────────────────────────────────────
  const broadRx = /(?:https?:\/\/[^\s"'`<>]+|\/[a-zA-Z0-9_\-\/\.]+)/g;

  const extractFromText = (text) => {
    if (!text || typeof text !== 'string') return;

    // Linkfinder pass
    let m;
    const lf = new RegExp(linkfinderRx.source, linkfinderRx.flags);
    while ((m = lf.exec(text)) !== null) addPath(m[1]);

    // Broad pass
    const broad = text.match(broadRx);
    if (broad) broad.forEach(v => addPath(v));
  };

  // ── DOM attributes ────────────────────────────────────────────────────────
  document.querySelectorAll('*').forEach(el => {
    ['href', 'src', 'action', 'data-url', 'data-src', 'data-href', 'data-path', 'data-api'].forEach(attr => {
      const val = el[attr] || el.getAttribute(attr);
      if (val) addPath(val);
    });
  });

  // ── Inline scripts ────────────────────────────────────────────────────────
  document.querySelectorAll('script:not([src])').forEach(s => extractFromText(s.textContent));

  // ── Collect fetchable same-domain resources ───────────────────────────────
  const toFetch = new Set();
  document.querySelectorAll('script[src]').forEach(s => s.src && toFetch.add(s.src));
  document.querySelectorAll('link[href]').forEach(l => l.href && toFetch.add(l.href));
  performance.getEntriesByType('resource').forEach(e => {
    addPath(e.name);
    toFetch.add(e.name);
  });

  const fetchable = [...toFetch].filter(u => {
    try {
      const h = new URL(u).hostname;
      return (h === domain || h.endsWith('.' + baseDomain))
        && /\.(js|html|htm|json|xml|css|map|txt)(\?|$)/i.test(u);
    } catch (e) { return false; }
  });

  console.log('[path-recon] fetching:', fetchable.length, 'resources');

  // ── Batch fetch ───────────────────────────────────────────────────────────
  for (let i = 0; i < fetchable.length; i += 8) {
    await Promise.allSettled(
      fetchable.slice(i, i + 8).map(url =>
        fetch(url, { credentials: 'omit' })
          .then(r => {
            // Skip binary responses
            const ct = r.headers.get('content-type') || '';
            if (/image|font|audio|video|octet-stream|woff|ttf|eot/.test(ct)) return;
            return r.ok ? r.text() : Promise.reject();
          })
          .then(t => { if (t) extractFromText(t); })
          .catch(() => {})
      )
    );
    if (i + 8 < fetchable.length) await new Promise(r => setTimeout(r, 100));
  }

  // ── Well-known probes ─────────────────────────────────────────────────────
  const wellKnown = [
    '/robots.txt', '/sitemap.xml', '/sitemap_index.xml',
    '/.well-known/security.txt', '/manifest.json', '/asset-manifest.json',
    '/sw.js', '/service-worker.js'
  ];
  await Promise.allSettled(
    wellKnown.map(p =>
      fetch(location.origin + p, { credentials: 'omit' })
        .then(r => r.ok ? r.text() : Promise.reject())
        .then(t => {
          paths.add(p);
          extractFromText(t);
          if (p.includes('robots')) {
            t.split('\n').forEach(line => {
              const m = line.match(/^(?:Disallow|Allow|Sitemap):\s*(\S+)/i);
              if (m) addPath(m[1]);
            });
          }
        })
        .catch(() => {})
    )
  );

  // ── Final output ──────────────────────────────────────────────────────────
  const sorted = [...paths]
    .map(p => p.trim())
    .filter(p => isValidPath(p))       // re-validate everything
    .sort()
    .filter((v, i, a) => a[i - 1] !== v);

  const blob = new Blob([sorted.join('\n')], { type: 'text/plain;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'paths_' + domain + '_' + Date.now() + '.txt';
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(a.href); }, 1000);

  console.log('[path-recon] total clean paths:', sorted.length);
  return sorted;
})();
```

### Step 3 — What you get

- A `.txt` file auto-downloads: one clean absolute path per line, sorted and deduped.
- Console prints `[path-recon] fetching: N resources` and `total clean paths: N`.
- The script also returns the array from the console for copy/paste.

### Step 4 — Fuzz & verify the harvest

```bash
# Content discovery with the harvested paths as a seed list
ffuf -w paths_target.txt -u https://target.com/FUZZ -mc 200,201,204,301,302,307,401,403 -ac

# Filter for live endpoints
cat paths_target.txt | httpx -mc 200,401,403 -silent | tee live_paths.txt

# Deeper: extract params from harvested paths
# (see api-fuzzing / ffuf-web-fuzzing skills for the follow-on work)
```

## Commands

```bash
# Verify harvested endpoints are alive
cat paths_target.txt | httpx -silent -mc 200,201,204,401,403

# Feed harvested paths into ffuf for parameter/content fuzzing
ffuf -w paths_target.txt:FUZZ -u https://target.com/FUZZ -ac

# Merge with other recon sources (wayback/gau)
cat paths_target.txt wayback_urls.txt | sort -u > combined.txt
```

## Tools

- **Browser DevTools Console + Network tab** — the runtime environment for the script (Chrome/Edge/Firefox).
- **Performance API** — reads all resource entries the page actually loaded.
- **ffuf / kiterunner** — content discovery using the harvested paths as a seed wordlist.
- **httpx** — liveness/status filtering of harvested endpoints.
- **Burp Suite** — optional: run the same script inside a browser proxied through Burp to capture every fetch in history.

## Bypass Techniques / Edge Cases

- **App is behind auth**: run the script while logged in as the highest-privilege account in scope — protected routes/chunks only load in that state.
- **CORS blocks the fetches**: the script scopes to same-domain/same-base-domain resources, so this is rare; if a CDN subdomain 404s on CORS, the catch silently skips it.
- **`credentials: 'omit'`** means protected API endpoints fetched by the script won't carry cookies — fine for path discovery, but don't expect response bodies from authed endpoints.
- **Big apps**: batches 8 fetches at a time with a 100ms delay; for very large bundles consider raising the batch size and tolerance (be mindful of rate limits / scope rules).
- **Missing chunks**: if you skipped routes, their chunks aren't in the Network tab — go back and click through them, then re-run.
- **JS-rendered paths**: paths built only at runtime (template literals, concatenated strings) won't appear as literals; follow up with `js-secret-hunting` and dynamic crawling.
- **Source maps**: if `.map` files are exposed, fetch them and mine the `sources` array — original source paths reveal the full route table.

## Notes

- Only run this against targets **in scope** and within the program's rate-limit rules; the script issues real fetches to the origin.
- The strict validator keeps output fuzz-ready — don't be tempted to disable it unless you're mining for specific asset names.
- Combine with `js-recon-tricks` (LinkFinder/JSFScan equivalent CLI runs) and `js-secret-hunting` for the full JS attack-surface picture.
- The same-origin path list is a seed, not a complete map — pair it with brute-force fuzzing (`ffuf-web-fuzzing`) and API discovery (`api-fuzzing`) for coverage.

## Agent / MCP Execution Notes

When an agent (e.g., the hunter agent) runs this script through the chrome-devtools MCP `evaluate_script`, apply these adaptations — the raw console script alone will time out or produce no usable output:

1. **Wrap the script** so it can be evaluated and its result returned:
   ```javascript
   async () => await ((async () => { /* script body, minus the Blob/a.click download */ return sorted; })())
   ```
2. **Return values, not downloads.** `evaluate_script` can't see the `a.click()` Blob download. Remove/replace the download block and `return` the result object (e.g., the sorted paths array) — the MCP returns it as JSON.
3. **MCP ~10s timeout — use the FAST PATH on heavy pages.** The full fetch-crawl loop (Step 2 script) exceeds the MCP's default ~10s `evaluate_script` timeout on SPA pages with hundreds of resources. Fast path (completes in ~1s):
   ```javascript
   () => {
     const hrefs = [...document.querySelectorAll('a[href]')].map(a => a.href);
     const srcs = [...document.querySelectorAll('script[src],link[href],img[src]')].map(e => e.src || e.href).filter(Boolean);
     const perf = performance.getEntriesByType('resource').map(r => r.name);
     const uniq = [...new Set([...hrefs, ...srcs, ...perf])];
     const paths = uniq.filter(u => u.startsWith('http')).map(u => { try { return new URL(u).pathname; } catch { return u; } });
     return [...new Set(paths)].sort();
   }
   ```
   Use the full fetch-based crawl only on lightweight pages (low resource counts, e.g., simple home/login pages).
4. **Per-page execution.** `performance.getEntriesByType('resource')` resets on every navigation, so run the dump on EACH page/route you visit and merge/dedupe the results across pages (e.g., write each page's output to `/tmp/opencode/<page>_paths.txt`).
5. **Save outputs to disk** yourself (the MCP context has no browser downloads folder): write the returned JSON to a file, then filter for interesting endpoints and verify with `httpx -mc 200,401,403`.

## References

- LinkFinder (concept origin of the quoted-path regex): https://github.com/GerbenJavado/LinkFinder
- ProjectDiscovery ffuf: https://github.com/ffuf/ffuf
- ProjectDiscovery httpx: https://github.com/projectdiscovery/httpx
- JSFScan: https://github.com/KathanP19/JSFScan

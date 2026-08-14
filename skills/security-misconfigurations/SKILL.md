---
name: "security-misconfigurations"
version: "1.1"
category: "recon"
subcategory: "misconfiguration"
phase: "scanning"
tags: ["bug-bounty", "misconfiguration", "easy-wins", "debug-mode", "default-credentials", "directory-listing", "backup-files", "dev-endpoints", "unprotected-services", "recon", "discovery", "access-control", "account-takeover", "api", "auth", "authorization", "bypass", "cloud", "cors", "exploitation", "fuzzing", "graphql", "idor", "iis", "information-disclosure", "js-recon", "mass-assignment", "mobile", "oauth", "path-traversal", "privesc", "session", "takeover", "token", "waf-bypass", "env-files", "docker", "config-exposure"]
tools: ["curl", "ffuf", "gobuster", "dirsearch", "httpx", "nuclei", "burp-suite", "katana", "waybackurls", "hydra"]
follow_up_skills: ["admin-panel-bypass", "information-disclosure-harvesting", "exposed-source-code-recovery", "ffuf-web-fuzzing", "idor-detection-exploitation", "exploitation-chaining", "bug-bounty-reporting"]
prerequisite_skills: ["recon-attack-surface-mapping"]
description: "Bug bounty skill: security misconfigurations - scanning phase, recon category"
---
# Security Misconfigurations — The Easy Wins

## Summary

Not every vulnerability requires a complex payload — sometimes the system is already misconfigured. No bypass, no injection: something was simply left exposed, enabled, or forgotten. These bugs are everywhere and many hunters walk right past them. This skill is the class-level checklist for finding them: debug mode enabled, default credentials, open admin panels, directory listing, unprotected services, backup files, hidden directories, and dev/staging endpoints. Each technique is low-effort and high-reward.

## Key Concepts

- **Misconfiguration definition** — a system is set up in an insecure way (default configs, debug features, missing auth, exposed tooling)
- **Low effort → high reward** — these findings often require only a single HTTP request
- **Impact classes** — unauthorized access, sensitive data exposure, system control, and a foothold for further exploitation
- **Combination value** — a misconfiguration is rarely the end; chain it (misconfig + IDOR, misconfig + data exposure) to raise severity
- **Hunting mindset** — ask "what did the developer forget to secure?" not "what payload can I send?"

## Attack Surface — Where to Look

- Admin panels and restricted areas
- Debug / status / log pages
- Backup files and archives
- Hidden directories
- Server and application config files
- Development, staging, and test endpoints
- Response headers (server version, debug info)

## Methodology

### 1. Try Common Admin / Restricted Paths

```
/admin
/admin/login
/dashboard
/control-panel
```

If any path responds with `200` and an admin UI or login form — and no authentication is enforced — that is already a misconfiguration finding.

### 2. Check for Default Credentials

Try the classic pairs on any login you find:

```
admin:admin
admin:password
test:test
admin:123456
root:root
administrator:administrator
```

> Real impact scenario: `/admin` returns a login page, `admin:admin` works → full admin access → critical vulnerability.

### 3. Look for Debug / Status Pages

```
/debug
/status
/logs
```

Debug output can leak source paths, env vars, framework versions, and internal state.

### 4. Analyze Access

If a protected resource is accessible without any restriction (no login redirect, no 403), the misconfiguration is confirmed. Verify what the unauthenticated access actually exposes before reporting.

### 5. Pro Techniques — Easy Wins

- **Backup files** — `/backup.zip`, `/backup.tar.gz`, `/config.bak`, `/.env`, `/db.sql` — routinely contain secrets and source code
- **Directory listing** — if enabled, browse the directory directly for files not linked anywhere else
- **Development endpoints** — `/dev`, `/staging`, `/test` — often less hardened than production
- **Header inspection** — look for server version and debug headers that reveal weaknesses
- **Combine with other bugs** — a misconfiguration as an entry point amplifies IDOR, data exposure, and auth bypass findings

### 6. Modern Dev Config Artifacts (High-Value)

`wp-config.php.bak`-style finds are old news. Modern dev workflows expose a new generation of sensitive files — each one routinely full of credentials:

- `.env.local`, `.env.production`, `.env.staging` — API keys, DB creds, third-party service secrets
- `config/sync.php` — roots/bedrock-style setups with plain-text DB credentials
- `docker-compose.yml`, `Dockerfile`, `docker.env` — leaked through misconfigured upload/static dirs
- `package.json` / `composer.json` — may hardcode tokens for private repositories (npm/GitHub/Packagist)
- `sftp-config.json` — accidentally committed by Sublime Text users (contains server + credentials)

Fuzz for them with extension lists — don't just probe the literal names:

```bash
ffuf -w modern-configs.txt -u https://target.com/FUZZ \
  -fc 404,403 -e .bak,.old,.save,.swp,.txt,.json,.yml,.yaml,.env,.ini \
  -t 50 -ac
```

Also probe inside app-specific dirs: `/wp-content/themes/<theme>/`, `/wp-content/plugins/<plugin>/`, `/node_modules/`, `/app/config/`, `/src/`.

## Detection Commands

```bash
# Probe common admin/restricted paths
for p in admin admin/login dashboard control-panel console; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$p")
  echo "/$p -> HTTP $code"
done

# Probe debug/status/log endpoints
for p in debug status logs health info; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$p")
  [ "$code" != "404" ] && echo "[!] /$p -> HTTP $code"
done

# Probe backup/config files
for f in backup.zip backup.tar.gz config.bak .env db.sql dump.sql; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$f")
  [ "$code" != "404" ] && echo "[!] /$f -> HTTP $code"
done

# Probe modern dev config artifacts
for f in .env.local .env.production .env.staging .env.backup config/sync.php \
         docker-compose.yml docker-compose.yaml Dockerfile docker.env \
         sftp-config.json package.json composer.json .npmrc .pypirc; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$f")
  [ "$code" != "404" ] && echo "[!] /$f -> HTTP $code"
done

# Extension fuzz for config artifacts (catches .bak/.old/.swp/.yml variants)
ffuf -w modern-configs.txt -u https://target.com/FUZZ \
  -fc 404,403 -e .bak,.old,.save,.swp,.txt,.json,.yml,.yaml,.env,.ini -t 50 -ac

# Probe dev/staging/test endpoints
for p in dev staging test qa preprod uat; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$p/")
  [ "$code" != "404" ] && echo "[!] /$p -> HTTP $code"
done

# Directory listing check
curl -s "https://target.com/uploads/" | head -20
curl -s "https://target.com/static/" | head -20

# Header fingerprinting
curl -sI "https://target.com/" | grep -iE "server|x-powered|x-aspnet|server-timing"
```

## Checklist

- [ ] Brute-force common admin panel paths
- [ ] Test default credentials (admin:admin, admin:password, test:test)
- [ ] Check debug/status/log endpoints (/debug, /status, /logs)
- [ ] Check directory listing on uploads/static/assets directories
- [ ] Probe backup files (/backup.zip, /config.bak, /.env)
- [ ] Probe modern dev config artifacts (.env.local/.env.production, docker-compose.yml, sftp-config.json, composer.json/package.json tokens)
- [ ] Extension-fuzz config names (.bak/.old/.swp/.yml/.env variants) with ffuf
- [ ] Probe dev/staging/test endpoints (/dev, /staging, /test)
- [ ] Inspect response headers for server version/debug info
- [ ] Confirm unauthenticated access to protected resources
- [ ] Chain misconfiguration with IDOR/data exposure to raise severity

## Common Mistakes

- Ignoring "simple" issues because they lack a payload
- Not testing default credentials
- Skipping directory enumeration
- Not checking configuration files
- Reporting without confirming what unauthenticated access actually exposes

## Not a Finding If

- The path returns a standard 404 (nothing exposed)
- A login page appears but default credentials fail and no bypass applies (that is an auth test, not a misconfiguration finding)
- Directory listing is disabled and files are not individually accessible
- A version banner exists but no exposed surface or exploitation path follows

## Notes

- Do not invent exploitation steps — verify access, document exactly what was exposed, then stop
- Respect scope: only test systems you are authorized to test (educational/authorized engagement only)
- Deep dives live in sibling skills: `admin-panel-bypass` (admin discovery/bypass), `information-disclosure-harvesting` (artifacts, headers, backups), `exposed-source-code-recovery` (VCS + archive source recovery), `ffuf-web-fuzzing` (large-scale content discovery)

## References

- https://medium.com/bug-bounty-hunting-a-comprehensive-guide-in/security-misconfigurations-the-easy-wins-most-hunters-miss-4dce0b06e311
- https://owasp.org/Top10/A05_2021-Security_Misconfiguration/

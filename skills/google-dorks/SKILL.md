---
name: "google-dorks"
version: "2.0"
category: "recon"
subcategory: "attack-surface"
phase: "reconnaissance"
tags: ["bug-bounty", "recon", "google-dorks", "passive-recon", "osint"]
tools: ["google-search"]
follow_up_skills: ["subdomain-enumeration-checklist", "ffuf-web-fuzzing", "recon-attack-surface-mapping", "js-recon-tricks"]
prerequisite_skills: ["google-search"]
description: "Bug bounty skill: google dorks - reconnaissance phase, recon category"
---
# Google Dorks for Bug Bounty Hunting

## Summary

Google Dorks are advanced search operators that uncover hidden endpoints, exposed files, misconfigurations, and sensitive information on target domains. Organized by vulnerability type for efficient bug bounty recon.

## Key Concepts

- **Google Dork**: A search query using advanced operators (`site:`, `inurl:`, `ext:`, `intitle:`, `intext:`) to find specific content on web servers.
- **Scope Discipline**: Only test domains explicitly listed in the program's scope.
- **Combine operators**: `site:target.com ext:env -ext:php` — chain operators for precision.
- **Exclude noise**: `-inurl:help -inurl:support` to filter false positives.

## Technical Details

### Authentication & Login Issues
```
site:target.com inurl:login | inurl:signin | inurl:auth
site:target.com inurl:admin | inurl:dashboard | inurl:panel
site:target.com intitle:"admin" inurl:"/admin"
```

### Exposed Files & Directories
```
site:target.com ext:log | ext:txt | ext:conf | ext:cnf | ext:ini | ext:env
site:target.com ext:sql | ext:db | ext:backup | ext:bak | ext:old
site:target.com inurl:"/backup" | inurl:"/dump" | inurl:"/old"
site:target.com ext:php intitle:"phpinfo()"
```

### Sensitive Config & Credentials
```
site:target.com ext:env "DB_PASSWORD" | "AWS_SECRET" | "API_KEY"
site:target.com inurl:.git | inurl:".git/config"
site:target.com ext:xml | ext:json inurl:config | inurl:settings
site:target.com "index of" inurl:"/config"
```

### Open Redirects & URL Parameters
```
site:target.com inurl:redirect= | inurl:url= | inurl:next= | inurl:return=
site:target.com inurl:returnUrl= | inurl:goto= | inurl:dest=
```

### Potential Injection Points
```
site:target.com inurl:id= | inurl:pid= | inurl:item= | inurl:page=
site:target.com inurl:search= | inurl:query= | inurl:keyword=
site:target.com inurl:file= | inurl:path= | inurl:folder=
site:target.com inurl:load= | inurl:read= | inurl:display=
```

### Exposed API Endpoints
```
site:target.com inurl:/api/ | inurl:/v1/ | inurl:/v2/ | inurl:/v3/
site:target.com inurl:/api/swagger | inurl:/api-docs | inurl:/openapi
site:target.com ext:json inurl:api | inurl:swagger
```

### Directory Listing & Index Pages
```
site:target.com intitle:"index of /"
site:target.com intitle:"index of" "parent directory"
site:target.com intitle:"directory listing"
```

### Error Messages & Stack Traces
```
site:target.com intitle:"error" | intitle:"exception" | intitle:"warning"
site:target.com "sql syntax" | "mysql error" | "ORA-" | "syntax error"
site:target.com intext:"stack trace" | intext:"debug info"
```

### Misconfigured Cloud Storage
```
site:s3.amazonaws.com "target"
site:blob.core.windows.net "target"
site:storage.googleapis.com "target"
```

### JS Files for Endpoints & Keys
```
site:target.com ext:js inurl:main | inurl:app | inurl:bundle
site:target.com ext:js "apiKey" | "api_key" | "token" | "secret"
```

### Subdomains & Dev/Staging Environments
```
site:*.target.com inurl:dev | inurl:staging | inurl:test | inurl:uat
site:*.target.com inurl:demo | inurl:beta | inurl:sandbox
```

## Methodology

1. Start with broad target scope: `site:*.target.com` for all subdomains.
2. Narrow by vulnerability type using the dork lists above.
3. Chain operators to refine results: `site:target.com ext:env -ext:php`.
4. Exclude false positives: append `-inurl:help -inurl:support -inurl:blog`.
5. Verify findings manually or with automated tools before reporting.
6. For bug bounty, use `"responsible disclosure"` type searches to find programs.

## Payloads

N/A — these are search queries, not exploitation payloads.

## Commands

N/A — these are Google search queries used in the browser.

## Tools

- Google Search (web browser)
- `site:` operator — filter by domain
- `inurl:` / `intitle:` / `intext:` — search in URL, title, or body
- `ext:` — filter by file extension
- `*` wildcard — match any subdomain

## Bypass Techniques

N/A

## Notes

- Always verify that the target domain is within your authorized scope before testing.
- Combine multiple operators for better precision: `site:target.com ext:env "DB_PASSWORD"`.
- Filter out generic pages (help, support, blog) to reduce noise.
- Use `site:*.target.com` with wildcard to include all subdomains.
- Google dorks are passive recon — they don't send traffic to the target.
- Results may vary over time as Google re-indexes pages.

## References

- https://imran-niaz.medium.com/here-are-powerful-google-dorks-for-bug-bounty-hunting-cf5d84c82b7d

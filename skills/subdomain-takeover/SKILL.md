---
name: "subdomain-takeover"
version: "2.0"
category: "recon"
subcategory: "subdomain-enumeration"
phase: "exploitation"
tags: ["bug-bounty", "takeover", "dns", "cname", "cloud-misconfiguration"]
tools: ["subfinder", "dnsx", "httpx", "subzy", "nuclei", "can-i-take-over-xyz"]
follow_up_skills: ["exploitation-chaining", "bug-bounty-reporting"]
prerequisite_skills: ["subdomain-enumeration-checklist"]
description: "Bug bounty skill: subdomain takeover - exploitation phase, recon category"
---
# Subdomain Takeover

## Summary

Subdomain takeover occurs when a subdomain's DNS record (usually a CNAME) points to a cloud provider resource that has been deleted or deactivated, but the DNS record remains. An attacker can claim the abandoned resource and gain full control of the subdomain.

## Key Concepts

- **CNAME Record**: A DNS record that maps a subdomain to a cloud provider's hostname (e.g., `dev.company.com CNAME example-app.vercel.app`).
- **Abandoned Resource**: When the cloud resource is deleted but the DNS record persists, the subdomain becomes available for takeover.
- **Impact**: Phishing, cookie theft, JS injection, malware delivery, whitelist bypass, brand damage.

## Technical Details

### Takeover Chain

```
dev.company.com  ->  CNAME  ->  example-app.vercel.app
Vercel resource deleted
Attacker registers example-app.vercel.app
Attacker controls dev.company.com
```

### Step-by-Step Workflow

**1. Enumerate subdomains**
```bash
subfinder -d target.com -o subs.txt
```

**2. Extract CNAME records**
```bash
dnsx -l subs.txt -a -cname -resp
```

**3. Identify potential vulnerable services** (look for 404, 403, 301, 302 responses)
```bash
httpx -l subs.txt -mc 404,403,301,302 -title -server -tech-detect
```

**4. Check automatically using tools**
```bash
subzy run --targets subs.txt
```

### Automated Exploitation Example (Heroku)

Once a vulnerable Heroku-based subdomain is detected:
```bash
heroku create example-app
heroku domains:add dev.company.com
```

## Methodology

1. Enumerate as many subdomains as possible using passive and active tools.
2. Extract all CNAME records from the subdomain list.
3. Identify CNAMEs pointing to known cloud providers (AWS, Heroku, Vercel, Netlify, GitHub Pages, Azure, etc.).
4. Check if the target resource responds with 404/NXDOMAIN/error page indicating it's available for claiming.
5. Use automated tools (subzy, SubOver, nuclei templates) to confirm.
6. Claim the cloud resource and verify control.

## Payloads

None — this is a configuration-based attack.

## Commands

```bash
# Subdomain enumeration
subfinder -d target.com -o subs.txt

# CNAME extraction
dnsx -l subs.txt -a -cname -resp

# Check for vulnerable responses
httpx -l subs.txt -mc 404,403,301,302 -title -server -tech-detect

# Automated takeover check
subzy run --targets subs.txt

# Heroku takeover example
heroku create example-app
heroku domains:add dev.company.com
```

## Tools

- **subfinder** — Subdomain discovery (ProjectDiscovery)
- **dnsx** — DNS record extraction
- **httpx** — HTTP probing with status/tech detection
- **subzy** — Automated subdomain takeover detection
- **SubOver** — Subdomain takeover tool
- **Nuclei** — Template-based scanning (includes takeover templates)
- **can-i-take-over-xyz** — Reference list of vulnerable cloud services

## Bypass Techniques

None — this is a configuration/misconfiguration finding.

## Notes

- Recon is everything — more subdomains = more takeover chances.
- Cloud adoption (Vercel, Netlify, Heroku, AWS, Azure) has made takeovers more common — companies create and delete microservices rapidly but forget DNS records.
- Focus on subdomains returning 404, 403, 301, or 302 — these often indicate abandoned resources.
- Always verify you can claim the resource before reporting.
- Subdomain takeovers often result in high-severity bounties due to potential for phishing and cookie theft.

## References

- https://osintteam.blog/subdomain-takeover-in-2025-new-methods-tools-33bba0de6afc
- https://github.com/projectdiscovery/subfinder
- https://github.com/projectdiscovery/dnsx
- https://github.com/LukaSikic/subzy
- https://github.com/Ice3man543/SubOver
- https://github.com/projectdiscovery/nuclei-templates
- https://github.com/EdOverflow/can-i-take-over-xyz

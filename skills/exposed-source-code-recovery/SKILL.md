---
name: "exposed-source-code-recovery"
version: "2.1"
category: "privesc"
subcategory: "source-code"
phase: "reconnaissance"
tags: ["bug-bounty", "privesc", "source-code", "git-exposure", "vcs-leak", "recon", "backup-files", "misconfiguration"]
tools: ["curl", "ffuf", "git-dumper", "svn-extractor"]
follow_up_skills: ["information-disclosure-harvesting", "authorization-session-testing", "exploitation-chaining"]
description: "Bug bounty skill: exposed source code recovery - reconnaissance phase, privesc category"
---
# Exposed Source Code

## Summary

Source code intended to be kept server-side can be disclosed via exposed version control system (VCS) metadata directories. These directories contain complete repository history, source files, diffs, and sensitive information (database passwords, API keys, secret keys) that enable further attacks. Backup archives are a second, equally fruitful channel — `/backup.zip`, `/site.tar.gz`, and similar files often contain complete source trees without any VCS parsing needed.

## Where to Find

- `/.git` — Git repository metadata
- `/.svn` — Subversion metadata
- `/.hg` — Mercurial metadata
- `/.bzr` — Bazaar metadata
- `/_darcs` — Darcs metadata
- `/BitKeeper` — BitKeeper metadata
- Backup archives — `/backup.zip`, `/backup.tar.gz`, `/site.zip`, `/config.bak`, `/db.sql` — often full source dumps, no VCS needed

Check the root and common subdirectory paths of the target.

## Methodology

1. Probe for exposed VCS directories by requesting their root paths (e.g., `https://target.com/.git/`).
2. If accessible, use the appropriate dumping tool to download the full repository.
3. Examine downloaded files for secrets (credentials, API keys, hardcoded passwords, tokens).
4. Review commit history for secrets that were committed and later removed (they remain in history).

## Detection Commands

```bash
# Check for exposed .git
curl -s -o /dev/null -w "%{http_code}" https://target.com/.git/
curl -s -o /dev/null -w "%{http_code}" https://target.com/.git/config

# Check for exposed .svn
curl -s -o /dev/null -w "%{http_code}" https://target.com/.svn/
curl -s -o /dev/null -w "%{http_code}" https://target.com/.svn/entries

# Check for exposed .hg
curl -s -o /dev/null -w "%{http_code}" https://target.com/.hg/

# Check for exposed .bzr
curl -s -o /dev/null -w "%{http_code}" https://target.com/.bzr/

# Check for exposed _darcs
curl -s -o /dev/null -w "%{http_code}" https://target.com/_darcs/

# Check for exposed BitKeeper
curl -s -o /dev/null -w "%{http_code}" https://target.com/BitKeeper
```

## Exploitation Tools

### Git — git-dumper

```bash
pip install git-dumper
git-dumper https://target.com/.git/ ./output_dir
```

### Subversion — svn-extractor

```bash
git clone https://github.com/anantshri/svn-extractor
python svn-extractor.py -u https://target.com/.svn/ -o ./output_dir
```

### Mercurial — hg-dumper

```bash
git clone https://github.com/arthaud/hg-dumper
python hg-dumper.py https://target.com/.hg/ ./output_dir
```

### Bazaar — bzr_dumper

```bash
git clone https://github.com/shpik-kr/bzr_dumper
python bzr_dumper.py https://target.com/.bzr/ ./output_dir
```

### Darcs

No public dumping tool found — manual exploration of `/_darcs` is required.

## Not a Finding If

- The `.git` directory returns `403 Forbidden` or `404 Not Found` — not exposed
- Only directory listing is disabled but individual files are accessible — still a finding if `.git/config` or other sensitive files can be read
- The VCS directory exists but is served as a plain text listing with no ability to download files — partial disclosure, may still leak filenames

## Notes

- Exposed `.git` is the most common and most critical — it contains the full commit history, and secrets removed in later commits remain accessible in older revisions
- Even if the server returns `403` on `/.git/`, check `/.git/config` directly — some configurations block directory listing but allow file access
- `.git/HEAD` is the smallest file to check — it returns `ref: refs/heads/main\n` if accessible
- VCS exposure often leads to full source code disclosure, which enables finding other vulnerabilities (hardcoded credentials, API keys, business logic flaws)
- Always check common subdirectories too: `/admin/.git/`, `/api/.git/`, `/backup/.git/`

# Bug Bounty Workflow Rules

## Fuzzing & Brute-Forcing: Use ffuf, NOT curl
- For any path/content/parameter fuzzing or brute-forcing, use **ffuf** instead of curl loops.
- Prefer the user-maintained wordlists in `/home/bugbounty/.config/opencode/skills/wordlist/`.
- Create custom inline wordlists (`-w <(seq ...)`, `printf`, process substitution, or temp files in `/tmp/opencode`) when a task needs a non-standard word list.
- Standard ffuf flags: `-ac` (auto-calibration), `-fc 404,403`, `-mc 200,301,302,401`, `-t` threads, `-rate` stealth limit.

## Available Wordlists
- `/home/bugbounty/.config/opencode/skills/wordlist/adminpanel.txt` — admin panel paths (419)
- `/home/bugbounty/.config/opencode/skills/wordlist/apis.txt` — API paths/routes (280k)
- `/home/bugbounty/.config/opencode/skills/wordlist/commonapis.txt` — common API paths (220)
- `/home/bugbounty/.config/opencode/skills/wordlist/common.txt` — common web paths (4.4k)
- `/home/bugbounty/.config/opencode/skills/wordlist/directory-list-2.3-medium.txt` — dirbuster medium (220k)
- `/home/bugbounty/.config/opencode/skills/wordlist/git-paths.txt` — git exposure paths (20)
- `/home/bugbounty/.config/opencode/skills/wordlist/lfi.txt` — LFI payloads (70k)
- `/home/bugbounty/.config/opencode/skills/wordlist/wordpress-1.txt` — WordPress paths (6.5k)

## Wordlist Selection Guidance
- Directory/endpoint discovery: `common.txt` (fast) → `directory-list-2.3-medium.txt` (thorough)
- API testing: `commonapis.txt` (fast) → `apis.txt` (thorough)
- WordPress targets: `wordpress-1.txt`
- LFI: `lfi.txt`
- Git exposure: `git-paths.txt`
- Admin panels: `adminpanel.txt`

## Tools Preference
- Prefer ffuf for fuzzing/bruteforce; use curl only for single-shot requests, headers inspection, or API calls.

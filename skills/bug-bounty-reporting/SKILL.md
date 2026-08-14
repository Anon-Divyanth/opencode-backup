---
name: "bug-bounty-reporting"
description: "Bug bounty skill: bug bounty reporting - reporting phase, report category"
version: "2.0"
category: "report"
subcategory: "reporting"
phase: "reporting"
tags: ["bug-bounty", "report", "reporting", "writeup", "impact", "severity", "chain", "escalation", "business-impact", "reproducibility"]
follow_up_skills: ["exploitation-chaining"]
prerequisite_skills: ["wordpress-assessment", "iis-hacking", "laravel-vulnerability-assessment", "denial-of-service-testing", "exploitation-chaining"]
---
# Bug Bounty Reporting

Category: report / reporting
Phase: reporting

## Tags
bug-bounty, report, reporting, writeup, impact, severity, chain, escalation

## Summary

The difference between a $200 and a $3,000 report is rarely skill — it's depth. A report is only as strong as the impact it demonstrates and the clarity of its steps-to-reproduce. When findings are chained, the report must present the chain as a single escalation path, not a list of isolated bugs.

## Methodology
1. Identify the attack surface related to reporting
2. Apply bug bounty reporting testing techniques
3. Validate findings and document impact
4. Chain with follow-up skills for maximum impact
5. Translate technical impact to business impact (severity follows business impact, not the technical primitive)

## Key Concepts

- **Impact sells**: Don't write *"User role can be changed."* Write *"An attacker can escalate privileges to administrator, gaining access to user data, financial records, and account management functionality."*
- **Chain presentation**: When chaining findings, present the escalation path end-to-end (entry point → weak control → adjacent system → privilege escalation → business impact → critical severity) rather than separate findings.
- **Severity justification**: Tie the severity to confidentiality, integrity, and availability impact of the *combined* chain.

## Reporting a Full Chain

When findings are chained, never report the bugs in isolation. Tell the full story:

- **Open with the end-state framing**: *"An unauthenticated attacker can do X"* — then walk through the chain step by step.
- **Make the impact escalation explicit**: *"While each individual issue might be low or medium risk, together they result in full compromise of the system."*
- **List every assumption that wasn't enforced** (e.g., dev test accounts left active, profile input not sanitized, authenticated requests assumed legitimate, auth assumed sufficient for sensitive functions) — these map directly to the fixes.
- **Include validation evidence per step** (the XSS firing, the `GET /script.js` hit in the payload server log, the successful admin login), not just the final outcome.

### Red Team vs. Bug Bounty Endgames

The reporting goal shapes how far the chain is pushed:

- **Red team** — demonstrate impact holistically; follow the chain as far as possible (lateral movement, persistence) while staying undetected.
- **Bug bounty** — clearly show risk and potential impact so the vendor can fix it. Sometimes stop *before* full exploitation: the report is enough to prove the point. The chain's purpose is to show **how multiple bugs combine**.

## Escalated Chain Report Template

Reusable template for reporting a chained vulnerability as a single high/critical finding.

### Title
```
Privilege Escalation to Administrator via IDOR + Missing Role Validation
```

### Summary
```
An authenticated attacker can escalate privileges to administrator by chaining an
insecure direct object reference (IDOR) with missing backend role validation.
```

### Steps to Reproduce
1. Log in as normal user.
2. Intercept request to:
   - `GET /api/user/profile?id=1042`
3. Modify ID to another user.
4. Identify role update endpoint:
   - `POST /api/user/update-role`
5. Modify request body:
   - `{ "user_id": 1042, "role": "admin" }`
6. Observe successful role change.
7. Log in with escalated privileges.

### Impact
```
An attacker can gain administrator-level access, allowing:
- Access to all user data
- Account deletion/modification
- Financial record exposure
- Potential full system compromise
```

### Severity Justification
```
This vulnerability enables vertical privilege escalation and full administrative
control. The impact affects confidentiality, integrity, and availability.
```

### Recommended Fix
- Enforce backend authorization checks
- Validate user roles server-side
- Restrict ID-based access via ownership validation

## Why Most Reports Stay Medium

Because hunters:
- Think in isolation (report one primitive instead of the chain)
- Submit early (before exploring adjacency)
- Don't map privilege boundaries
- Describe the technical mechanism instead of the business impact

## Follow-up Skills
- exploitation-chaining — build the escalation path before reporting it

## Prerequisites
- wordpress-assessment
- iis-hacking
- laravel-vulnerability-assessment
- denial-of-service-testing
- exploitation-chaining

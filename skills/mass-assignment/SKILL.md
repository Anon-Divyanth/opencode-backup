---
name: "mass-assignment"
version: "2.0"
category: "api"
subcategory: "mass-assignment"
phase: "exploitation"
tags: ["bug-bounty", "mass-assignment", "autobinding", "privilege-escalation", "orm", "access-control", "account-takeover", "api", "auth", "authorization", "bypass", "cloud", "cors", "exploitation", "fuzzing", "graphql", "idor", "iis", "information-disclosure", "js-recon", "mobile", "oauth", "path-traversal", "privesc", "session", "takeover", "token", "waf-bypass"]
tools: ["burp-suite", "arjun", "paramspider", "authz", "autorize", "burp", "graphqlmap", "grpcurl", "john", "kiterunner", "paramalyzer", "parameth", "repeater", "restler", "zap"]
follow_up_skills: ["graphql-vulnerabilities", "api-fuzzing", "authorization-session-testing", "idor-detection-exploitation", "prototype-pollution-exploitation"]
description: "Bug bounty skill: mass assignment - exploitation phase, api category"
---
# Mass Assignment

## Summary

Mass Assignment occurs when a web application automatically maps user-supplied input to object properties without proper filtering. An attacker can modify attributes they should not have access to, such as permissions, admin flags, or balances. Common in frameworks using ORM techniques (Ruby on Rails, Django, Laravel, etc.).

## Key Concepts

- **ORM mass assignment**: Frameworks map entire request bodies to model attributes in a single operation
- **Whitelist (`$fillable`/`attr_accessible`)**: Explicitly allowed fields for mass assignment
- **Blacklist (`$guarded`/`attr_protected`)**: Explicitly denied fields
- **API exposure**: Mass assignment often targets REST APIs that accept JSON bodies

## Attack Surface

- REST/JSON, GraphQL inputs, form-encoded and multipart bodies
- Model binding in controllers/resolvers; ORM create/update helpers
- Writable nested relations, sparse/patch updates, bulk endpoints

## Technical Details

Consider a `User` model with attributes: `username`, `email`, `password`, `isAdmin`. A normal update form only allows changing the first three. If the server uses `request.all()` or similar to update the model, an attacker adds the extra parameter:

```json
{
    "username": "attacker",
    "email": "attacker@email.com",
    "password": "unsafe_password",
    "isAdmin": true
}
```

If the framework doesn't whitelist fields, `isAdmin` is written to the model, granting admin privileges.

### Framework-Specific Examples

**Laravel** — see `Knowledge/Vulnerabilities/Laravel_Common_Vulnerability_Spots.md` for vulnerable/fix code:

```php
// Vulnerable
$user->update($request->all());

// Fix: validate and whitelist
$validated = $request->validate(['name' => 'required', 'email' => 'required|email']);
$user->update($validated);
```

Also set `$fillable` in the Eloquent model to whitelist allowed fields.

**Ruby on Rails** — bypass via nested parameters (see `Knowledge/Vulnerabilities/XSS.md` for Rails mass assignment XSS payload).

### ORM Framework Edges

- **Rails**: Strong parameters misconfiguration or deep nesting via `accepts_nested_attributes_for`
- **Laravel**: `$fillable`/`$guarded` misuses; `guarded=[]` opens all; casts mutating hidden fields
- **Django REST Framework**: Writable nested serializer, `read_only`/`extra_kwargs` gaps, partial updates
- **Mongoose/Prisma**: Schema paths not filtered; `select:false` doesn't prevent writes; upsert defaults

### Parser and Validator Gaps

- Validators run post-bind and do not cover extra fields
- Unknown fields silently dropped in response but persisted underneath
- Inconsistent allowlists between mobile/web/gateway; alt encodings bypass validation pipeline

## Key Vulnerabilities

### Privilege Escalation

- Set `role`/`isAdmin`/`permissions` during signup or profile update
- Toggle admin/staff flags where exposed

### Ownership Takeover

- Change `ownerId`/`accountId`/`tenantId` to seize resources
- Move objects across users/tenants

### Feature Gate Bypass

- Enable premium/beta/feature flags via `flags`/`features` fields
- Raise limits/`seatCount`/`quotas`

### Billing and Entitlements

- Modify `plan`/`price`/`prorate`/`trialEnd` or `creditBalance`
- Bypass server-side recomputation

### Nested and Relation Writes

- Writable nested serializers or ORM relations allow creating or linking related objects beyond caller's scope

## Testing Locations

Mass assignment can appear in any endpoint that creates or updates objects:

- **Account Registration** — Add privilege escalation fields to the registration body
- **Login Response** — Some APIs return user data after login that may include privileged fields; intercept and modify
- **Password Reset / Change** — Add admin fields to reset/change requests
- **Email Change / Username Change** — Profile update endpoints are a common vector
- **Organization/Team Creation** — Inject `org`, `organization`, `company` parameters to gain unauthorized access
- **Any Create/Update endpoint** — POST, PUT, PATCH

## Reconnaissance

### Surface Map

- Identify controllers/resolvers with automatic model binding (e.g., `request.json → model`)
- GraphQL input types that mirror database models; admin/staff tools exposed via API
- Parse OpenAPI/GraphQL schemas to uncover hidden fields or enums
- Inspect client bundles and mobile apps for form fields and mutation payload names

### Parameter Strategies

Build a sensitive-field dictionary per resource:

- **Flat fields**: `isAdmin`, `role`, `roles[]`, `permissions[]`, `status`, `plan`, `tier`, `premium`, `verified`, `emailVerified`
- **Ownership/tenancy**: `userId`, `ownerId`, `accountId`, `organizationId`, `tenantId`, `workspaceId`
- **Limits/quotas**: `usageLimit`, `seatCount`, `maxProjects`, `creditBalance`
- **Feature flags/gates**: `features`, `flags`, `betaAccess`, `allowImpersonation`
- **Billing**: `price`, `amount`, `currency`, `prorate`, `nextInvoice`, `trialEnd`

### Shape Variants

- Alternate shapes: arrays vs scalars; nested JSON; objects under unexpected keys
- Dot/bracket paths: `profile.role`, `profile[role]`, `settings[roles][]`
- Duplicate keys and precedence: `{"role":"user","role":"admin"}`
- Sparse/patch formats: JSON Patch / JSON Merge Patch; try adding forbidden paths

### Encodings and Channels

- Content-types: `application/json`, `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`
- GraphQL: add suspicious fields to input objects; overfetch response to detect changes
- Batch/bulk: arrays of objects; verify per-item allowlists not skipped

## Methodology

1. Identify endpoints that create or update objects (POST, PUT, PATCH) and GraphQL mutations.
2. Review the request body format and capture responses — observed returned fields build the candidate list.
3. Add extra parameters not present in the original form across all transports and encodings.
4. Test all case/name variants for privilege escalation fields (nested objects, arrays, alternative shapes, duplicate keys, batch operations).
5. Check if the server silently accepts and processes the injected fields.
6. Compare state — before/after diffs across roles. Verify by observing changed behavior or response containing the new attribute.
7. Test variations — nested objects, arrays, alternative shapes, duplicate keys, batch operations.

### Step 0: Find Variables via Documentation

API documentation often lists all available fields including privileged ones. Search the docs for:
- Authentication/authorization field names (`admin`, `role`, `permissions`)
- Hidden parameters not exposed in the UI
- Example payloads that include admin-level fields
- Swagger/OpenAPI specs — these reveal the full schema

### Step 1: Find Hidden Variables via Request Inspection

Intercept a legitimate request and inspect for parameters beyond the obvious ones (username, email, password). Bonus parameters like `uam`, `mfa`, `account` hint at privileged fields that may be mass-assignable:

```json
POST /create/user
{
    "username": "hapi_hacker",
    "pass": "ff7ftw",
    "uam": 1,
    "mfa": true,
    "account": 101
}
```

Also read API documentation — docs often list available fields including privileged ones not exposed in the UI.

### Step 2: Test Admin Field Variants

For registration and all create/update endpoints, cycle through privilege escalation field names:

```json
// Registration baseline
POST /api/v1/register
{
    "username": "hAPI_hacker",
    "email": "hapi@hacker.com",
    "password": "Password1!"
}
```

Try each variant as an additional field:

| # | Field | Value | Notes |
|---|---|---|---|
| 1 | `"admin":` | `true` | Common boolean flag |
| 2 | `"ADMIN":` | `true` | Uppercase variant |
| 3 | `"isadmin":` | `true` | Lowercase |
| 4 | `"ISADMIN":` | `true` | All uppercase |
| 5 | `"Admin":` | `true` | Title case |
| 6 | `"role":` | `"admin"` | String role name |
| 7 | `"role":` | `"ADMIN"` | Uppercase role |
| 8 | `"role":` | `"administrator"` | Full role name |
| 9 | `"user_priv":` | `"administrator"` | Underscore variant |
| 10 | `"user_priv":` | `"admin"` | Short variant |
| 11 | `"admin":` | `1` | Integer instead of boolean |

### Step 3: Test Organizational Access

During registration, try injecting organization/group parameters to join a different org:

```json
POST /api/v1/register
{
    "username": "hAPI_hacker",
    "email": "hapi@hacker.com",
    "org": "CompanyA",
    "password": "Password1!"
}
```

Test variants: `org`, `organization`, `company`, `team`, `group`, `department`.

### Step 4: Test at Every Auth-Related Endpoint

- **Login**: `POST /api/login` — add admin fields alongside credentials
- **Password reset**: `POST /api/reset-password` — add role escalation
- **Email change**: `POST /api/change-email` — add privilege fields
- **Username change**: `POST /api/change-username` — add hidden fields

### Common Fields to Test

```
# Privilege escalation
isAdmin, admin, ADMIN, IsAdmin, isadmin, ISADMIN
role, roles, user_role, user_priv, access_level, permissions
administrator, moderator, manager, superuser

# Financial
balance, credit, points, tokens, quota, account

# Bypass / verification
verified, verified_at, email_verified, active, approved, mfa

# Tokens
api_key, api_token, token, uam

# Organization access
org, organization, company, team, groups, department
```

## Exploitation Payloads

```json
{
    "username": "attacker",
    "email": "attacker@email.com",
    "password": "unsafe_password",
    "isAdmin": true,
    "role": "admin",
    "balance": 999999,
    "verified": true
}
```

### Nested / Array Syntax

```
// Rails-style nested params
user[name]=attacker&user[email]=attacker@email.com&user[isAdmin]=true

// PHP/Laravel array params
user[name]=attacker&user[email]=attacker@email.com&user[isAdmin]=1

// JSON with nested object
{"user": {"name": "attacker", "isAdmin": true}}
```

## GraphQL-Specific Techniques

- Field-level authorization may be missing on input types — attempt forbidden fields in mutation inputs
- Combine aliasing/batching to compare effects of mass assignment attempts
- Use fragments to overfetch changed fields immediately after mutation to detect side effects
- Diff the resource immediately after mutation; effects are often visible even if the mutation returns filtered fields

## Validation

- Show a minimal request where adding a sensitive field changes persisted state for a non-privileged caller
- Provide before/after evidence (response body, subsequent GET, or GraphQL query) proving the forbidden attribute value was written
- Demonstrate consistency across at least two encodings or channels
- For nested/bulk, show that protected fields are written within child objects or array elements
- Quantify impact (e.g., role flip, cross-tenant move, quota increase) and reproducibility

## Tools

- **Burp Suite Repeater** — Manually add extra JSON/params to requests
- **Arjun** — Parameter discovery tool to find hidden parameters
- **ParamSpider** — URL parameter mining

## Bypass Techniques

- **Add uppercase/mixed case**: `isadmin`, `IsAdmin`, `IS_ADMIN`
- **Use array syntax**: `isAdmin[]=true`
- **JSON duplicate keys**: `{"isAdmin": false, "isAdmin": true}` — some parsers use the last value
- **Nested attributes**: `user[isAdmin]=true` when the API uses `params.require(:user).permit(...)`
- **HTTP Parameter Pollution**: Send `isAdmin=false&isAdmin=true`
- **Add to different content types**: JSON body, form-urlencoded, multipart — the framework may parse them differently

### Content-Type Switching

- Switch between JSON, form-encoded, multipart, and `text/plain`; some code paths only validate one content type

### Key Path Variants

- Dot/bracket/object re-shaping to reach nested fields through different binders
- `profile.role`, `profile[role]`, `settings[roles][]`, `user->role`

### Batch Paths

- Per-item checks may be skipped in bulk operations
- Insert a single malicious object within a large batch of legitimate items

### Race and Reorder

- Race two concurrent updates: first sets a forbidden field, second normalizes it
- Final state may retain the forbidden change due to race window

## Not a Finding If

- The framework has a proper whitelist (`$fillable`/`attr_accessible`) that excludes sensitive fields
- The server validates and strips unexpected parameters
- The endpoint only performs read operations (GET)
- Server recomputes derived fields (`plan`/`price`/`role`) ignoring client input
- Fields marked read-only are enforced consistently across all encodings and channels
- Only UI-side changes with no persisted effect (client-side only)

## Notes

- Also known as **Massive Assignment** or **Autobinding**
- Blacklisting (`$guarded`) is weaker than whitelisting — forgetting to add one field to the blacklist can be catastrophic
- Always check the model definition for accessible attributes
- GraphQL mutations with auto-generated input types are particularly prone to mass assignment if not carefully configured

### Pro Tips

- Build a sensitive-field dictionary per resource and fuzz systematically
- Always try alternate shapes and encodings; many validators are shape/content-type specific
- For GraphQL, diff the resource immediately after mutation; effects are often visible even if the mutation returns filtered fields
- Inspect SDKs/mobile apps for hidden field names and nested write examples
- Prefer minimal PoCs that prove durable state changes; avoid UI-only effects

### Impact

- Privilege escalation and admin feature access
- Cross-tenant or cross-account resource takeover
- Financial/billing manipulation and quota abuse
- Policy/approval bypass by toggling verification or status flags

## References

- https://owasp.org/www-community/attacks/Mass_Assignment_Cheat_Sheet
- https://laravel.com/docs/eloquent#mass-assignment
- https://guides.rubyonrails.org/security.html#mass-assignment
- https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

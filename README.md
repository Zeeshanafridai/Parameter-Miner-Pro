# Parameter Miner Pro

> Finds hidden parameters that Burp Suite's Param Miner extension and Arjun miss. Deeper wordlist. Smarter diff engine. Header injection. JSON body mining. Prototype pollution. Path discovery.

Zero dependencies. Pure Python.

---

## What Makes This Different

| Feature | Arjun | Burp Param Miner | This tool |
|---------|-------|-----------------|-----------|
| Query param mining | ✅ | ✅ | ✅ + binary batching |
| Response diff quality | basic | good | ✅ multi-signal scoring |
| HTTP header mining | ❌ | ✅ | ✅ + 80 headers + classification |
| JSON body key mining | partial | partial | ✅ + type variations |
| Prototype pollution | ❌ | ❌ | ✅ |
| Mass assignment | ❌ | ❌ | ✅ |
| Path / endpoint mining | ❌ | ❌ | ✅ 150+ paths |
| API version probing | ❌ | ❌ | ✅ |
| Cache poisoning headers | ❌ | ✅ | ✅ + auto-classified |
| Confidence scoring | ❌ | partial | ✅ 0-100 score |
| Zero dependencies | ✅ | ❌ | ✅ |

---

## Installation

```bash
git clone https://github.com/yourhandle/param-miner-pro
cd param-miner-pro
python3 param_miner.py --help
```

---

## Usage

### Full scan (all techniques)
```bash
python3 param_miner.py -u "https://target.com/api/user?id=1"
```

### Authenticated scan
```bash
python3 param_miner.py -u "https://target.com/api/user" -c "session=abc123"
```

### POST JSON endpoint
```bash
python3 param_miner.py \
  -u "https://target.com/api/users/create" \
  -m POST \
  -d '{"username":"test","email":"test@test.com"}' \
  -c "session=TOKEN"
```

### Header mining only (cache poisoning focus)
```bash
python3 param_miner.py -u "https://target.com/" --checks headers
```

### Path discovery only
```bash
python3 param_miner.py -u "https://target.com" --checks paths --versions
```

### Custom wordlist + lower threshold (more sensitive)
```bash
python3 param_miner.py -u "https://target.com/api" \
  -w my_wordlist.txt \
  --threshold 15
```

### Full scan + report
```bash
python3 param_miner.py -u "https://target.com/api" \
  -c "session=TOKEN" \
  -m POST \
  --checks query headers json paths \
  --versions \
  --report \
  -o results.json
```

---

## Detection Techniques

### Query Parameter Mining
- Sends params in batches of 25 (fast)
- Multi-signal diff: size, similarity, status, structure, reflection
- Binary narrowing on batch hits
- Double-confirms with second canary value

### HTTP Header Mining (80+ headers)
- Finds: cache poisoning headers, auth bypass headers, debug headers
- Auto-classifies finding type:
  - `cache_poisoning` — X-Forwarded-Host, X-Host, etc.
  - `privilege_escalation` — X-Role, X-User-ID, X-Admin
  - `debug_disclosure` — X-Debug, X-Dev-Mode
  - `ip_bypass` — X-Forwarded-For, True-Client-IP
  - `method_override` — X-HTTP-Method-Override

### JSON Body Mining
- Tests hidden JSON keys: `isAdmin`, `debugMode`, `role`, `bypass`, etc.
- Type variations: string, bool, null, int
- **Prototype pollution**: `__proto__`, `constructor`, `prototype`
- **Mass assignment**: `admin=true`, `role=admin`, `premium=true`

### Path / Endpoint Mining (150+ paths)
- Admin panels: `/admin`, `/backstage`, `/cp`
- Debug endpoints: `/debug`, `/actuator/env`, `/actuator/beans`
- API docs: `/swagger`, `/graphql`, `/openapi.json`
- Secrets: `/.env`, `/.git/config`
- API versions: `/api/v1` through `/api/v10`

---

## Confidence Scoring

Every finding gets a 0-100 confidence score:

| Score | Meaning |
|-------|---------|
| 60-100 | Canary value reflected in response — near certain |
| 40-59  | Status changed OR large body diff |
| 25-39  | Significant similarity drop or structural change |
| 0-24   | Noise — filtered out |

---

## Bug Bounty Use Cases

```
Finding            Impact
─────────────────────────────────────────────────────
X-Forwarded-Host   Cache poisoning, password reset hijack
X-Original-URL     Access control bypass (403→200)
X-Debug: true      Stack traces, internal paths, secrets
debug=true         Admin panel exposure, verbose errors
isAdmin=true       Privilege escalation via mass assignment
__proto__          Prototype pollution → RCE in some stacks
/actuator/env      Spring Boot secret exposure
/.env              Database credentials, API keys
/api/v1 (old)      Older API with missing auth checks
```

## License
MIT — For authorized testing only.

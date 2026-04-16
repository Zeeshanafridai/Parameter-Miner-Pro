"""
Technique: HTTP Header Mining
--------------------------------
Discovers hidden headers that change server behavior.

High-value header findings:
  - X-Forwarded-Host → cache poisoning, password reset poisoning
  - X-Original-URL / X-Rewrite-URL → access control bypass
  - X-HTTP-Method-Override → PUT/DELETE bypass
  - X-Debug / X-Dev-Mode → debug info disclosure
  - X-Role / X-User-ID → privilege escalation
  - X-Internal → bypass IP restrictions
  - X-Api-Version → older/vulnerable API versions
  - X-Forwarded-For → IP-based auth bypass
  - Host header injection → SSRF, cache poisoning
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from ..core import (request, ResponseDiff, CANARY_VALUE,
                    R, G, Y, C, DIM, BOLD, RST)
from ..wordlists.params import HEADER_PARAMS, CACHE_PARAMS

# Extra headers not in main list
EXTENDED_HEADERS = [
    # Debug / internal
    "X-Debug", "X-Debug-Mode", "X-Dev", "X-Dev-Mode",
    "X-Development", "X-Testing", "X-Internal", "X-Private",
    "X-Admin", "X-Super-Admin", "X-Admin-Mode",
    "X-Verbose", "X-Trace", "X-Profile",

    # Auth bypass
    "X-Role", "X-User-Role", "X-User-Type",
    "X-User-ID", "X-Authenticated-User", "X-Username",
    "X-Auth-User", "X-Authenticated", "X-Bypass-Auth",
    "X-Remote-User", "X-WEBAUTH-USER",
    "X-Forwarded-User", "X-Auth-Request-User",
    "X-Consumer-Username", "X-Consumer-Groups",

    # IP/rate limit bypass
    "X-Forwarded-For", "X-Real-IP", "X-Client-IP",
    "X-Original-IP", "X-Remote-IP", "Client-IP",
    "True-Client-IP", "CF-Connecting-IP",
    "X-Cluster-Client-IP", "Fastly-Client-IP",
    "X-Azure-ClientIP", "X-Appengine-User-IP",

    # Cache / CDN
    "X-Forwarded-Host", "X-Original-Host", "X-Host",
    "X-Forwarded-Server", "X-Forwarded-Proto",
    "Forwarded", "CDN-Loop", "Via",
    "X-Cache-Key", "X-Cache-Tags", "Surrogate-Key",

    # Method override
    "X-HTTP-Method-Override", "X-Method-Override",
    "X-HTTP-Method", "_method", "X-Override",

    # API / versioning
    "X-Api-Version", "X-API-Version", "API-Version",
    "X-Version", "Version", "Accept-Version",
    "X-Api-Key", "X-API-KEY", "X-Auth-Token",

    # Misc interesting
    "X-Request-ID", "X-Correlation-ID", "X-Trace-ID",
    "X-B3-TraceId", "X-B3-SpanId",
    "X-Amzn-Trace-Id", "X-Cloud-Trace-Context",
    "X-Tenant-ID", "X-Organization-ID", "X-Workspace-ID",
    "X-Feature-Flag", "X-Beta", "X-Experiment",
    "X-CSRF-Token", "X-XSRF-Token",
]

# All unique headers
ALL_HEADERS = list(dict.fromkeys(HEADER_PARAMS + CACHE_PARAMS + EXTENDED_HEADERS))


def _test_header(url: str, header_name: str, header_value: str,
                  baseline: dict, cookies: str, method: str) -> dict:
    """Test a single header injection."""
    resp = request(url, method=method,
                    headers={header_name: header_value},
                    cookies=cookies)

    diff = ResponseDiff(baseline, resp, header_value)

    if not diff.is_significant(threshold=20):
        return {}

    # Confirm with different value
    alt_value = "z33alt-header-test"
    resp2 = request(url, method=method,
                     headers={header_name: alt_value},
                     cookies=cookies)
    diff2 = ResponseDiff(baseline, resp2, alt_value)

    score = max(diff.score(), diff2.score())
    if score < 20:
        return {}

    # Classify the finding type
    finding_type = _classify_header_finding(header_name, diff, resp)

    return {
        "param":        header_name,
        "location":     "header",
        "method":       method,
        "score":        score,
        "diff":         diff.summary(),
        "finding_type": finding_type,
        "severity":     _header_severity(header_name, finding_type),
        "canary_reflected": diff.canary_reflected,
        "status_changed":   diff.status_changed,
        "evidence":     {
            "status":         resp["status"],
            "canary_reflected": diff.canary_reflected,
            "new_content":    list(diff.new_interesting.keys()),
        }
    }


def _classify_header_finding(header: str, diff: ResponseDiff, resp: dict) -> str:
    h = header.lower()
    if any(x in h for x in ["host", "forwarded-host", "original-host"]):
        return "cache_poisoning"
    if any(x in h for x in ["method-override", "http-method", "_method"]):
        return "method_override"
    if any(x in h for x in ["debug", "dev", "verbose", "trace", "internal"]):
        return "debug_disclosure"
    if any(x in h for x in ["role", "user-id", "authenticated", "auth", "bypass"]):
        return "privilege_escalation"
    if any(x in h for x in ["forwarded-for", "real-ip", "client-ip", "true-client"]):
        return "ip_bypass"
    if any(x in h for x in ["api-version", "version", "api-key"]):
        return "api_versioning"
    if any(x in h for x in ["tenant", "organization", "workspace"]):
        return "tenant_confusion"
    if diff.canary_reflected:
        return "header_injection"
    return "behavior_change"


def _header_severity(header: str, finding_type: str) -> str:
    high_types = {"cache_poisoning", "privilege_escalation", "debug_disclosure"}
    high_headers = {"x-forwarded-host", "x-original-url", "x-rewrite-url",
                     "x-http-method-override", "x-role", "x-user-id",
                     "x-authenticated", "x-admin", "x-debug"}
    h = header.lower()
    if finding_type in high_types or h in high_headers:
        return "High"
    return "Medium"


def mine(url: str, baseline: dict, wordlist: list = None,
          cookies: str = None, method: str = "GET",
          threads: int = 15, canary: str = CANARY_VALUE,
          verbose: bool = True) -> list:
    """
    Mine for hidden HTTP headers.
    """
    headers_to_test = wordlist or ALL_HEADERS

    if verbose:
        print(f"\n  {C}[HEADERS]{RST} Testing {len(headers_to_test)} headers "
              f"| {threads} threads")

    confirmed = []
    done = 0

    def test(header_name):
        return _test_header(url, header_name, canary, baseline, cookies, method)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(test, h): h for h in headers_to_test}
        for future in as_completed(futures):
            result = future.result()
            done += 1
            if result:
                confirmed.append(result)
                if verbose:
                    sev_color  = R if result["severity"] == "High" else Y
                    ftype      = result.get("finding_type", "")
                    print(f"  {G}[+]{RST} {sev_color}{result['param']}{RST} "
                          f"({ftype}) score:{result['score']}")
            elif verbose and done % 20 == 0:
                print(f"  {DIM}[{done}/{len(headers_to_test)}]{RST}",
                      end="\r")

    if verbose:
        print(f"\r{' '*50}\r", end="")
        print(f"  {G}[✓]{RST} Headers confirmed: {len(confirmed)}\n")

    return confirmed

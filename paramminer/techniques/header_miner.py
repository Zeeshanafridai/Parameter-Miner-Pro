"""
Header Parameter Miner
------------------------
Discovers hidden/undocumented HTTP headers that change server behavior.

Categories:
  - Cache poisoning headers (X-Forwarded-Host, X-Original-URL...)
  - IP spoofing headers (X-Forwarded-For, True-Client-IP...)
  - Debug-enabling headers (X-Debug, X-Dev-Mode...)
  - Routing headers (X-Original-URL, X-Rewrite-URL...)
  - Authentication bypass headers (X-Forwarded-User, X-Remote-User...)
  - Host header injection
  - HTTP request smuggling headers (Transfer-Encoding, Content-Length...)
"""

import time
from ..core import http_get, deep_diff, R, G, Y, C, DIM, BOLD, RST
from ..wordlists.params import HEADERS

# Extended header list with categories
HEADER_CATEGORIES = {
    "Cache Poisoning": [
        "X-Forwarded-Host",
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Override-URL",
        "X-Forwarded-Scheme",
        "X-Forwarded-Proto",
        "X-Forwarded-Port",
        "Forwarded",
        "X-Host",
        "X-Forwarded-Server",
        "X-HTTP-Host-Override",
    ],
    "IP Spoofing": [
        "X-Forwarded-For",
        "X-Real-IP",
        "X-Client-IP",
        "X-Remote-IP",
        "X-Remote-Addr",
        "X-Originating-IP",
        "True-Client-IP",
        "CF-Connecting-IP",
        "X-Cluster-Client-IP",
        "Fastly-Client-IP",
        "X-Custom-IP-Authorization",
        "X-ProxyUser-Ip",
        "Client-IP",
        "X-Original-Forwarded-For",
    ],
    "Auth Bypass": [
        "X-Forwarded-User",
        "X-Remote-User",
        "X-Auth-User",
        "X-User",
        "X-Username",
        "X-Authenticated-User",
        "X-Authenticated-Userid",
        "X-Admin",
        "X-Internal",
        "X-Internal-Request",
        "X-Bypass",
        "X-Authenticated",
        "Authorization",
        "X-Auth-Token",
        "X-Access-Token",
        "X-API-Key",
        "X-Api-Key",
        "Api-Key",
    ],
    "Debug / Dev": [
        "X-Debug",
        "X-Debug-Token",
        "X-Dev-Mode",
        "X-Development",
        "X-Test",
        "X-Testing",
        "X-Profiler",
        "X-Profile",
        "X-Flamegraph",
        "X-Trace",
        "X-Verbose",
        "Symfony-Debug",
        "Laravel-Debug",
        "X-XHPROF",
    ],
    "Routing": [
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Request-URI",
        "X-HTTP-Method-Override",
        "X-Method-Override",
        "_method",
        "X-Destination",
        "Destination",
        "X-Backend",
        "X-Service",
        "X-Microservice",
    ],
    "Cache Control": [
        "Cache-Control",
        "Pragma",
        "X-Cache",
        "Surrogate-Control",
        "CDN-Cache-Control",
        "Cloudflare-CDN-Cache-Control",
        "Fastly-Debug-Digest",
        "X-Cache-Key",
        "Vary",
        "Age",
    ],
    "Request Smuggling": [
        "Transfer-Encoding",
        "Content-Length",
        "Content-Encoding",
        "TE",
        "Trailer",
    ],
    "Misc Interesting": [
        "X-CSRF-Token",
        "X-Requested-With",
        "X-Correlation-ID",
        "X-Request-ID",
        "X-Trace-ID",
        "X-Session-Token",
        "X-Instance-ID",
        "X-Version",
        "X-Client-Version",
        "X-App-Version",
        "Accept-Version",
        "X-Feature-Flag",
        "X-Experiment",
        "X-AB-Test",
        "X-Preview",
        "X-Staging",
        "X-Environment",
        "X-Region",
        "X-Datacenter",
    ],
}

# High-value test values for headers
HEADER_TEST_VALUES = {
    "X-Forwarded-For":      ["127.0.0.1", "0.0.0.0", "::1", "169.254.169.254"],
    "X-Forwarded-Host":     ["localhost", "127.0.0.1", "internal.service"],
    "X-Original-URL":       ["/admin", "/internal", "/debug", "/.env"],
    "X-Rewrite-URL":        ["/admin", "/internal"],
    "X-Debug":              ["1", "true", "enabled"],
    "X-Dev-Mode":           ["1", "true", "enabled"],
    "X-Admin":              ["1", "true"],
    "X-Internal":           ["1", "true"],
    "X-HTTP-Method-Override":["PUT", "DELETE", "PATCH"],
    "X-Method-Override":    ["PUT", "DELETE"],
    "X-Forwarded-Proto":    ["http", "https"],
    "X-Auth-Token":         ["admin", "test", "bypass"],
}

DEFAULT_TEST_VALUE = "z33test"


def mine_headers(url: str, baseline: dict,
                  cookies: str = None, extra_headers: dict = None,
                  categories: list = None, verbose: bool = True) -> list:
    """
    Test all headers and return those that cause response differences.
    """
    findings = []
    base_headers = extra_headers or {}

    cats_to_test = categories or list(HEADER_CATEGORIES.keys())
    all_headers  = []
    for cat in cats_to_test:
        all_headers.extend(HEADER_CATEGORIES.get(cat, []))

    total = len(all_headers)

    if verbose:
        print(f"\n  {C}[HEADER MINING]{RST} Testing {total} headers across "
              f"{len(cats_to_test)} categories")

    for i, header_name in enumerate(all_headers):
        test_values = HEADER_TEST_VALUES.get(header_name, [DEFAULT_TEST_VALUE])

        for test_val in test_values[:2]:  # test first 2 values per header
            test_headers = {**base_headers, header_name: test_val}
            resp = http_get(url, headers=test_headers, cookies=cookies)
            diff = deep_diff(baseline, resp)

            if diff["significant"] or diff["status_diff"]:
                finding = {
                    "type":        "header",
                    "name":        header_name,
                    "value_tested":test_val,
                    "category":    _get_category(header_name),
                    "diff":        diff,
                    "status":      resp["status"],
                    "confidence":  diff["confidence"],
                    "detail":      _describe_header_finding(header_name, diff, resp),
                }
                findings.append(finding)

                if verbose:
                    sev = f"{R}{BOLD}" if diff["confidence"] > 70 else Y
                    print(f"\r{' '*70}\r  {sev}[HEADER]{RST} {header_name}: {test_val} "
                          f"→ {_describe_header_finding(header_name, diff, resp)}")
                break  # found for this header — move on

        if verbose and i % 10 == 0:
            pct = (i / total) * 100
            print(f"  {DIM}[{pct:5.1f}%] {i}/{total} headers tested...{RST}", end="\r")

    if verbose:
        print(f"\r{' '*60}\r", end="")
        if findings:
            print(f"  {G}[+]{RST} {len(findings)} interesting header(s) found\n")
        else:
            print(f"  {DIM}[-] No interesting headers found{RST}\n")

    return findings


def _get_category(header_name: str) -> str:
    for cat, headers in HEADER_CATEGORIES.items():
        if header_name in headers:
            return cat
    return "Unknown"


def _describe_header_finding(header_name: str, diff: dict, resp: dict) -> str:
    parts = []
    if diff["status_diff"]:
        parts.append(f"status changed → {resp['status']}")
    if abs(diff["size_diff"]) > 100:
        parts.append(f"size diff {diff['size_diff']:+d}")
    if diff["interesting"].get("redirect"):
        parts.append(f"redirects → {resp.get('location', '')[:40]}")
    if diff["interesting"].get("error"):
        parts.append("error in response")
    if diff["interesting"].get("debug"):
        parts.append("debug content exposed")
    if diff["interesting"].get("new_cookie"):
        parts.append("new cookie set")
    return " | ".join(parts) if parts else f"confidence {diff['confidence']}%"

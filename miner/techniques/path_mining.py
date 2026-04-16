"""
Technique: Path Parameter + REST Endpoint Mining
--------------------------------------------------
Discovers hidden URL path segments and REST-style parameters.

Finds:
  - Hidden endpoints: /api/admin, /api/internal, /api/debug
  - Path parameter injection: /api/users/{id}/role
  - Version discrepancies: /api/v1/ vs /api/v2/
  - Hidden API namespaces: /internal/, /private/, /staff/
  - GraphQL endpoints
  - File/extension tricks: .json, .xml, .debug
"""

import urllib.parse
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from ..core import (request, ResponseDiff, R, G, Y, C, DIM, BOLD, RST)

# High-value path segments to probe
HIDDEN_PATHS = [
    # Admin / internal
    "/admin", "/admin/", "/administrator",
    "/internal", "/internal/", "/private",
    "/staff", "/staff/", "/manage", "/management",
    "/superuser", "/root", "/su",
    "/backstage", "/backend", "/backoffice",
    "/cp", "/controlpanel", "/control",
    "/panel", "/dashboard", "/console",

    # Debug / dev
    "/debug", "/debug/", "/dev", "/development",
    "/test", "/testing", "/staging",
    "/beta", "/alpha", "/preview",
    "/profiler", "/benchmark", "/status",
    "/health", "/healthcheck", "/ping",
    "/metrics", "/stats", "/statistics",

    # API discovery
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
    "/api/admin", "/api/internal", "/api/debug",
    "/api/users", "/api/user", "/api/accounts",
    "/api/keys", "/api/tokens", "/api/secrets",
    "/api/config", "/api/settings", "/api/env",
    "/api/logs", "/api/audit", "/api/events",
    "/v1", "/v2", "/v3", "/v4",
    "/rest", "/rest/v1", "/rest/v2",
    "/graphql", "/gql", "/query",

    # Docs / schema
    "/swagger", "/swagger-ui", "/swagger-ui.html",
    "/swagger.json", "/swagger.yaml",
    "/openapi", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api/docs", "/docs",
    "/redoc", "/rapidoc",
    "/wsdl", "/wadl",

    # Config / secrets exposure
    "/.env", "/.env.local", "/.env.production",
    "/config", "/config.json", "/config.yaml",
    "/settings.json", "/app.config",
    "/.git", "/.git/config", "/.git/HEAD",
    "/.svn", "/.hg",
    "/robots.txt", "/sitemap.xml",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/.well-known/security.txt",

    # Monitoring / observability
    "/actuator", "/actuator/", "/actuator/env",
    "/actuator/health", "/actuator/metrics",
    "/actuator/beans", "/actuator/configprops",
    "/actuator/mappings", "/actuator/httptrace",
    "/actuator/loggers", "/actuator/threaddump",
    "/jolokia", "/jolokia/exec",
    "/trace", "/dump", "/heapdump",
    "/env", "/beans", "/mappings",
    "/__debug__", "/_debug", "/_status",
    "/_health", "/_metrics", "/_version",
    "/nginx_status", "/server-status", "/server-info",

    # File extensions on existing path
    ".json", ".xml", ".yaml", ".csv",
    ".debug", ".test", ".bak", ".old", ".tmp",
]

# API versioning patterns
VERSION_PATTERNS = [
    "/api/v{n}", "/v{n}", "/api/{n}", "/{n}",
]


def _test_path(base_url: str, path: str,
                baseline_status: int,
                cookies: str = None) -> dict:
    """Test a single path and return finding if interesting."""
    parsed  = urllib.parse.urlparse(base_url)
    test_url = f"{parsed.scheme}://{parsed.netloc}{path}"

    resp = request(test_url, cookies=cookies)

    # Interesting if different from baseline behavior
    interesting = False
    reason      = ""

    if resp["status"] == 200:
        interesting = True
        reason = "200 OK — endpoint exists"
    elif resp["status"] in (301, 302, 307, 308):
        interesting = True
        reason = f"Redirect to: {resp['redirect_loc']}"
    elif resp["status"] == 401:
        interesting = True
        reason = "401 Unauthorized — exists but requires auth"
    elif resp["status"] == 403:
        interesting = True
        reason = "403 Forbidden — exists but access denied"
    elif resp["status"] == 405:
        interesting = True
        reason = "405 Method Not Allowed — exists but wrong method"
    elif resp["status"] == 500:
        interesting = True
        reason = "500 Server Error — may indicate interesting endpoint"

    if not interesting:
        return {}

    # Extra checks for high-value paths
    body_lower = resp["body"].lower()
    severity   = "Info"

    if any(x in path for x in ["/admin", "/internal", "/private", "/.env",
                                  "/actuator", "/debug", "/config"]):
        severity = "High"
    elif any(x in path for x in ["/api/", "/graphql", "/swagger", "/openapi"]):
        severity = "Medium"

    has_secrets = bool(re.search(
        r"password|secret|api_key|token|private_key|aws_|database_url",
        body_lower
    ))
    if has_secrets:
        severity = "Critical"
        reason += " — SENSITIVE DATA IN RESPONSE"

    return {
        "param":    path,
        "location": "path",
        "method":   "GET",
        "score":    80 if severity == "Critical" else
                    60 if severity == "High" else
                    40 if severity == "Medium" else 20,
        "status":   resp["status"],
        "severity": severity,
        "reason":   reason,
        "url":      test_url,
        "body_snippet": resp["body"][:300] if resp["status"] == 200 else "",
        "has_secrets": has_secrets,
    }


def mine_paths(url: str, baseline: dict = None,
                cookies: str = None, wordlist: list = None,
                threads: int = 20, verbose: bool = True) -> list:
    """Discover hidden paths and endpoints."""
    paths_to_test = wordlist or HIDDEN_PATHS
    baseline_status = baseline["status"] if baseline else 404

    if verbose:
        print(f"\n  {C}[PATH MINING]{RST} Testing {len(paths_to_test)} "
              f"paths | {threads} threads")

    confirmed = []
    done = 0

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(_test_path, url, p, baseline_status, cookies): p
                   for p in paths_to_test}
        for future in as_completed(futures):
            result = future.result()
            done  += 1
            if result:
                confirmed.append(result)
                if verbose:
                    sev_map = {"Critical": R+BOLD, "High": R, "Medium": Y, "Info": DIM}
                    col     = sev_map.get(result["severity"], "")
                    print(f"  {G}[+]{RST} {col}{result['status']}{RST} "
                          f"{result['param']} — {result['reason'][:60]}")
            elif verbose and done % 30 == 0:
                print(f"  {DIM}[{done}/{len(paths_to_test)}]{RST}", end="\r")

    if verbose:
        print(f"\r{' '*50}\r", end="")
        print(f"  {G}[✓]{RST} Paths found: {len(confirmed)}\n")

    return confirmed


def mine_api_versions(url: str, cookies: str = None,
                       max_version: int = 10,
                       verbose: bool = True) -> list:
    """Probe API version endpoints."""
    findings = []
    parsed   = urllib.parse.urlparse(url)
    base     = f"{parsed.scheme}://{parsed.netloc}"

    versions_to_try = []
    for n in range(0, max_version + 1):
        versions_to_try.extend([
            f"{base}/api/v{n}",
            f"{base}/api/v{n}/",
            f"{base}/v{n}",
            f"{base}/v{n}/",
            f"{base}/api/{n}.{0}",
        ])

    for test_url in versions_to_try:
        resp = request(test_url, cookies=cookies)
        if resp["status"] not in (404, 0):
            findings.append({
                "param":    test_url.replace(base, ""),
                "location": "api_version",
                "method":   "GET",
                "url":      test_url,
                "status":   resp["status"],
                "score":    40,
                "severity": "Medium",
                "reason":   f"API version endpoint exists (HTTP {resp['status']})",
            })
            if verbose:
                print(f"  {Y}[+]{RST} API version: {test_url} [{resp['status']}]")

    return findings

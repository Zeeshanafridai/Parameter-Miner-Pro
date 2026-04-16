"""
Parameter Fuzzer
-----------------
The engine that actually sends probes and detects hidden params.

Strategy:
  1. Establish a stable baseline (3 requests)
  2. Send params in batches — reduces request count dramatically
  3. If batch shows diff → bisect to find exact param
  4. Confirm candidate with 2 additional requests
  5. Test for reflection, error trigger, redirect, timing

Batch size: 30 params per request (canary = unique value per param)
Unique canary values let us pinpoint which param in a batch responded.
"""

import time
import threading
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from ..core import http_get, http_post, deep_diff, build_probe_url, R, G, Y, C, DIM, BOLD, RST

# Canary prefix — unique enough to detect reflection
CANARY_PREFIX = "z33x"


def _make_canary(param_name: str, batch_id: int) -> str:
    """Generate a unique canary value for a parameter."""
    return f"{CANARY_PREFIX}{abs(hash(param_name)) % 9999:04d}{batch_id}"


def _build_batch_url(base_url: str, params: list, batch_id: int) -> tuple:
    """
    Build a URL with all params in batch appended.
    Returns (url, {param: canary_value})
    """
    canary_map = {p: _make_canary(p, batch_id) for p in params}
    qs_parts   = "&".join(f"{p}={v}" for p, v in canary_map.items())
    sep        = "&" if "?" in base_url else "?"
    return f"{base_url}{sep}{qs_parts}", canary_map


def _build_batch_body(existing_data: dict, params: list, batch_id: int,
                       content_type: str = "form") -> tuple:
    """Build POST body with batch params injected."""
    import json, urllib.parse
    canary_map = {p: _make_canary(p, batch_id) for p in params}
    combined   = {**(existing_data or {}), **canary_map}

    if content_type == "json":
        return json.dumps(combined), canary_map
    else:
        return urllib.parse.urlencode(combined), canary_map


def _check_reflection(response_body: str, canary_map: dict) -> list:
    """Check which canary values are reflected in the response."""
    reflected = []
    for param, canary in canary_map.items():
        if canary in response_body:
            reflected.append(param)
    return reflected


def get_stable_baseline(url: str, method: str = "GET",
                          body: str = None, content_type: str = "form",
                          cookies: str = None, headers: dict = None,
                          samples: int = 3) -> dict:
    """
    Get a stable baseline by averaging multiple requests.
    Returns the most representative response.
    """
    responses = []
    for _ in range(samples):
        if method.upper() == "GET":
            r = http_get(url, headers=headers, cookies=cookies)
        else:
            import urllib.parse
            data = dict(urllib.parse.parse_qsl(body or ""))
            r = http_post(url, data=data if content_type == "form" else None,
                          json_body=data if content_type == "json" else None,
                          headers=headers, cookies=cookies)
        responses.append(r)
        time.sleep(0.15)

    # Use median-length response as baseline
    responses.sort(key=lambda x: x["body_length"])
    return responses[len(responses) // 2]


def probe_batch(url: str, params: list, baseline: dict,
                batch_id: int, method: str = "GET",
                body_str: str = None, content_type: str = "form",
                cookies: str = None, headers: dict = None,
                threshold: int = 25) -> dict:
    """
    Send one batch of params and check for response differences.
    Returns dict: {significant: bool, diff: dict, canary_map: dict, reflected: list}
    """
    import json, urllib.parse

    if method.upper() == "GET":
        test_url, canary_map = _build_batch_url(url, params, batch_id)
        resp = http_get(test_url, headers=headers, cookies=cookies)
    else:
        body_data = dict(urllib.parse.parse_qsl(body_str or ""))
        combined  = {**body_data}
        canary_map = {p: _make_canary(p, batch_id) for p in params}
        combined.update(canary_map)

        if content_type == "json":
            resp = http_post(url, json_body=combined,
                              headers=headers, cookies=cookies)
        else:
            resp = http_post(url, data=combined,
                              headers=headers, cookies=cookies)

    diff      = deep_diff(baseline, resp)
    reflected = _check_reflection(resp["body"], canary_map)

    # Mark as significant if diff confidence is above threshold or reflection found
    significant = diff["confidence"] >= threshold or bool(reflected)

    return {
        "significant": significant,
        "diff":        diff,
        "canary_map":  canary_map,
        "reflected":   reflected,
        "response":    resp,
    }


def bisect_batch(url: str, params: list, baseline: dict,
                  batch_id: int, method: str, body_str: str,
                  content_type: str, cookies: str, headers: dict,
                  threshold: int, depth: int = 0) -> list:
    """
    Recursively bisect a batch to find which specific param caused the diff.
    """
    if depth > 6 or not params:
        return []

    if len(params) == 1:
        # Confirm single param
        result = probe_batch(url, params, baseline, batch_id + depth * 100,
                              method, body_str, content_type, cookies, headers, threshold)
        if result["significant"] or result["reflected"]:
            return params
        return []

    mid   = len(params) // 2
    left  = params[:mid]
    right = params[mid:]

    found = []

    for half in [left, right]:
        result = probe_batch(url, half, baseline, batch_id + depth * 100,
                              method, body_str, content_type, cookies, headers, threshold)
        if result["significant"] or result["reflected"]:
            if len(half) == 1:
                found.extend(half)
            else:
                found.extend(bisect_batch(url, half, baseline,
                                           batch_id, method, body_str,
                                           content_type, cookies, headers,
                                           threshold, depth + 1))

    return found


class ParamFuzzer:
    """Main parameter fuzzer — orchestrates batch probing and bisection."""

    def __init__(self, url: str, method: str = "GET",
                  body: str = None, content_type: str = "form",
                  cookies: str = None, headers: dict = None,
                  batch_size: int = 30, threads: int = 10,
                  threshold: int = 25, verbose: bool = True,
                  delay: float = 0.0):
        self.url          = url
        self.method       = method.upper()
        self.body         = body
        self.content_type = content_type
        self.cookies      = cookies
        self.headers      = headers or {}
        self.batch_size   = batch_size
        self.threads      = threads
        self.threshold    = threshold
        self.verbose      = verbose
        self.delay        = delay

        self.baseline     = None
        self.findings     = []
        self._lock        = threading.Lock()
        self._tested      = 0
        self._total       = 0

    def _print_progress(self, tested: int, total: int, found: int):
        pct = (tested / max(total, 1)) * 100
        bar_w = 30
        filled = int(bar_w * tested / max(total, 1))
        bar = "█" * filled + "░" * (bar_w - filled)
        sys.stdout.write(
            f"\r  {DIM}[{bar}]{RST} {pct:5.1f}% "
            f"({tested}/{total}) {G}found:{found}{RST}  "
        )
        sys.stdout.flush()

    def establish_baseline(self):
        if self.verbose:
            print(f"  {C}[*]{RST} Establishing baseline ({3} samples)...")

        self.baseline = get_stable_baseline(
            self.url, self.method, self.body,
            self.content_type, self.cookies, self.headers
        )

        if self.verbose:
            print(f"  {DIM}    Status: {self.baseline['status']} | "
                  f"Length: {self.baseline['body_length']} | "
                  f"Time: {self.baseline['elapsed']}s{RST}")

    def fuzz(self, param_list: list) -> list:
        """
        Fuzz all params in param_list.
        Returns list of confirmed hidden parameters.
        """
        if not self.baseline:
            self.establish_baseline()

        self._total   = len(param_list)
        self._tested  = 0
        self.findings = []

        # Create batches
        batches = [param_list[i:i + self.batch_size]
                   for i in range(0, len(param_list), self.batch_size)]

        if self.verbose:
            print(f"\n  {C}[FUZZING]{RST} {self._total} params in "
                  f"{len(batches)} batches of {self.batch_size}")
            print(f"  {DIM}  Threads: {self.threads} | "
                  f"Threshold: {self.threshold} | "
                  f"Batch bisection enabled{RST}\n")

        def process_batch(batch_data):
            batch, bid = batch_data
            result = probe_batch(
                self.url, batch, self.baseline, bid,
                self.method, self.body, self.content_type,
                self.cookies, self.headers, self.threshold
            )

            found_in_batch = []

            if result["significant"] or result["reflected"]:
                if len(batch) == 1:
                    found_in_batch = batch
                elif result["reflected"]:
                    found_in_batch = result["reflected"]
                else:
                    # Bisect to find exact param
                    found_in_batch = bisect_batch(
                        self.url, batch, self.baseline, bid,
                        self.method, self.body, self.content_type,
                        self.cookies, self.headers, self.threshold
                    )

            with self._lock:
                self._tested += len(batch)
                for p in found_in_batch:
                    if p not in self.findings:
                        self.findings.append(p)
                        if self.verbose:
                            print(f"\r{' '*80}\r  {G}{BOLD}[FOUND]{RST} {p}")

                if self.verbose:
                    self._print_progress(self._tested, self._total,
                                          len(self.findings))

            if self.delay:
                time.sleep(self.delay)

            return found_in_batch

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(process_batch, (batch, i))
                       for i, batch in enumerate(batches)]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass

        if self.verbose:
            print(f"\r{' '*80}\r")
            print(f"  {G}[+]{RST} Fuzzing complete: "
                  f"{len(self.findings)} hidden param(s) found "
                  f"from {self._total} candidates\n")

        return self.findings

    def confirm_and_detail(self, param_name: str) -> dict:
        """
        Send a dedicated confirmation request for a single param
        and build a detailed finding.
        """
        import urllib.parse

        canary = _make_canary(param_name, 9999)

        if self.method == "GET":
            sep = "&" if "?" in self.url else "?"
            test_url = f"{self.url}{sep}{param_name}={canary}"
            resp = http_get(test_url, headers=self.headers, cookies=self.cookies)
        else:
            body_data = dict(urllib.parse.parse_qsl(self.body or ""))
            body_data[param_name] = canary
            if self.content_type == "json":
                import json
                resp = http_post(self.url, json_body=body_data,
                                  headers=self.headers, cookies=self.cookies)
            else:
                resp = http_post(self.url, data=body_data,
                                  headers=self.headers, cookies=self.cookies)

        diff      = deep_diff(self.baseline, resp)
        reflected = canary in resp["body"]

        # Test for interesting behaviors with different values
        behaviors = []
        for test_val, behavior in [
            ("1",             "integer"),
            ("true",          "boolean"),
            ("admin",         "privilege_keyword"),
            ("' OR 1=1--",    "sqli_probe"),
            ("<script>",      "xss_probe"),
            ("../etc/passwd", "traversal_probe"),
        ]:
            if self.method == "GET":
                sep = "&" if "?" in self.url else "?"
                burl = f"{self.url}{sep}{param_name}={test_val}"
                br = http_get(burl, headers=self.headers, cookies=self.cookies)
            else:
                bd = {**(dict(urllib.parse.parse_qsl(self.body or ""))),
                      param_name: test_val}
                br = http_post(self.url,
                                data=bd if self.content_type != "json" else None,
                                json_body=bd if self.content_type == "json" else None,
                                headers=self.headers, cookies=self.cookies)

            beh_diff = deep_diff(self.baseline, br)
            if beh_diff["significant"] or beh_diff["status_diff"]:
                behaviors.append({
                    "value":     test_val,
                    "behavior":  behavior,
                    "status":    br["status"],
                    "size_diff": beh_diff["size_diff"],
                    "confidence":beh_diff["confidence"],
                })

        return {
            "param":     param_name,
            "reflected": reflected,
            "diff":      diff,
            "behaviors": behaviors,
            "status":    resp["status"],
            "response_snippet": resp["body"][:300],
        }

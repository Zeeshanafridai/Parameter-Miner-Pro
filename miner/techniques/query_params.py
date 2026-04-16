"""
Technique: URL Query Parameter Mining
---------------------------------------
Discovers hidden GET parameters that affect the response.
Uses canary values + response diff engine for accuracy.

Strategy:
  1. Establish stable baseline
  2. Send canary in known-working params first (calibrate diff sensitivity)
  3. Binary batching — send 30 params per request, narrow down hits
  4. Confirm individually — re-test all hits with isolation
  5. Deep-probe confirmed params — extract values, side effects
"""

import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from ..core import (request, ResponseDiff, get_stable_baseline,
                    CANARY_VALUE, R, G, Y, C, DIM, BOLD, RST)
from ..wordlists.params import ALL_PARAMS, DEBUG_PARAMS, AUTH_PARAMS

# How many params to batch per request (balance between speed and accuracy)
BATCH_SIZE = 25


def _send_batch(url: str, param_batch: list, canary: str,
                baseline: dict, cookies: str, headers: dict,
                method: str) -> list:
    """
    Send a batch of params in one request.
    Returns list of param names that caused a significant diff.
    """
    if method.upper() == "GET":
        test_params = {p: canary for p in param_batch}
        resp = request(url, params=test_params, cookies=cookies, headers=headers)
    else:
        test_data = {p: canary for p in param_batch}
        resp = request(url, method=method, data=test_data,
                        cookies=cookies, headers=headers)

    diff = ResponseDiff(baseline, resp, canary)

    if not diff.is_significant(threshold=20):
        return []

    # Something in this batch caused a diff — return all for individual testing
    return param_batch


def _confirm_param(url: str, param: str, canary: str,
                    baseline: dict, cookies: str, headers: dict,
                    method: str, threshold: int = 25) -> dict:
    """
    Test a single parameter in isolation.
    Returns finding dict if confirmed significant.
    """
    if method.upper() == "GET":
        resp = request(url, params={param: canary},
                        cookies=cookies, headers=headers)
    else:
        resp = request(url, method=method,
                        data={param: canary},
                        cookies=cookies, headers=headers)

    diff = ResponseDiff(baseline, resp, canary)

    if not diff.is_significant(threshold):
        return {}

    # Try a second value to confirm it's the param and not luck
    alt_canary = "z33alt9x2"
    if method.upper() == "GET":
        resp2 = request(url, params={param: alt_canary},
                         cookies=cookies, headers=headers)
    else:
        resp2 = request(url, method=method,
                         data={param: alt_canary},
                         cookies=cookies, headers=headers)

    diff2 = ResponseDiff(baseline, resp2, alt_canary)

    # Both values trigger a diff → real parameter
    if diff.is_significant(threshold) or diff2.is_significant(threshold):
        return {
            "param":       param,
            "location":    "query" if method.upper() == "GET" else "body",
            "method":      method,
            "score":       max(diff.score(), diff2.score()),
            "diff":        diff.summary(),
            "canary_reflected": diff.canary_reflected or diff2.canary_reflected,
            "status_changed":   diff.status_changed,
            "evidence":    _collect_evidence(resp, param, canary),
        }

    return {}


def _collect_evidence(resp: dict, param: str, canary: str) -> dict:
    """Extract evidence of why this param matters."""
    body = resp["body"]
    evidence = {}

    # Is canary reflected?
    if canary in body:
        idx = body.find(canary)
        ctx_start = max(0, idx - 50)
        ctx_end   = min(len(body), idx + len(canary) + 50)
        evidence["reflection_context"] = body[ctx_start:ctx_end]

    # Status code
    evidence["status"] = resp["status"]

    # Any interesting headers?
    interesting_headers = ["x-debug", "x-powered-by", "server", "x-version"]
    for h in interesting_headers:
        if h in resp["headers"]:
            evidence[f"header_{h}"] = resp["headers"][h]

    # Body snippet if small diff
    if resp["body_length"] < 5000:
        evidence["body_snippet"] = body[:300]

    return evidence


def mine(url: str, wordlist: list = None, baseline: dict = None,
          cookies: str = None, headers: dict = None,
          method: str = "GET", threads: int = 10,
          batch_size: int = BATCH_SIZE,
          threshold: int = 25, canary: str = CANARY_VALUE,
          verbose: bool = True) -> list:
    """
    Full query parameter mining run.
    Returns list of confirmed parameter findings.
    """
    params_to_test = wordlist or ALL_PARAMS

    if baseline is None:
        baseline = get_stable_baseline(url, method=method,
                                        cookies=cookies, headers=headers)

    if verbose:
        print(f"\n  {C}[QUERY PARAMS]{RST} Testing {len(params_to_test)} params "
              f"in batches of {batch_size} | {threads} threads")

    # Phase 1: Batch scanning
    batches = [params_to_test[i:i+batch_size]
               for i in range(0, len(params_to_test), batch_size)]

    candidate_params = []

    def process_batch(batch):
        hits = _send_batch(url, batch, canary, baseline,
                            cookies, headers, method)
        return hits

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(process_batch, b): b for b in batches}
        done = 0
        for future in as_completed(futures):
            hits = future.result()
            candidate_params.extend(hits)
            done += 1
            if verbose:
                pct = done / len(batches) * 100
                print(f"  {DIM}[{done:03d}/{len(batches)}] "
                      f"Batches scanned — {len(candidate_params)} candidates{RST}",
                      end="\r")

    if verbose:
        print(f"\r{' '*70}\r", end="")
        print(f"  {Y}[*]{RST} Phase 1 complete: {len(candidate_params)} candidates "
              f"from {len(batches)} batches")

    if not candidate_params:
        if verbose:
            print(f"  {DIM}[-] No candidates found{RST}")
        return []

    # Phase 2: Individual confirmation
    if verbose:
        print(f"  {C}[*]{RST} Phase 2: Confirming {len(candidate_params)} candidates...")

    confirmed = []

    def confirm(param):
        time.sleep(0.05)  # small delay to avoid hammering
        return _confirm_param(url, param, canary, baseline,
                               cookies, headers, method, threshold)

    with ThreadPoolExecutor(max_workers=min(threads, 5)) as ex:
        futures = {ex.submit(confirm, p): p for p in candidate_params}
        for future in as_completed(futures):
            result = future.result()
            if result:
                confirmed.append(result)
                if verbose:
                    score_color = R if result["score"] > 60 else Y
                    reflected   = f" {G}[REFLECTED]{RST}" if result["canary_reflected"] else ""
                    print(f"  {G}[+]{RST} {score_color}{result['param']}{RST} "
                          f"(score:{result['score']}){reflected}")

    if verbose:
        print(f"\n  {G}[✓]{RST} Confirmed: {len(confirmed)} hidden parameters\n")

    return confirmed

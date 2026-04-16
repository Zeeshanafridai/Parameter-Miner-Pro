"""
Parameter Miner Pro — Main Orchestrator
"""

import json
import time
import datetime
from .core import http_get, http_post, R, G, Y, C, DIM, BOLD, RST
from .wordlists.params import get_all_params, get_security_params, load_wordlist
from .techniques.response_miner import mine_all
from .techniques.fuzzer import ParamFuzzer
from .techniques.header_miner import mine_headers


def scan(url: str, method: str = "GET",
          body: str = None, content_type: str = "form",
          cookies: str = None, headers: dict = None,
          wordlist_path: str = None, extra_params: list = None,
          batch_size: int = 30, threads: int = 10,
          threshold: int = 25, mine_responses: bool = True,
          test_headers: bool = False, delay: float = 0.0,
          quick: bool = False, verbose: bool = True) -> dict:
    """
    Full parameter mining scan.
    """
    results = {
        "url":           url,
        "method":        method,
        "start_time":    datetime.datetime.utcnow().isoformat(),
        "found_params":  [],
        "found_headers": [],
        "mined_params":  [],
        "total_tested":  0,
        "requests_made": 0,
    }

    if verbose:
        print(f"\n{R}{BOLD}{'═'*60}{RST}")
        print(f"{R}{BOLD}  PARAMETER MINER PRO — Deep Scan{RST}")
        print(f"{R}{BOLD}{'═'*60}{RST}")
        print(f"  {C}Target{RST}   : {url}")
        print(f"  {C}Method{RST}   : {method.upper()}")
        print(f"  {C}Batches{RST}  : {batch_size} params/req | {threads} threads")
        print()

    # Step 1: Fetch page and mine params from response
    if mine_responses:
        if verbose:
            print(f"{Y}[STEP 1] Response Mining{RST}")
        resp = http_get(url, headers=headers, cookies=cookies)
        ct   = resp.get("content_type", "")
        json_body = resp["body"] if "json" in ct else ""
        mined = mine_all(url, resp["body"], json_body, verbose=verbose)
        results["mined_params"] = mined
    else:
        mined = []

    # Step 2: Build param list
    if verbose:
        print(f"{Y}[STEP 2] Building Wordlist{RST}")

    if wordlist_path:
        file_params = load_wordlist(wordlist_path)
        if verbose:
            print(f"  {G}[+]{RST} Loaded {len(file_params)} params from {wordlist_path}")
    else:
        file_params = []

    if quick:
        builtin = get_security_params()
    else:
        builtin = get_all_params()

    # Merge: mined first (most likely to be real), then file, then builtin
    all_params = []
    seen = set()
    for p in (mined + file_params + (extra_params or []) + builtin):
        pk = p.lower()
        if pk not in seen:
            seen.add(pk)
            all_params.append(p)

    if verbose:
        print(f"  {G}[+]{RST} Total unique params to test: {len(all_params)}")
        print(f"      {DIM}(mined:{len(mined)} + file:{len(file_params)} + "
              f"builtin:{len(builtin)}){RST}\n")

    results["total_tested"] = len(all_params)

    # Step 3: Fuzz params
    if verbose:
        print(f"{Y}[STEP 3] Parameter Fuzzing{RST}")

    fuzzer = ParamFuzzer(
        url=url, method=method, body=body, content_type=content_type,
        cookies=cookies, headers=headers, batch_size=batch_size,
        threads=threads, threshold=threshold, verbose=verbose, delay=delay
    )

    found = fuzzer.fuzz(all_params)

    # Step 4: Confirm and detail each finding
    if verbose and found:
        print(f"{Y}[STEP 4] Confirming & Detailing Findings{RST}\n")

    detailed_findings = []
    for param in found:
        if verbose:
            print(f"  {C}[~]{RST} Confirming: {param}")
        detail = fuzzer.confirm_and_detail(param)
        detailed_findings.append(detail)
        if verbose:
            _print_param_detail(detail)

    results["found_params"] = detailed_findings

    # Step 5: Header mining
    if test_headers:
        if verbose:
            print(f"{Y}[STEP 5] Header Mining{RST}")
        header_findings = mine_headers(
            url, fuzzer.baseline, cookies=cookies,
            extra_headers=headers, verbose=verbose
        )
        results["found_headers"] = header_findings

    # Summary
    if verbose:
        _print_summary(results)

    return results


def _print_param_detail(detail: dict):
    param = detail["param"]
    print(f"\n  {G}[+] {param}{RST}")
    if detail["reflected"]:
        print(f"       {Y}Reflected in response{RST}")
    diff = detail["diff"]
    if diff["size_diff"] != 0:
        print(f"       Size diff  : {diff['size_diff']:+d} bytes")
    if diff["status_diff"]:
        print(f"       Status diff: baseline → {detail['status']}")
    if detail["behaviors"]:
        print(f"       Behaviors  :")
        for b in detail["behaviors"][:3]:
            print(f"         val={b['value']:<20} → {b['behavior']} "
                  f"(conf:{b['confidence']}%)")
    if detail.get("response_snippet"):
        snippet = detail["response_snippet"][:100].replace("\n", " ")
        print(f"       Snippet    : {DIM}{snippet}{RST}")
    print()


def _print_summary(results: dict):
    params  = results["found_params"]
    headers = results["found_headers"]

    print(f"\n{R}{BOLD}{'═'*60}{RST}")
    print(f"{R}{BOLD}  SCAN COMPLETE{RST}")
    print(f"{R}{BOLD}{'═'*60}{RST}\n")
    print(f"  Params tested    : {results['total_tested']}")
    print(f"  Params found     : {G}{BOLD}{len(params)}{RST}")
    print(f"  Headers found    : {G}{BOLD}{len(headers)}{RST}")
    print(f"  Mined from page  : {results['mined_params'] and len(results['mined_params']) or 0}")

    if params:
        print(f"\n  {G}{BOLD}Hidden Parameters:{RST}")
        for p in params:
            ref  = f" {Y}[reflected]{RST}" if p.get("reflected") else ""
            behs = len(p.get("behaviors", []))
            beh  = f" {C}[{behs} behaviors]{RST}" if behs else ""
            print(f"    {G}→{RST} {p['param']}{ref}{beh}")

    if headers:
        print(f"\n  {G}{BOLD}Interesting Headers:{RST}")
        for h in headers:
            print(f"    {G}→{RST} {h['name']}: {h['value_tested']} "
                  f"— {h.get('detail','')}")
    print()

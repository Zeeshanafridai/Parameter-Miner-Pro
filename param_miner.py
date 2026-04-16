#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          PARAMETER MINER PRO  —  by Z33                      ║
║       github.com/yourhandle/param-miner-pro                  ║
╚══════════════════════════════════════════════════════════════╝

Finds hidden parameters that sqlmap, Burp, and Arjun miss.
Deeper wordlist. Smarter diffing. Header injection. Proto pollution.
"""

import argparse
import json
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from miner.core import (get_stable_baseline, R, G, Y, C, DIM, BOLD, RST)
from miner.techniques import query_params, header_mining, json_mining, path_mining
from miner.wordlists.params import ALL_PARAMS, DEBUG_PARAMS, AUTH_PARAMS, URL_PARAMS, HEADER_PARAMS
                                      URL_PARAMS, HEADER_PARAMS, ALL_HEADERS)

BANNER = f"""
{R}
  ██████╗  █████╗ ██████╗  █████╗ ███╗   ███╗    ███╗   ███╗██╗███╗   ██╗███████╗██████╗
  ██╔══██╗██╔══██╗██╔══██╗██╔══██╗████╗ ████║    ████╗ ████║██║████╗  ██║██╔════╝██╔══██╗
  ██████╔╝███████║██████╔╝███████║██╔████╔██║    ██╔████╔██║██║██╔██╗ ██║█████╗  ██████╔╝
  ██╔═══╝ ██╔══██║██╔══██╗██╔══██║██║╚██╔╝██║    ██║╚██╔╝██║██║██║╚██╗██║██╔══╝  ██╔══██╗
  ██║     ██║  ██║██║  ██║██║  ██║██║ ╚═╝ ██║    ██║ ╚═╝ ██║██║██║ ╚████║███████╗██║  ██║
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝    ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
{RST}{DIM}  Parameter Miner Pro — Hidden Params, Headers, JSON Keys, Paths, Prototype Pollution{RST}
"""


def run_scan(args) -> dict:
    results = {
        "url":       args.url,
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "findings":  [],
    }

    print(BANNER)
    print(f"  {C}Target{RST}   : {args.url}")
    print(f"  {C}Method{RST}   : {args.method}")
    print(f"  {C}Cookies{RST}  : {'Yes' if args.cookies else 'No'}")
    print(f"  {C}Threads{RST}  : {args.threads}")
    print()

    # Stable baseline
    print(f"{Y}[STEP 1] Establishing baseline...{RST}")
    extra_headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                extra_headers[k.strip()] = v.strip()

    baseline = get_stable_baseline(
        args.url,
        method=args.method,
        cookies=args.cookies,
        headers=extra_headers or None
    )
    print(f"  Status: {baseline['status']} | "
          f"Length: {baseline['body_length']} | "
          f"Time: {baseline['elapsed']}s\n")

    all_findings = []

    # Load custom wordlist
    custom_wl = None
    if args.wordlist:
        with open(args.wordlist) as f:
            custom_wl = [l.strip() for l in f if l.strip()]
        print(f"  {G}[+]{RST} Loaded {len(custom_wl)} words from {args.wordlist}\n")

    checks = args.checks or ["query", "headers", "json", "paths"]

    # Query params
    if "query" in checks:
        print(f"{Y}[STEP 2] Query Parameter Mining{RST}")
        findings = query_params.mine(
            args.url,
            wordlist   = custom_wl or ALL_PARAMS,
            baseline   = baseline,
            cookies    = args.cookies,
            headers    = extra_headers or None,
            method     = args.method,
            threads    = args.threads,
            threshold  = args.threshold,
            verbose    = True,
        )
        for f in findings:
            f["category"] = "query_param"
        all_findings.extend(findings)

    # Headers
    if "headers" in checks:
        print(f"{Y}[STEP 3] HTTP Header Mining{RST}")
        findings = header_mining.mine(
            args.url,
            baseline  = baseline,
            wordlist  = custom_wl,
            cookies   = args.cookies,
            method    = args.method,
            threads   = args.threads,
            verbose   = True,
        )
        for f in findings:
            f["category"] = "header"
        all_findings.extend(findings)

    # JSON body
    if "json" in checks and args.method.upper() in ("POST", "PUT", "PATCH"):
        print(f"{Y}[STEP 4] JSON Body Mining{RST}")
        base_body = {}
        if args.data:
            try:
                base_body = json.loads(args.data)
            except Exception:
                pass

        json_baseline = get_stable_baseline(
            args.url, method=args.method,
            cookies=args.cookies,
        )
        findings = json_mining.run_all(
            args.url,
            baseline   = json_baseline,
            base_body  = base_body or None,
            cookies    = args.cookies,
            wordlist   = custom_wl,
            threads    = args.threads,
            verbose    = True,
        )
        for f in findings:
            f["category"] = "json"
        all_findings.extend(findings)

    # Path mining
    if "paths" in checks:
        print(f"{Y}[STEP 5] Path / Endpoint Mining{RST}")
        findings = path_mining.mine_paths(
            args.url,
            baseline = baseline,
            cookies  = args.cookies,
            wordlist = None,
            threads  = args.threads,
            verbose  = True,
        )
        for f in findings:
            f["category"] = "path"
        all_findings.extend(findings)

        if args.versions:
            version_findings = path_mining.mine_api_versions(
                args.url, cookies=args.cookies, verbose=True
            )
            for f in version_findings:
                f["category"] = "api_version"
            all_findings.extend(version_findings)

    results["findings"] = all_findings

    # Summary
    _print_summary(all_findings)

    return results


def _print_summary(findings: list):
    if not findings:
        print(f"\n{DIM}  No hidden parameters found.{RST}")
        print(f"  {DIM}Tips:{RST}")
        print(f"  {DIM}  • Try with --cookies for authenticated scan{RST}")
        print(f"  {DIM}  • Use --method POST for POST endpoint mining{RST}")
        print(f"  {DIM}  • Lower --threshold for more sensitive detection{RST}\n")
        return

    print(f"\n{R}{BOLD}{'═'*60}{RST}")
    print(f"{R}{BOLD}  FINDINGS: {len(findings)} hidden parameters{RST}")
    print(f"{R}{BOLD}{'═'*60}{RST}\n")

    # Group by category
    by_cat = {}
    for f in findings:
        cat = f.get("category", "unknown")
        by_cat.setdefault(cat, []).append(f)

    for cat, cat_findings in by_cat.items():
        print(f"  {C}{cat.upper()} ({len(cat_findings)}){RST}")
        for f in sorted(cat_findings, key=lambda x: x.get("score", 0), reverse=True):
            sev = f.get("severity", "")
            sev_col = R if sev in ("Critical", "High") else Y if sev == "Medium" else DIM
            score   = f.get("score", 0)
            note    = f.get("finding_type") or f.get("reason") or ""
            print(f"    {G}+{RST} {sev_col}{f['param']}{RST} "
                  f"(score:{score}) {DIM}{note[:50]}{RST}")
        print()


def main():
    parser = argparse.ArgumentParser(
        prog="param-miner",
        description="Parameter Miner Pro — Find hidden params, headers, JSON keys, endpoints"
    )

    parser.add_argument("-u", "--url",       required=True)
    parser.add_argument("-m", "--method",    default="GET",
                        choices=["GET","POST","PUT","PATCH","DELETE","HEAD"])
    parser.add_argument("-d", "--data",      help="JSON body for POST requests")
    parser.add_argument("-c", "--cookies",   help="Session cookies")
    parser.add_argument("-H", "--header",    action="append",
                        help="Extra headers (Name: Value)")
    parser.add_argument("-w", "--wordlist",  help="Custom wordlist file")

    parser.add_argument("--checks",  nargs="+",
                        choices=["query", "headers", "json", "paths"],
                        help="Which checks to run (default: all)")
    parser.add_argument("--versions", action="store_true",
                        help="Also probe API version endpoints")
    parser.add_argument("--threshold", type=int, default=25,
                        help="Diff score threshold 0-100 (default: 25)")
    parser.add_argument("--threads",   type=int, default=10)

    parser.add_argument("-o", "--output",    help="Save JSON results")
    parser.add_argument("--report",          action="store_true")
    parser.add_argument("-q", "--quiet",     action="store_true")

    args = parser.parse_args()

    results = run_scan(args)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n{G}[+] Saved to {args.output}{RST}")

    if args.report:
        _save_report(results)


def _save_report(results: dict):
    import datetime
    ts   = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path = f"param_report_{ts}.md"

    lines = [f"# Parameter Mining Report\n",
             f"**Target:** `{results['url']}`  ",
             f"**Date:** {results['scan_time']}  ",
             f"**Findings:** {len(results['findings'])}  \n",
             "---\n"]

    for f in results["findings"]:
        sev = f.get("severity", "Info")
        lines.append(f"## [{sev}] `{f['param']}` ({f.get('location','?')})\n")
        lines.append(f"- **Score:** {f.get('score',0)}")
        lines.append(f"- **Category:** {f.get('category','?')}")
        if f.get("reason"):
            lines.append(f"- **Reason:** {f['reason']}")
        if f.get("finding_type"):
            lines.append(f"- **Type:** {f['finding_type']}")
        lines.append("")

    with open(path, "w") as f:
        f.write("\n".join(lines))
    print(f"{G}[+] Report: {path}{RST}")


if __name__ == "__main__":
    main()

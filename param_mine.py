#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          PARAMETER MINER PRO  —  by Z33                      ║
║       github.com/yourhandle/param-miner-pro                  ║
╚══════════════════════════════════════════════════════════════╝
"""

import argparse, sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from paramminer.scanner import scan
from paramminer.core import R, G, Y, C, DIM, BOLD, RST
from paramminer.report.generator import generate as gen_report

BANNER = f"""
{R}
  ██████╗  █████╗ ██████╗  █████╗ ███╗   ███╗    ███╗   ███╗██╗███╗   ██╗███████╗██████╗
  ██╔══██╗██╔══██╗██╔══██╗██╔══██╗████╗ ████║    ████╗ ████║██║████╗  ██║██╔════╝██╔══██╗
  ██████╔╝███████║██████╔╝███████║██╔████╔██║    ██╔████╔██║██║██╔██╗ ██║█████╗  ██████╔╝
  ██╔═══╝ ██╔══██║██╔══██╗██╔══██║██║╚██╔╝██║    ██║╚██╔╝██║██║██║╚██╗██║██╔══╝  ██╔══██╗
  ██║     ██║  ██║██║  ██║██║  ██║██║ ╚═╝ ██║    ██║ ╚═╝ ██║██║██║ ╚████║███████╗██║  ██║
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝    ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
{RST}{DIM}  Hidden Parameter Discovery — Batched Fuzzing + Response Mining + Header Analysis{RST}
"""

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(prog="param-miner", description="Hidden Parameter Discovery Tool")

    parser.add_argument("-u", "--url",          required=True)
    parser.add_argument("-m", "--method",       default="GET")
    parser.add_argument("-d", "--data",         help="POST body")
    parser.add_argument("--content-type",       default="form", choices=["form","json"])
    parser.add_argument("-c", "--cookies")
    parser.add_argument("-H", "--header",       action="append")
    parser.add_argument("-w", "--wordlist",     help="Custom wordlist file")
    parser.add_argument("-p", "--param",        action="append", help="Extra params to test")
    parser.add_argument("--batch-size",         type=int, default=30)
    parser.add_argument("--threads",            type=int, default=10)
    parser.add_argument("--threshold",          type=int, default=25,
                        help="Diff confidence threshold 0-100 (default:25)")
    parser.add_argument("--no-mine",            action="store_true",
                        help="Skip response mining — use wordlist only")
    parser.add_argument("--headers",            action="store_true",
                        help="Also mine HTTP headers")
    parser.add_argument("--quick",              action="store_true",
                        help="Quick mode — security params only (~200)")
    parser.add_argument("--delay",              type=float, default=0.0)
    parser.add_argument("--report",             action="store_true")
    parser.add_argument("--report-prefix",      default="paramminer_report")
    parser.add_argument("-o", "--output")
    parser.add_argument("-q", "--quiet",        action="store_true")

    args = parser.parse_args()

    headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

    results = scan(
        url            = args.url,
        method         = args.method.upper(),
        body           = args.data,
        content_type   = args.content_type,
        cookies        = args.cookies,
        headers        = headers or None,
        wordlist_path  = args.wordlist,
        extra_params   = args.param,
        batch_size     = args.batch_size,
        threads        = args.threads,
        threshold      = args.threshold,
        mine_responses = not args.no_mine,
        test_headers   = args.headers,
        delay          = args.delay,
        quick          = args.quick,
        verbose        = not args.quiet,
    )

    if args.report:
        paths = gen_report(results, args.report_prefix)
        print(f"\n{C}[*] Reports:{RST}")
        print(f"    JSON     : {paths['json']}")
        print(f"    Markdown : {paths['markdown']}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n{G}[+] Results: {args.output}{RST}")

if __name__ == "__main__":
    main()

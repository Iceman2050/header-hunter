#!/usr/bin/env python3
"""header-hunter: scan HTTP response headers for AI-agent-directed signals
and possible indirect prompt-injection attempts.

Usage:
    python headerhunter.py https://example.com
    python headerhunter.py --file urls.txt --json
"""

from __future__ import annotations

import argparse
import sys

from headerhunter.analyze import analyze
from headerhunter.fetch import DEFAULT_TIMEOUT, MAX_REDIRECTS, fetch_headers
from headerhunter.report import render_json, render_table, result_for


def scan_url(url: str, timeout: int, max_redirects: int) -> dict:
    fetched = fetch_headers(url, timeout=timeout, max_redirects=max_redirects)
    analysis = analyze(fetched["headers"])
    return result_for(url, fetched, analysis)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="headerhunter",
        description="Scan HTTP response headers for AI-agent signals and "
                    "possible indirect prompt-injection attempts.")
    ap.add_argument("url", nargs="?",
                    help="single URL to scan")
    ap.add_argument("--file", metavar="PATH",
                    help="file with one URL per line (batch mode)")
    ap.add_argument("--json", action="store_true",
                    help="emit machine-readable JSON instead of tables")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                    help="request timeout in seconds (default %d)" % DEFAULT_TIMEOUT)
    ap.add_argument("--max-redirects", type=int, default=MAX_REDIRECTS,
                    help="max redirects to follow (default %d)" % MAX_REDIRECTS)
    args = ap.parse_args(argv)

    urls: list[str] = []
    if args.file:
        try:
            with open(args.file) as f:
                urls = [ln.strip() for ln in f if ln.strip()
                        and not ln.strip().startswith("#")]
        except OSError as e:
            print("error: cannot read --file: %s" % e, file=sys.stderr)
            return 2
    if args.url:
        urls.append(args.url)
    if not urls:
        ap.print_help()
        return 2

    results = [scan_url(u, args.timeout, args.max_redirects) for u in urls]

    if args.json:
        print(render_json(results))
    else:
        for r in results:
            print(render_table(r))
    return 0


if __name__ == "__main__":
    sys.exit(main())

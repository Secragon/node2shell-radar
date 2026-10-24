"""Headless scanner for reproducible reports and CI."""

import argparse
import asyncio
import json
import sys

from radar.engine import Control, run_scan
from radar.models import ScanOptions, parse_targets
from radar.storage import export_report, grouped_websites


def main(argv=None):
    parser = argparse.ArgumentParser(description="Node2Shell Radar: discover sites and assess Node.js version evidence")
    parser.add_argument("targets", nargs="+", help="Domains or HTTP(S) URLs")
    parser.add_argument("--no-passive-dns", action="store_true", help="Skip public subdomain sources")
    parser.add_argument("--no-active-dns", action="store_true", help="Skip common DNS names")
    parser.add_argument("--no-tls-names", action="store_true", help="Skip certificate names")
    parser.add_argument("--extra-ports", action="store_true", help="Check common nonstandard web ports")
    parser.add_argument("--crawl", action="store_true", help="Follow a bounded set of same-origin GET links")
    parser.add_argument("--all-addresses", action="store_true", help="Check every resolved address")
    parser.add_argument("--active-check", action="store_true", help="Run safe Brotli request parsing checks, including Strapi's paired login test")
    parser.add_argument("--output", help="Export report to JSON or CSV")
    args = parser.parse_args(argv)
    try:
        options = ScanOptions(parse_targets("\n".join(args.targets)),
                              passive_dns=not args.no_passive_dns,
                              active_dns=not args.no_active_dns,
                              tls_names=not args.no_tls_names,
                              extra_ports=args.extra_ports,
                              crawl=args.crawl, all_addresses=args.all_addresses,
                              active_check=args.active_check)
    except ValueError as exc:
        parser.error(str(exc))
    run, assets = {}, {}

    def emit(event):
        kind = event["type"]
        if kind == "started":
            run.update(event)
        elif kind == "asset":
            asset = event["asset"]
            assets[asset["id"]] = asset
        elif kind == "finished":
            run.update(event)
        elif kind == "progress":
            print(f"{event['completed']}/{event['total']} {event['current']}", file=sys.stderr)
        elif kind == "log":
            print(event["message"], file=sys.stderr)

    asyncio.run(run_scan(options, Control(), emit))
    if run.get("status") != "COMPLETED":
        print("Scan did not complete.", file=sys.stderr)
        return 1
    if args.output:
        export_report(args.output, run, list(assets.values()))
        print(args.output)
    else:
        print(json.dumps({"websites": grouped_websites(list(assets.values())),
                          "coverage": run.get("coverage", {})}, indent=2))
    return 0

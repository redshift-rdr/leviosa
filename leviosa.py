import argparse
import asyncio
import json
import sys
from contextlib import aclosing

from core.config import load_config
from core.loader import load_modules
from core.models import LeviosaContext
from core.parsers import request_source
from core.requester import send
from core.runner import run_modules


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leviosa",
        description="A lightweight web penetration testing helper.",
    )
    parser.add_argument(
        "target",
        help="URL, URL-list file (.txt), or JSON request file (.json)",
    )
    parser.add_argument(
        "--module", "-m",
        dest="modules",
        action="append",
        default=[],
        metavar="NAME",
        help="Module to run (repeatable). Loaded from modules/<name>.py",
    )
    parser.add_argument(
        "--no-proxy",
        action="store_true",
        help="Disable BurpSuite proxy (default: 127.0.0.1:8080)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        metavar="N",
        help="Max concurrent requests (default: 20)",
    )
    parser.add_argument(
        "--max-body-bytes",
        type=int,
        metavar="N",
        help="Cap response body reads at N bytes (0 = unlimited, default: 1048576)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Log debug info to stderr",
    )
    return parser


def main():
    parser = build_parser()
    args, remaining = parser.parse_known_args()

    config = load_config()
    if args.no_proxy:
        config.proxy_enabled = False
    if args.concurrency is not None:
        config.concurrency = args.concurrency
    if args.max_body_bytes is not None:
        config.max_body_bytes = args.max_body_bytes
    if args.modules:
        config.modules = args.modules
    if args.verbose:
        config.verbose = True

    if config.verbose:
        proxy_info = (
            f"{config.proxy_host}:{config.proxy_port}" if config.proxy_enabled else "disabled"
        )
        print(f"[leviosa] proxy: {proxy_info}", file=sys.stderr)

    try:
        source = request_source(args.target)
    except FileNotFoundError:
        print(f"error: file not found: {args.target!r}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"error: malformed JSON in {args.target!r}: {e.msg}", file=sys.stderr)
        sys.exit(1)

    if config.verbose:
        print(f"[leviosa] target: {args.target!r}", file=sys.stderr)
        if config.modules:
            print(f"[leviosa] modules: {', '.join(config.modules)}", file=sys.stderr)

    if config.modules:
        try:
            modules = load_modules(config.modules)
        except FileNotFoundError as e:
            print(f"error: {e}", file=sys.stderr)
            sys.exit(1)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            sys.exit(1)

        for mod in modules:
            mod.setup(remaining)

        context = LeviosaContext()
        try:
            asyncio.run(run_modules(modules, source, config, context))
        except KeyboardInterrupt:
            print("\n[leviosa] interrupted.", file=sys.stderr)
            sys.exit(130)
        except RuntimeError as e:
            print(f"error: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Raw dispatch: stream statuses as they complete. read_body=False since
        # we only print the status line, so no body is ever downloaded.
        async def _raw():
            async with aclosing(send(source(), config, read_body=False)) as stream:
                async for resp in stream:
                    print(f"{resp.status} {resp.request.method} {resp.request.url}")

        try:
            asyncio.run(_raw())
        except KeyboardInterrupt:
            print("\n[leviosa] interrupted.", file=sys.stderr)
            sys.exit(130)


if __name__ == "__main__":
    main()

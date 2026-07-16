import argparse
import asyncio
import inspect
import json
import shutil
import sys
import textwrap
from contextlib import aclosing

from core.config import load_config
from core.cookies import (
    overrides_from_donor,
    overrides_from_header_string,
    with_cookie_overrides,
)
from core.filters import add_filter_args
from core.loader import discover_modules, load_modules
from core.logdb import TrafficLogger
from core.models import LeviosaContext
from core.parsers import request_source
from core.requester import resolve_proxy, send
from core.runner import run_modules


def _option_rows(parser: argparse.ArgumentParser) -> list[tuple[str, str]]:
    """Extract (option-display, help) pairs from an argparse parser."""
    rows = []
    for action in parser._actions:
        if not action.option_strings:  # skip positionals
            continue
        flags = ", ".join(action.option_strings)
        # nargs == 0 means a flag that takes no value (store_true etc.).
        metavar = "" if action.nargs == 0 else (action.metavar or action.dest.upper())
        rows.append((f"{flags} {metavar}".strip(), action.help or ""))
    return rows


def _print_option_rows(rows: list[tuple[str, str]], indent: int) -> None:
    """Print (left, help) rows aligned, wrapping help text to the terminal width."""
    if not rows:
        return
    left_width = max(len(left) for left, _ in rows)
    help_col = indent + left_width + 2
    total = max(shutil.get_terminal_size((100, 24)).columns, 60)
    avail = max(total - help_col, 20)
    for left, help_text in rows:
        wrapped = textwrap.wrap(help_text, avail) or [""]
        print(f"{' ' * indent}{left.ljust(left_width)}  {wrapped[0]}")
        for cont in wrapped[1:]:
            print(f"{' ' * help_col}{cont}")


def list_modules() -> None:
    """Print every available module, its description and its CLI options."""
    print("Available modules:\n")
    for name in discover_modules():
        try:
            module = load_modules([name])[0]
        except Exception as e:  # a broken module shouldn't sink the whole listing
            print(f"  {name}")
            print(f"      (failed to load: {e})\n")
            continue

        doc = inspect.getdoc(type(module)) or ""
        summary = doc.split("\n\n", 1)[0].replace("\n", " ").strip() or "(no description)"
        print(f"  {name}")
        for line in textwrap.wrap(summary, 72):
            print(f"      {line}")

        parser = module.option_parser()
        rows = _option_rows(parser) if parser is not None else []
        if rows:
            print("      options:")
            _print_option_rows(rows, indent=8)
        else:
            print("      (no module-specific options)")
        print()

    filter_parser = argparse.ArgumentParser(add_help=False)
    add_filter_args(filter_parser)
    print("All modules also accept the standard request filters:")
    _print_option_rows(_option_rows(filter_parser), indent=2)


class _ListModulesAction(argparse.Action):
    """Print the module listing and exit (like --help; no target required)."""

    def __init__(self, option_strings, dest, **kwargs):
        super().__init__(option_strings, dest, nargs=0, default=argparse.SUPPRESS, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        list_modules()
        parser.exit()


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
        "--list-modules",
        action=_ListModulesAction,
        help="List available modules, their descriptions and options, then exit",
    )
    parser.add_argument(
        "--proxy",
        metavar="URL",
        help="Route non-burp traffic through this proxy, credentials optional, "
             "e.g. --proxy http://user:pass@127.0.0.1:8081",
    )
    parser.add_argument(
        "--no-proxy",
        action="store_true",
        help="Force all traffic direct, overriding per-module burp opt-in and --proxy",
    )
    parser.add_argument(
        "--log-db",
        metavar="PATH",
        help="SQLite file for the traffic log (default: leviosa.db)",
    )
    parser.add_argument(
        "--no-log",
        action="store_true",
        help="Disable the sqlite traffic log",
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
        "--follow-redirects", "-L",
        action="store_true",
        help="Follow HTTP redirects (default: off, redirects are reported as-is)",
    )
    parser.add_argument(
        "--cookies",
        metavar="STR",
        help="Replace cookie values by name using a pasted Cookie header, "
             "e.g. --cookies \"session=abc; csrf=xyz\"",
    )
    parser.add_argument(
        "--cookie-from",
        metavar="FILE",
        help="Replace cookie values using cookies from a freshly captured "
             "request JSON file (refreshes a timed-out session)",
    )
    parser.add_argument(
        "--random-timing",
        action="store_true",
        help="Send requests sequentially with a random human-like delay between each one "
             "(see --random-timing-min / --random-timing-max for the range)",
    )
    parser.add_argument(
        "--random-timing-min",
        type=float,
        metavar="SECS",
        help="Minimum inter-request delay in seconds when --random-timing is active (default: 2.0)",
    )
    parser.add_argument(
        "--random-timing-max",
        type=float,
        metavar="SECS",
        help="Maximum inter-request delay in seconds when --random-timing is active (default: 8.0)",
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
    if args.proxy is not None:
        config.proxy_url = args.proxy
    if args.no_proxy:
        config.no_proxy = True
    if args.log_db is not None:
        config.log_db_path = args.log_db
    if args.no_log:
        config.log_enabled = False
    if args.concurrency is not None:
        config.concurrency = args.concurrency
    if args.max_body_bytes is not None:
        config.max_body_bytes = args.max_body_bytes
    if args.follow_redirects:
        config.follow_redirects = True
    if args.modules:
        config.modules = args.modules
    if args.random_timing:
        config.random_timing = True
    if args.random_timing_min is not None:
        config.random_timing_min = args.random_timing_min
        config.random_timing = True
    if args.random_timing_max is not None:
        config.random_timing_max = args.random_timing_max
        config.random_timing = True
    if args.verbose:
        config.verbose = True

    if config.verbose:
        if config.no_proxy:
            proxy_info = "disabled (all traffic direct)"
        elif config.proxy_url:
            proxy_info = f"{config.proxy_url} (non-burp traffic)"
        else:
            proxy_info = "direct (burp per-module opt-in only)"
        print(f"[leviosa] proxy: {proxy_info}", file=sys.stderr)
        log_info = config.log_db_path if config.log_enabled else "disabled"
        print(f"[leviosa] traffic log: {log_info}", file=sys.stderr)
        if config.random_timing:
            print(
                f"[leviosa] random timing: {config.random_timing_min:.1f}s–{config.random_timing_max:.1f}s (sequential)",
                file=sys.stderr,
            )

    try:
        source = request_source(args.target)
    except FileNotFoundError:
        print(f"error: file not found: {args.target!r}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"error: malformed JSON in {args.target!r}: {e.msg}", file=sys.stderr)
        sys.exit(1)

    # Cookie overrides refresh timed-out session cookies. Donor file first, then
    # the pasted header on top so an explicit --cookies value always wins.
    cookie_overrides: dict[str, str] = {}
    try:
        if args.cookie_from:
            cookie_overrides.update(overrides_from_donor(args.cookie_from))
        if args.cookies:
            cookie_overrides.update(overrides_from_header_string(args.cookies))
    except FileNotFoundError:
        print(f"error: cookie file not found: {args.cookie_from!r}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"error: malformed JSON in cookie file {args.cookie_from!r}: {e.msg}", file=sys.stderr)
        sys.exit(1)
    source = with_cookie_overrides(source, cookie_overrides)

    if config.verbose:
        print(f"[leviosa] target: {args.target!r}", file=sys.stderr)
        if cookie_overrides:
            print(
                f"[leviosa] overriding {len(cookie_overrides)} cookie(s): "
                f"{', '.join(cookie_overrides)}",
                file=sys.stderr,
            )
        if config.modules:
            print(f"[leviosa] modules: {', '.join(config.modules)}", file=sys.stderr)

    # The traffic log captures every request/response, including traffic that
    # bypasses burp, so the whole engagement is recorded locally.
    logger = TrafficLogger(config.log_db_path) if config.log_enabled else None
    try:
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
                asyncio.run(run_modules(modules, source, config, context, logger))
            except KeyboardInterrupt:
                print("\n[leviosa] interrupted.", file=sys.stderr)
                sys.exit(130)
            except RuntimeError as e:
                print(f"error: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            # Raw dispatch: stream statuses as they complete. read_body=False since
            # we only print the status line, so no body is ever downloaded. No
            # module, so proxy follows --proxy / direct (no burp opt-in).
            proxy, proxy_auth = resolve_proxy(config, use_burp=False)

            async def _raw():
                stream = send(
                    source(),
                    config,
                    read_body=False,
                    proxy=proxy,
                    proxy_auth=proxy_auth,
                    logger=logger,
                )
                async with aclosing(stream) as responses:
                    async for resp in responses:
                        print(f"{resp.status} {resp.request.method} {resp.request.url}")

            try:
                asyncio.run(_raw())
            except KeyboardInterrupt:
                print("\n[leviosa] interrupted.", file=sys.stderr)
                sys.exit(130)
    finally:
        if logger is not None:
            logger.close()


if __name__ == "__main__":
    main()

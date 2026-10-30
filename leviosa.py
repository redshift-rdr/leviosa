import argparse
import asyncio
import inspect
import json
import shutil
import sqlite3
import sys
import textwrap
from contextlib import aclosing, ExitStack
from pathlib import Path

from core.config import load_config
from core.cookies import (
    overrides_from_donor,
    overrides_from_header_string,
    with_cookie_overrides,
)
from core.filters import add_filter_args, filters_from_args
from core.options import setup_modules, ValidationParser
from core.loader import discover_modules, load_modules
from core.logdb import TrafficLogger
from core.models import LeviosaContext
from core.parsers import request_source
from core.requester import resolve_proxy, send
from core.runner import run_modules
from core.progress import Progress
from core.tooltags import BurpTool, parse_module_tools, resolve_module_tool
from core.scans import read_scan, scan_config, prepare_scan, run_scan
from core.scanoutput import JsonlResults, ScanReporter


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


def list_modules(modules_dir=None) -> None:
    """Print every available module, its description and its CLI options."""
    print("Available modules:\n")
    for name in discover_modules(modules_dir):
        try:
            module = load_modules([name], modules_dir)[0]
        except Exception as e:  # a broken module shouldn't sink the whole listing
            print(f"  {name}")
            print(f"      (failed to load: {e})\n")
            continue

        doc = inspect.getdoc(type(module)) or ""
        summary = doc.split("\n\n", 1)[0].replace("\n", " ").strip() or "(no description)"
        print(f"  {name}")
        print(f"      tool: {module.tool}")
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
        directory_parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
        directory_parser.add_argument("--modules-dir")
        directory_args, _ = directory_parser.parse_known_args()
        list_modules(directory_args.modules_dir)
        parser.exit()


class _MainParser(argparse.ArgumentParser):
    def parse_known_args(self, args=None, namespace=None):
        parsed, remaining = super().parse_known_args(args, namespace)
        if parsed.target is None and parsed.scan is None:
            self.error("a target or --scan FILE is required")
        if not parsed.scan and (parsed.validate_scan or parsed.results is not None):
            self.error("--validate-scan and --results require --scan")
        return parsed, remaining


def build_parser() -> argparse.ArgumentParser:
    parser = _MainParser(
        prog="leviosa",
        description="A lightweight web penetration testing helper.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "target", nargs="?",
        help="URL, URL-list or JSON request file; overrides target in --scan",
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
    parser.add_argument('--burp', action=argparse.BooleanOptionalAction, default=None,
                        help='Explicitly route all traffic through Burp (default off)')
    parser.add_argument('--proxy-config', metavar='FILE',
                        help='TOML file of ordered endpoint-regex upstream proxy rules')
    parser.add_argument(
        "--proxy",
        metavar="URL",
        help="Fallback proxy for traffic not matched by endpoint rules, credentials optional, "
             "e.g. --proxy http://user:pass@127.0.0.1:8081",
    )
    parser.add_argument(
        "--no-proxy",
        action="store_true",
        help="Force all traffic direct, overriding Burp mode and all proxy rules",
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
    parser.add_argument("--tool", type=BurpTool, choices=list(BurpTool),
                        help="Override the BURP_TOOL category for this run")
    parser.add_argument("--module-tool", dest="module_tools", action="append", default=[],
                        metavar="NAME=TAG", help="Override a selected module's category (repeatable); "
                        "TAG is Repeater, Intruder or Scanner")
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
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Pace ALL categories sequentially, overriding human mode "
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
    parser.add_argument("--human-mode", action=argparse.BooleanOptionalAction, default=None,
                        help="Pace Repeater traffic; Intruder and Scanner retain normal concurrency")
    parser.add_argument("--human-timing-min", type=float, metavar="SECS",
                        help="Minimum Repeater idle interval (default: 2.0); enables human mode unless explicitly disabled")
    parser.add_argument("--human-timing-max", type=float, metavar="SECS",
                        help="Maximum Repeater idle interval (default: 8.0); enables human mode unless explicitly disabled")
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Log debug info to stderr",
    )
    parser.add_argument("--modules-dir", metavar="PATH",
                        help="Load custom modules from this directory instead of built-ins")
    parser.add_argument("--scan", metavar="FILE", help="Run ordered module steps from a TOML file")
    parser.add_argument("--validate-scan", action="store_true",
                        help="Validate and display a scan without sending traffic or creating outputs")
    parser.add_argument("--results", metavar="FILE", help="Append scan findings and progress to a separate JSONL file")
    parser.add_argument('--auth-check', action=argparse.BooleanOptionalAction, default=None,
                        help='Check authenticated session and pause for verified credential replacement; dispatches sequentially')
    parser.add_argument('--auth-check-url', help='Protected GET URL used to test authentication (same origin as captured credentials)')
    parser.add_argument('--auth-success-text', help='Text required in the protected check response, in addition to 2xx')
    parser.add_argument('--auth-mechanism', choices=['auto', 'cookies', 'bearer'],
                        help='Credential to refresh; auto prefers Bearer when both are present')
    parser.add_argument('--auth-check-interval', type=int,
                        help='Check before every N scan requests (default: 20), plus after 401/403/redirects')
    parser.add_argument('--progress', action=argparse.BooleanOptionalAction, default=None,
                        help='Show periodic request progress on stderr (default: enabled)')
    parser.add_argument('--progress-interval', type=float, metavar='SECONDS',
                        help='Seconds between progress lines (default: 5)')
    add_filter_args(parser)
    return parser


def _apply_cli(config, args, parser, selected_modules=None):
    if args.progress is not None:
        config.progress = args.progress
    if args.progress_interval is not None:
        config.progress_interval = args.progress_interval
    if args.burp is not None:
        config.burp = args.burp
    if args.proxy_config is not None:
        config.proxy_config_path = str(Path(args.proxy_config).expanduser().resolve())
    for field in ('auth_check', 'auth_check_url', 'auth_success_text', 'auth_mechanism', 'auth_check_interval'):
        value = getattr(args, field, None)
        if value is not None:
            setattr(config, field, value)
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
    if args.tool is not None:
        config.tool = args.tool
        # A CLI-wide override takes precedence over file-configured defaults,
        # including per-module exceptions; CLI named overrides are applied next.
        config.module_tools = {}
    try:
        module_tools = parse_module_tools(args.module_tools)
        unselected = module_tools.keys() - set(config.modules if selected_modules is None else selected_modules)
        if unselected:
            parser.error("--module-tool refers to unselected module(s): " + ", ".join(sorted(unselected)))
        config.module_tools.update(module_tools)
    except ValueError as exc:
        parser.error(str(exc))
    if args.random_timing_min is not None:
        config.random_timing_min = args.random_timing_min
    if args.random_timing_max is not None:
        config.random_timing_max = args.random_timing_max
    if args.random_timing is not None:
        config.random_timing = args.random_timing
    elif args.random_timing_min is not None or args.random_timing_max is not None:
        config.random_timing = True
    if args.human_timing_min is not None:
        config.human_timing_min = args.human_timing_min
    if args.human_timing_max is not None:
        config.human_timing_max = args.human_timing_max
    if args.human_mode is not None:
        config.human_mode = args.human_mode
    elif args.human_timing_min is not None or args.human_timing_max is not None:
        config.human_mode = True
    try:
        config.validate_timing()
        config.validate_progress()
        config.validate_auth()
        config.validate_proxies()
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    if args.verbose:
        config.verbose = True

    if config.verbose:
        if config.no_proxy:
            proxy_info = "disabled (all traffic direct)"
        elif config.burp:
            proxy_info = f"Burp at {config.burp_host}:{config.burp_port} (all traffic)"
        elif config.proxy_rules:
            proxy_info = f"{len(config.proxy_rules)} ordered endpoint rules; configured fallback or direct"
        elif config.proxy_url or config.proxy_default_url:
            from core.proxies import split_proxy_auth
            proxy_info = split_proxy_auth(config.proxy_url or config.proxy_default_url)[0]
        else:
            proxy_info = "direct"
        print(f"[leviosa] proxy: {proxy_info}", file=sys.stderr)
        log_info = config.log_db_path if config.log_enabled else "disabled"
        print(f"[leviosa] traffic log: {log_info}", file=sys.stderr)
        if config.random_timing:
            print(
                f"[leviosa] random timing: {config.random_timing_min:.1f}s–{config.random_timing_max:.1f}s "
                "(all categories; overrides human mode)",
                file=sys.stderr,
            )
        elif config.human_mode:
            print(f"[leviosa] human mode: {config.human_timing_min:.1f}s–{config.human_timing_max:.1f}s "
                  "(Repeater only; Intruder/Scanner use normal concurrency)", file=sys.stderr)

    return config


def _scan_main(parser, args, remaining):
    if args.modules:
        parser.error("--module cannot be combined with --scan; select modules in [[steps]]")
    if remaining:
        parser.error("unrecognized scan arguments: " + " ".join(remaining) + "; put module options in step args")
    try:
        definition = read_scan(args.scan)
        config = scan_config(definition, load_config())
        _apply_cli(config, args, parser, definition.module_names)
        cookies = {}
        if args.cookie_from:
            cookies.update(overrides_from_donor(args.cookie_from))
        if args.cookies:
            cookies.update(overrides_from_header_string(args.cookies))
        target = args.target
        if target is not None and not target.startswith(("http://", "https://")):
            target = str(Path(target).expanduser().resolve())
        validation = ValidationParser(add_help=False, parents=[parser], allow_abbrev=False)
        protected = [Path("leviosa.toml").resolve()]
        if config.proxy_config_path:
            protected.append(Path(config.proxy_config_path))
        if args.cookie_from:
            protected.append(Path(args.cookie_from).resolve())
        plan = prepare_scan(
            definition, config, validation, target=target,
            modules_dir=str(Path(args.modules_dir).expanduser().resolve()) if args.modules_dir else None,
            results=str(Path(args.results).expanduser().resolve()) if args.results else None,
            filters=filters_from_args(args), cli_tool=args.tool,
            cli_module_tools=parse_module_tools(args.module_tools),
            source_transform=lambda source: with_cookie_overrides(source, cookies), protected_paths=protected,
        )
    except Exception as exc:
        parser.error(f"invalid scan: {exc}")
    if args.validate_scan:
        print(f"[SCAN] Valid: {plan.name}; target={plan.target}; {len(plan.steps)} steps")
        for step in plan.steps:
            print(f"[SCAN] {step.index}. {step.name}: {step.module.module_name} ({step.config.tool})")
        print(f"[SCAN] Traffic: {plan.config.log_db_path if plan.config.log_enabled else 'disabled'}; "
              f"results: {plan.results or 'console only'}")
        return 0
    try:
        with ExitStack() as resources:
            results = JsonlResults(plan.results) if plan.results else None
            if results is not None:
                resources.callback(results.close)
            logger = TrafficLogger(plan.config.log_db_path) if plan.config.log_enabled else None
            if logger is not None:
                resources.callback(logger.close)
            outcome = asyncio.run(run_scan(plan, output=ScanReporter(results), logger=logger))
        return 1 if outcome.failed else 0
    except KeyboardInterrupt:
        print("[leviosa] scan interrupted.", file=sys.stderr)
        return 130
    except (OSError, RuntimeError, ValueError, sqlite3.Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def main():
    parser = build_parser()
    args, remaining = parser.parse_known_args()
    if args.scan:
        return _scan_main(parser, args, remaining)

    try:
        config = load_config()
    except (ValueError, TypeError) as exc:
        parser.error(f"invalid configuration: {exc}")
    _apply_cli(config, args, parser)

    try:
        source = request_source(args.target)
    except FileNotFoundError:
        print(f"error: file not found: {args.target!r}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"error: malformed JSON in {args.target!r}: {e.msg}", file=sys.stderr)
        sys.exit(1)
    except (ValueError, KeyError, TypeError) as e:
        parser.error(f"invalid request file: {e}")

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

    try:
        modules = load_modules(config.modules, args.modules_dir)
    except (FileNotFoundError, ValueError) as exc:
        parser.error(str(exc))
    try:
        filters = filters_from_args(args)
    except ValueError as exc:
        parser.error(str(exc))
    setup_modules(modules, remaining, filters, parser)
    try:
        for module in modules:
            tool = resolve_module_tool(module, config)
            if config.verbose:
                print(f"[leviosa] {module.module_name}: tool={tool}", file=sys.stderr)
    except (ValueError, TypeError) as exc:
        parser.error(f"invalid module tool: {exc}")
    if not modules and filters:
        unfiltered_source = source

        def source():
            requests = unfiltered_source()
            for request_filter in filters:
                requests = request_filter.apply(requests)
            return requests

    # The traffic log captures every request/response, including traffic that
    # bypasses burp, so the whole engagement is recorded locally.
    try:
        logger = TrafficLogger(config.log_db_path) if config.log_enabled else None
    except (ValueError, OSError, sqlite3.Error) as exc:
        parser.error(str(exc))
    try:
        if config.modules:
            context = LeviosaContext()
            try:
                asyncio.run(run_modules(modules, source, config, context, logger))
            except KeyboardInterrupt:
                print("\n[leviosa] interrupted.", file=sys.stderr)
                sys.exit(130)
            except (RuntimeError, ValueError, TypeError, sqlite3.Error) as e:
                print(f"error: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            # Raw dispatch: stream statuses as they complete. read_body=False since
            # we only print the status line; the logger still captures capped
            # bodies. Global Burp mode and endpoint proxy rules apply here too.
            proxy, proxy_auth = resolve_proxy(config, use_burp=False)

            async def _raw():
                with Progress('requests', enabled=config.progress, interval=config.progress_interval) as progress:
                    guard = None
                    if config.auth_check:
                        from core.auth import AuthGuard, AuthenticationStopped
                        guard = AuthGuard(config)
                        for seed in source():
                            guard.bind(seed)
                            if guard.bound:
                                break
                        if not guard.bound:
                            raise AuthenticationStopped('No captured credentials on the authentication-check URL origin')
                    stream = send(
                        source(),
                        config,
                        read_body=False,
                        proxy=proxy,
                        proxy_auth=proxy_auth,
                        logger=logger,
                        **({"progress": progress} if config.progress else {}),
                        **({"auth_guard": guard} if guard is not None else {}),
                    )
                    async with aclosing(stream) as responses:
                        async for resp in responses:
                            print(f"{resp.status} {resp.request.method} {resp.request.url}")

            try:
                asyncio.run(_raw())
            except KeyboardInterrupt:
                print("\n[leviosa] interrupted.", file=sys.stderr)
                sys.exit(130)
            except (RuntimeError, ValueError, TypeError, sqlite3.Error) as e:
                print(f"error: {e}", file=sys.stderr)
                sys.exit(1)
    finally:
        if logger is not None:
            logger.close()


if __name__ == "__main__":
    sys.exit(main())

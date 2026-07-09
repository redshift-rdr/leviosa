"""
Inspect the leviosa sqlite traffic log.

Query the traffic captured by a run with stackable filters (time range, status
code, method, module, path substring, …) and print a readable table. Filters
combine with AND, so e.g.

    python traffic.py --after "2026-07-09 12:00" --status 500

shows only 500s captured on or after that time.
"""
import argparse
import sqlite3
import sys
from datetime import datetime
from urllib.parse import urlparse

from core.config import Config

# Column display defaults.
_DEFAULT_PATH_WIDTH = 60


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="traffic",
        description="Inspect the leviosa sqlite traffic log with stackable filters.",
    )
    parser.add_argument(
        "db",
        nargs="?",
        default=Config().log_db_path,
        help=f"Path to the traffic sqlite db (default: {Config().log_db_path})",
    )
    parser.add_argument(
        "--after", metavar="TIME",
        help="Only traffic at/after this time (any format SQLite understands, "
             "e.g. '2026-07-09' or '2026-07-09 12:30:00')",
    )
    parser.add_argument(
        "--before", metavar="TIME",
        help="Only traffic at/before this time",
    )
    parser.add_argument(
        "--status", type=int, action="append", default=[], metavar="CODE",
        help="Only this status code (repeatable, e.g. --status 500 --status 502)",
    )
    parser.add_argument(
        "--status-class", action="append", default=[], metavar="Nxx",
        help="Only this status class, e.g. 5xx or 4xx (repeatable)",
    )
    parser.add_argument(
        "--method", action="append", default=[], metavar="M",
        help="Only this HTTP method, case-insensitive (repeatable)",
    )
    parser.add_argument(
        "--module", action="append", default=[], metavar="NAME",
        help="Only traffic logged by this module (repeatable). "
             "Use --module '' for raw-dispatch traffic",
    )
    parser.add_argument(
        "--path", metavar="TEXT",
        help="Only requests whose URL contains this substring",
    )
    parser.add_argument(
        "--errors-only", action="store_true",
        help="Only network errors (status 0 / error flag set)",
    )
    parser.add_argument(
        "--limit", type=int, default=100, metavar="N",
        help="Max rows to show (default: 100; use 0 for no limit)",
    )
    parser.add_argument(
        "--desc", action="store_true",
        help="Show newest first (default: oldest first)",
    )
    parser.add_argument(
        "--path-width", type=int, default=_DEFAULT_PATH_WIDTH, metavar="N",
        help=f"Truncate the path column to N chars (default: {_DEFAULT_PATH_WIDTH})",
    )
    parser.add_argument(
        "--count", action="store_true",
        help="Print only the number of matching rows",
    )
    return parser


def build_where(args) -> tuple[str, list]:
    """Build a parameterised WHERE clause from the stackable filters (AND-joined)."""
    clauses: list[str] = []
    params: list = []

    if args.after:
        clauses.append("datetime(ts) >= datetime(?)")
        params.append(args.after)
    if args.before:
        clauses.append("datetime(ts) <= datetime(?)")
        params.append(args.before)
    if args.status:
        placeholders = ",".join("?" * len(args.status))
        clauses.append(f"status IN ({placeholders})")
        params.extend(args.status)
    if args.status_class:
        ranges = []
        for cls in args.status_class:
            digit = cls[0]
            if not digit.isdigit():
                raise ValueError(f"invalid --status-class {cls!r} (expected e.g. 5xx)")
            lo = int(digit) * 100
            ranges.append("(status BETWEEN ? AND ?)")
            params.extend([lo, lo + 99])
        clauses.append("(" + " OR ".join(ranges) + ")")
    if args.method:
        placeholders = ",".join("?" * len(args.method))
        clauses.append(f"UPPER(method) IN ({placeholders})")
        params.extend(m.upper() for m in args.method)
    if args.module:
        placeholders = ",".join("?" * len(args.module))
        clauses.append(f"IFNULL(module, '') IN ({placeholders})")
        params.extend(args.module)
    if args.path:
        clauses.append("url LIKE ?")
        params.append(f"%{args.path}%")
    if args.errors_only:
        clauses.append("error = 1")

    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


def _fmt_dt(ts: str) -> str:
    try:
        return datetime.fromisoformat(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return ts or ""


def _path_of(url: str, width: int) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    if width > 3 and len(path) > width:
        return path[: width - 3] + "..."
    return path


def _print_table(headers, rows, right_align):
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def render(cells):
        out = []
        for i, cell in enumerate(cells):
            out.append(cell.rjust(widths[i]) if i in right_align else cell.ljust(widths[i]))
        return "  ".join(out)

    print(render(headers))
    print("  ".join("-" * widths[i] for i in range(len(headers))))
    for row in rows:
        print(render(row))


def main():
    args = build_parser().parse_args()

    try:
        where, params = build_where(args)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)

    try:
        # Read-only connection so we never touch the log we are inspecting.
        conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    except sqlite3.OperationalError:
        print(f"error: cannot open traffic db: {args.db!r}", file=sys.stderr)
        sys.exit(1)

    try:
        if args.count:
            (total,) = conn.execute(f"SELECT COUNT(*) FROM traffic{where}", params).fetchone()
            print(total)
            return

        order = "DESC" if args.desc else "ASC"
        sql = (
            "SELECT ts, method, url, status, response_bytes, module, error "
            f"FROM traffic{where} ORDER BY id {order}"
        )
        if args.limit and args.limit > 0:
            sql += f" LIMIT {int(args.limit)}"

        cursor = conn.execute(sql, params)
        rows = []
        for ts, method, url, status, nbytes, module, error in cursor:
            rows.append([
                _fmt_dt(ts),
                method or "",
                str(status),
                str(nbytes),
                module or "-",
                _path_of(url, args.path_width),
            ])
    except sqlite3.OperationalError as e:
        print(f"error: querying db failed: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        conn.close()

    if not rows:
        print("no matching traffic.")
        return

    headers = ["DATETIME (UTC)", "METHOD", "STATUS", "BYTES", "MODULE", "PATH"]
    _print_table(headers, rows, right_align={2, 3})
    print(f"\n{len(rows)} row(s)", end="")
    if args.limit and len(rows) == args.limit:
        print(f" (limited to {args.limit}; raise --limit or use --count)", end="")
    print()


if __name__ == "__main__":
    main()

"""Print random, first, last, or all SQLite rows as readable console tables."""
import argparse
from contextlib import closing
import itertools
import shutil
import sqlite3
import sys
import textwrap
from pathlib import Path


def quote(name):
    return '"' + name.replace('"', '""') + '"'


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError('must be at least 1')
    return number


def cell(value):
    if value is None:
        return 'NULL'
    if isinstance(value, bytes):
        return '0x' + value.hex()
    # Keep multiline HTTP data readable, but escape terminal control sequences.
    return ''.join(char if char == '\n' or char.isprintable() else repr(char)[1:-1]
                   for char in str(value).replace('\r\n', '\n'))


def wrapped(value, width):
    return [part for line in cell(value).split('\n')
            for part in (textwrap.wrap(line, width, replace_whitespace=False,
                                       drop_whitespace=False) or [''])]


def print_table(columns, rows, width):
    preview = list(itertools.islice(rows, 25))
    widths = [max(len(name), min(40, max((len(line) for row in preview
              for line in cell(row[index]).split('\n')), default=0)))
              for index, name in enumerate(columns)]
    vertical = sum(len(name) for name in columns) + 3 * len(columns) + 1 > width
    if vertical:
        key_width = min(max(map(len, columns)), width // 3)
        widths = [key_width, width - key_width - 7]
        display_columns = ['Column', 'Value']
    else:
        while sum(widths) + 3 * len(columns) + 1 > width:
            index = max(range(len(widths)), key=lambda i: widths[i] - len(columns[i]))
            widths[index] -= 1
        display_columns = columns
    border = '+' + '+'.join('-' * (size + 2) for size in widths) + '+'

    def line(values):
        parts = [wrapped(value, size) for value, size in zip(values, widths)]
        for index in range(max(map(len, parts))):
            print('| ' + ' | '.join((part[index] if index < len(part) else '').ljust(size)
                                    for part, size in zip(parts, widths)) + ' |')

    if not vertical:
        print(border)
        line(display_columns)
        print(border)
    count = 0
    for count, row in enumerate(itertools.chain(preview, rows), 1):
        if vertical:
            print(f'Row {count}')
            print(border)
            line(display_columns)
            print(border)
            for name, value in zip(columns, row):
                line([name, value])
        else:
            line(row)
        print(border)
    if not count:
        print('(no rows)')
    print(f'{count} row(s)\n')


def ordering(conn, table):
    info = conn.execute(f'PRAGMA table_info({quote(table)})').fetchall()
    names = {row[1].lower() for row in info}
    for name in ('_rowid_', 'rowid', 'oid'):
        if name not in names:
            try:
                conn.execute(f'SELECT {name} FROM {quote(table)} LIMIT 0')
            except sqlite3.OperationalError:
                continue
            return [quote(name)]
    primary = sorted((row[5], row[1]) for row in info if row[5])
    if primary:
        return [quote(name) for _, name in primary]
    raise ValueError(f'{table}: no usable rowid or primary key for first/last ordering')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('db', nargs='?', default='leviosa.db', help='SQLite database (default: leviosa.db)')
    parser.add_argument('-n', '--rows', type=positive, default=5, help='Number of random rows per table (default: 5)')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--first', type=positive, metavar='N', help='First N rows in rowid/primary-key order')
    modes.add_argument('--last', type=positive, metavar='N', help='Last N rows, newest/highest key first')
    modes.add_argument('--dump', '--all', action='store_true', help='Print all rows in all selected tables, without truncating values')
    parser.add_argument('--table', action='append', help='Select a table (repeatable; default: all user tables)')
    parser.add_argument('--width', type=positive, default=shutil.get_terminal_size((120, 24)).columns,
                        help='Console table width; wide schemas use a column/value layout')
    args = parser.parse_args(argv)
    if args.width < 40:
        parser.error('--width must be at least 40')
    try:
        with closing(sqlite3.connect(Path(args.db).expanduser().resolve().as_uri() + '?mode=ro', uri=True)) as conn:
            conn.execute('PRAGMA query_only=ON')
            tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
            selected = list(dict.fromkeys(args.table)) if args.table else tables
            if any(name not in tables for name in selected):
                raise ValueError('Unknown table; available tables: ' + ', '.join(tables))
            if not selected:
                print('(no user tables)')
            for table in selected:
                sql = f'SELECT * FROM {quote(table)}'
                values = ()
                if not args.dump:
                    count = args.first or args.last or args.rows
                    if args.first or args.last:
                        direction = 'DESC' if args.last else 'ASC'
                        sql += ' ORDER BY ' + ', '.join(name + ' ' + direction for name in ordering(conn, table))
                    else:
                        sql += ' ORDER BY RANDOM()'
                    sql += ' LIMIT ?'
                    values = (count,)
                cursor = conn.execute(sql, values)
                print(f'Table: {table}')
                print_table([item[0] for item in cursor.description], iter(cursor), args.width)
    except BrokenPipeError:
        return 0
    except (sqlite3.Error, OSError, ValueError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

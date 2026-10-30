import sqlite3

import pytest

from sqlite_sample import main


@pytest.fixture
def database(tmp_path):
    path = tmp_path / 'sample.sqlite'
    with sqlite3.connect(path) as conn:
        conn.execute('CREATE TABLE ACTIVITY (id INTEGER, message TEXT)')
        conn.executemany('INSERT INTO ACTIVITY VALUES (?, ?)', [(i, f'value-{i}') for i in range(1, 9)])
        conn.execute('CREATE TABLE "other table" (key TEXT PRIMARY KEY, data BLOB) WITHOUT ROWID')
        conn.executemany('INSERT INTO "other table" VALUES (?, ?)', [('b', b'\x00\xff'), ('a', None)])
    return path


def test_default_five_random_rows_with_names(database, capsys):
    assert main([str(database), '--table', 'ACTIVITY']) == 0
    out = capsys.readouterr().out
    assert 'Table: ACTIVITY' in out and 'message' in out
    assert '5 row(s)' in out
    assert len([i for i in range(1, 9) if f'value-{i}' in out]) == 5


@pytest.mark.parametrize('args,expected', [(['--first', '2'], [1, 2]), (['--last', '2'], [8, 7])])
def test_first_last_order(database, capsys, args, expected):
    assert main([str(database), '--table', 'ACTIVITY', *args]) == 0
    out = capsys.readouterr().out
    present = [i for i in range(1, 9) if f'value-{i}' in out]
    assert sorted(present) == sorted(expected)
    assert out.index(f'value-{expected[0]}') < out.index(f'value-{expected[1]}')


def test_dump_all_tables_values_and_primary_key_order(database, capsys):
    assert main([str(database), '--dump']) == 0
    out = capsys.readouterr().out
    assert '8 row(s)' in out and '2 row(s)' in out
    assert 'Table: other table' in out and 'NULL' in out and '0x00ff' in out
    assert main([str(database), '--table', 'other table', '--first', '1']) == 0
    assert 'NULL' in capsys.readouterr().out
    assert main([str(database), '--table', 'other table', '--last', '1']) == 0
    assert '0x00ff' in capsys.readouterr().out


def test_custom_count_and_vertical_multiline_display(database, capsys):
    with sqlite3.connect(database) as conn:
        conn.execute('CREATE TABLE wide ("long column number one" TEXT, "long column number two" TEXT)')
        conn.execute('INSERT INTO wide VALUES (?,?)', ('first line\nsecond line\x1b[31m', 'x' * 100))
    assert main([str(database), '-n', '2', '--table', 'ACTIVITY']) == 0
    assert '2 row(s)' in capsys.readouterr().out
    assert main([str(database), '--table', 'wide', '--dump', '--width', '50']) == 0
    out = capsys.readouterr().out
    assert 'Column' in out and 'Value' in out and 'second line' in out
    assert '\x1b' not in out
    assert all(len(line) <= 50 for line in out.splitlines())


def test_missing_database_is_not_created(tmp_path, capsys):
    path = tmp_path / 'missing.sqlite'
    assert main([str(path)]) == 1
    assert not path.exists()
    assert 'error:' in capsys.readouterr().err


def test_table_selection_is_not_sql(database, capsys):
    assert main([str(database), '--table', 'ACTIVITY; DROP TABLE ACTIVITY']) == 1
    assert 'Unknown table' in capsys.readouterr().err
    with sqlite3.connect(database) as conn:
        assert conn.execute('SELECT count(*) FROM ACTIVITY').fetchone()[0] == 8

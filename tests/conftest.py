import pytest
from pathlib import Path

from core.models import LeviosaContext
from core.parsers import parse_request_file

EXAMPLE_JSON = Path(__file__).parent.parent / "example_requests_input_file.json"


@pytest.fixture
def sample_requests():
    return parse_request_file(str(EXAMPLE_JSON))


@pytest.fixture
def context():
    return LeviosaContext()


@pytest.fixture
def tmp_wordlist(tmp_path):
    wl = tmp_path / "wordlist.txt"
    wl.write_text("payload1\npayload2\npayload3\n")
    return str(wl)

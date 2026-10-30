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


@pytest.fixture(autouse=True)
def aioresponses_stream_writer_compatibility(monkeypatch):
    """aioresponses 0.7.9 omits aiohttp 3.14's new constructor argument.

    Only adapt the mock response factory; real HTTP sessions and runtime code
    retain aiohttp's unmodified constructor and continue to exercise the wire.
    """
    import inspect
    import aiohttp
    import aioresponses.core
    if 'stream_writer' not in inspect.signature(aiohttp.ClientResponse).parameters:
        return
    response_class = aiohttp.ClientResponse

    class MockResponse(response_class):
        def __init__(self, *args, **kwargs):
            from types import SimpleNamespace
            kwargs.setdefault('stream_writer', SimpleNamespace(output_size=0))
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(aioresponses.core, 'ClientResponse', MockResponse)

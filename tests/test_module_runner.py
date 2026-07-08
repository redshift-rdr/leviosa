from unittest.mock import patch

import pytest

from core.config import Config
from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse
from core.runner import run_modules
from modules.base import BaseModule
from modules.passthrough import PassthroughModule


def make_request(url="http://example.com"):
    return LeviosaRequest(method="GET", url=url, headers=[], params=[])


def make_response(url="http://example.com", status=200):
    req = make_request(url)
    return LeviosaResponse(status=status, headers={}, body=b"", request=req)


def fake_send_factory(captured=None, responses=None, recorded=None):
    """
    Build a replacement for core.requester.send: a real async generator.

    It consumes the (possibly lazy) request iterable — capturing the requests
    into `captured` if given — then yields either a preset `responses` list or
    one 200 response per request. `recorded` receives the read_body flag.
    """
    async def fake_send(reqs, config, read_body=True):
        if recorded is not None:
            recorded["read_body"] = read_body
        consumed = list(reqs)
        if captured is not None:
            captured.extend(consumed)
        out = responses if responses is not None else [
            LeviosaResponse(status=200, headers={}, body=b"", request=r) for r in consumed
        ]
        for resp in out:
            yield resp

    return fake_send


@pytest.fixture
def cfg():
    c = Config()
    c.proxy_enabled = False
    return c


# ---------------------------------------------------------------------------
# PassthroughModule unit tests
# ---------------------------------------------------------------------------

class TestPassthroughModule:
    async def test_mutate_returns_same_list(self):
        requests = [make_request("http://a.com"), make_request("http://b.com")]
        result = await PassthroughModule().mutate(requests, LeviosaContext())
        assert result is requests

    async def test_analyze_one_produces_no_output(self, capsys):
        await PassthroughModule().analyze_one(make_response(), LeviosaContext())
        assert capsys.readouterr().out == ""

    async def test_finalize_produces_no_output(self, capsys):
        await PassthroughModule().finalize(LeviosaContext())
        assert capsys.readouterr().out == ""

    async def test_mutate_empty_list(self):
        result = await PassthroughModule().mutate([], LeviosaContext())
        assert result == []


# ---------------------------------------------------------------------------
# run_modules integration tests (send() is patched with a fake async generator)
# ---------------------------------------------------------------------------

class TestRunModules:
    async def test_mutate_called_before_analyze_and_finalize(self, cfg):
        call_log = []

        class SpyModule(BaseModule):
            async def mutate(self, requests, context):
                call_log.append("mutate")
                return requests

            async def analyze_one(self, response, context):
                call_log.append("analyze_one")

            async def finalize(self, context):
                call_log.append("finalize")

        with patch("core.runner.send", fake_send_factory()):
            await run_modules([SpyModule()], lambda: iter([make_request()]), cfg, LeviosaContext())

        assert call_log == ["mutate", "analyze_one", "finalize"]

    async def test_modules_run_sequentially(self, cfg):
        call_log = []

        def make_spy(label):
            class SpyModule(BaseModule):
                async def mutate(self, requests, context):
                    call_log.append(f"{label}.mutate")
                    return requests

                async def analyze_one(self, response, context):
                    call_log.append(f"{label}.analyze_one")

                async def finalize(self, context):
                    call_log.append(f"{label}.finalize")

            return SpyModule()

        with patch("core.runner.send", fake_send_factory()):
            await run_modules(
                [make_spy("m1"), make_spy("m2")],
                lambda: iter([make_request()]),
                cfg,
                LeviosaContext(),
            )

        assert call_log == [
            "m1.mutate", "m1.analyze_one", "m1.finalize",
            "m2.mutate", "m2.analyze_one", "m2.finalize",
        ]

    async def test_analyze_one_called_once_per_response_then_finalize(self, cfg):
        log = []
        responses = [
            make_response("http://x.com/a", 200),
            make_response("http://x.com/b", 404),
            make_response("http://x.com/c", 500),
        ]

        class M(BaseModule):
            async def mutate(self, requests, context):
                return requests

            async def analyze_one(self, response, context):
                log.append(response.status)

            async def finalize(self, context):
                log.append("finalize")

        with patch("core.runner.send", fake_send_factory(responses=responses)):
            await run_modules([M()], lambda: iter([make_request()]), cfg, LeviosaContext())

        assert log == [200, 404, 500, "finalize"]

    async def test_factory_called_fresh_per_module(self, cfg):
        calls = {"n": 0}

        def factory():
            calls["n"] += 1
            return iter([make_request()])

        class M(BaseModule):
            async def mutate(self, requests, context):
                return requests

        with patch("core.runner.send", fake_send_factory()):
            await run_modules([M(), M()], factory, cfg, LeviosaContext())

        assert calls["n"] == 2

    async def test_each_module_receives_original_requests(self, cfg):
        received = []

        class MutatingModule(BaseModule):
            async def mutate(self, requests, context):
                return [make_request("http://mutated.com")]

        class RecordingModule(BaseModule):
            async def mutate(self, requests, context):
                reqs = list(requests)
                received.extend(reqs)
                return reqs

        with patch("core.runner.send", fake_send_factory()):
            await run_modules(
                [MutatingModule(), RecordingModule()],
                lambda: iter([make_request("http://original.com")]),
                cfg,
                LeviosaContext(),
            )

        assert len(received) == 1
        assert received[0].url == "http://original.com"

    async def test_send_receives_mutated_requests(self, cfg):
        mutated = [make_request("http://mutated-a.com"), make_request("http://mutated-b.com")]
        captured = []

        class ExpandingModule(BaseModule):
            async def mutate(self, requests, context):
                return mutated

        with patch("core.runner.send", fake_send_factory(captured=captured)):
            await run_modules(
                [ExpandingModule()],
                lambda: iter([make_request("http://original.com")]),
                cfg,
                LeviosaContext(),
            )

        assert [r.url for r in captured] == ["http://mutated-a.com", "http://mutated-b.com"]

    async def test_needs_body_propagates_to_send(self, cfg):
        recorded = {}

        class StatusOnly(BaseModule):
            needs_body = False

            async def mutate(self, requests, context):
                return requests

        with patch("core.runner.send", fake_send_factory(recorded=recorded)):
            await run_modules([StatusOnly()], lambda: iter([make_request()]), cfg, LeviosaContext())

        assert recorded["read_body"] is False

    async def test_needs_body_true_propagates_to_send(self, cfg):
        recorded = {}

        class WithBody(BaseModule):
            needs_body = True

            async def mutate(self, requests, context):
                return requests

        with patch("core.runner.send", fake_send_factory(recorded=recorded)):
            await run_modules([WithBody()], lambda: iter([make_request()]), cfg, LeviosaContext())

        assert recorded["read_body"] is True

    async def test_context_shared_across_modules(self, cfg):
        class WriterModule(BaseModule):
            async def mutate(self, requests, context):
                return requests

            async def finalize(self, context):
                context.data["token"] = "secret"

        class ReaderModule(BaseModule):
            read_value = None

            async def mutate(self, requests, context):
                ReaderModule.read_value = context.data.get("token")
                return requests

        with patch("core.runner.send", fake_send_factory()):
            await run_modules(
                [WriterModule(), ReaderModule()],
                lambda: iter([make_request()]),
                cfg,
                LeviosaContext(),
            )

        assert ReaderModule.read_value == "secret"

    async def test_analyze_receives_responses_from_send(self, cfg):
        fake_responses = [make_response("http://example.com", status=403)]
        received_responses = []

        class RecordingModule(BaseModule):
            async def mutate(self, requests, context):
                return requests

            async def analyze_one(self, response, context):
                received_responses.append(response)

        with patch("core.runner.send", fake_send_factory(responses=fake_responses)):
            await run_modules(
                [RecordingModule()],
                lambda: iter([make_request()]),
                cfg,
                LeviosaContext(),
            )

        assert len(received_responses) == 1
        assert received_responses[0].status == 403

    async def test_empty_modules_list_does_nothing(self, cfg):
        called = {"n": 0}

        async def fake_send(reqs, config, read_body=True):
            called["n"] += 1
            for r in reqs:
                yield make_response(r.url)

        with patch("core.runner.send", fake_send):
            await run_modules([], lambda: iter([make_request()]), cfg, LeviosaContext())

        assert called["n"] == 0

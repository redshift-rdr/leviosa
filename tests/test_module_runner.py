from unittest.mock import AsyncMock, patch

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

    async def test_analyze_produces_no_output(self, capsys):
        await PassthroughModule().analyze([make_response()], LeviosaContext())
        assert capsys.readouterr().out == ""

    async def test_mutate_empty_list(self):
        result = await PassthroughModule().mutate([], LeviosaContext())
        assert result == []


# ---------------------------------------------------------------------------
# run_modules integration tests (send() is patched)
# ---------------------------------------------------------------------------

class TestRunModules:
    async def test_mutate_called_before_analyze(self, cfg):
        call_log = []

        class SpyModule(BaseModule):
            async def mutate(self, requests, context):
                call_log.append("mutate")
                return requests

            async def analyze(self, responses, context):
                call_log.append("analyze")

        with patch("core.runner.send", new_callable=AsyncMock) as mock_send:
            mock_send.return_value = []
            await run_modules([SpyModule()], [], cfg, LeviosaContext())

        assert call_log == ["mutate", "analyze"]

    async def test_modules_run_sequentially(self, cfg):
        call_log = []

        def make_spy(label):
            class SpyModule(BaseModule):
                async def mutate(self, requests, context):
                    call_log.append(f"{label}.mutate")
                    return requests

                async def analyze(self, responses, context):
                    call_log.append(f"{label}.analyze")

            return SpyModule()

        with patch("core.runner.send", new_callable=AsyncMock) as mock_send:
            mock_send.return_value = []
            await run_modules([make_spy("m1"), make_spy("m2")], [], cfg, LeviosaContext())

        assert call_log == ["m1.mutate", "m1.analyze", "m2.mutate", "m2.analyze"]

    async def test_each_module_receives_original_requests(self, cfg):
        original = [make_request("http://original.com")]
        received = []

        class MutatingModule(BaseModule):
            async def mutate(self, requests, context):
                return [make_request("http://mutated.com")]

            async def analyze(self, responses, context):
                pass

        class RecordingModule(BaseModule):
            async def mutate(self, requests, context):
                received.extend(requests)
                return requests

            async def analyze(self, responses, context):
                pass

        with patch("core.runner.send", new_callable=AsyncMock) as mock_send:
            mock_send.return_value = []
            await run_modules([MutatingModule(), RecordingModule()], original, cfg, LeviosaContext())

        assert len(received) == 1
        assert received[0].url == "http://original.com"

    async def test_send_receives_mutated_requests(self, cfg):
        original = [make_request("http://original.com")]
        mutated = [make_request("http://mutated-a.com"), make_request("http://mutated-b.com")]

        class ExpandingModule(BaseModule):
            async def mutate(self, requests, context):
                return mutated

            async def analyze(self, responses, context):
                pass

        with patch("core.runner.send", new_callable=AsyncMock) as mock_send:
            mock_send.return_value = []
            await run_modules([ExpandingModule()], original, cfg, LeviosaContext())

        sent = mock_send.call_args[0][0]
        assert [r.url for r in sent] == ["http://mutated-a.com", "http://mutated-b.com"]

    async def test_context_shared_across_modules(self, cfg):
        class WriterModule(BaseModule):
            async def mutate(self, requests, context):
                return requests

            async def analyze(self, responses, context):
                context.data["token"] = "secret"

        class ReaderModule(BaseModule):
            read_value = None

            async def mutate(self, requests, context):
                ReaderModule.read_value = context.data.get("token")
                return requests

            async def analyze(self, responses, context):
                pass

        with patch("core.runner.send", new_callable=AsyncMock) as mock_send:
            mock_send.return_value = []
            await run_modules([WriterModule(), ReaderModule()], [], cfg, LeviosaContext())

        assert ReaderModule.read_value == "secret"

    async def test_analyze_receives_responses_from_send(self, cfg):
        fake_responses = [make_response("http://example.com", status=403)]
        received_responses = []

        class RecordingModule(BaseModule):
            async def mutate(self, requests, context):
                return requests

            async def analyze(self, responses, context):
                received_responses.extend(responses)

        with patch("core.runner.send", new_callable=AsyncMock) as mock_send:
            mock_send.return_value = fake_responses
            await run_modules([RecordingModule()], [make_request()], cfg, LeviosaContext())

        assert len(received_responses) == 1
        assert received_responses[0].status == 403

    async def test_empty_modules_list_does_nothing(self, cfg):
        with patch("core.runner.send", new_callable=AsyncMock) as mock_send:
            await run_modules([], [make_request()], cfg, LeviosaContext())
        mock_send.assert_not_called()

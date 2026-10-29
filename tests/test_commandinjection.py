import html
import subprocess

import pytest
from aioresponses import aioresponses

from core.config import Config
from core.loader import load_modules
from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse, Param, RequestBody
from core.options import ValidationParser, setup_modules
from core.runner import run_modules
from core.scans import prepare_scan, read_scan
from leviosa import build_parser
from modules.commandinjection import CommandInjection
from modules.traversal import Traversal


class Reporter:
    def __init__(self):
        self.findings = []

    def report(self, finding):
        self.findings.append(finding)

    def write(self, message):
        pass


def request(**kwargs):
    return LeviosaRequest(**({'method': 'GET', 'url': 'https://app.test/', 'headers': [],
                             'params': [Param('query', 'host', 'localhost')]} | kwargs))


def configured(tmp_path, payload=';{posix};#', markers=()):
    path = tmp_path / 'payloads.txt'
    path.write_text(payload + '\n')
    module = CommandInjection()
    module.setup(['--command-payloads', str(path)] + [arg for marker in markers for arg in ('--command-marker', marker)])
    return module


async def probe(module, output, *, baseline='', baseline_status=200, status=200, reverse=False):
    ctx = LeviosaContext(reporter=Reporter())
    variants = list(await module.mutate([request()], ctx))
    replies = []
    for variant in variants:
        _, location, _, payload, marker, _ = variant.metadata['commandinjection']
        body = baseline if location is None else output(payload, marker)
        replies.append(LeviosaResponse(baseline_status if location is None else status, {}, body.encode(), variant))
    for reply in reversed(replies) if reverse else replies:
        await module.analyze_one(reply, ctx)
    assert ctx.state['commandinjection.results'] == {}
    return ctx.reporter.findings


@pytest.mark.parametrize('template', [';{posix};#', '&{cmd}&rem ', ';{powershell};#'])
@pytest.mark.parametrize('reverse', [False, True])
async def test_generated_output_and_late_baseline(tmp_path, template, reverse):
    module = configured(tmp_path, template)
    finding, = await probe(module, lambda p, marker: '<pre>' + marker + '</pre>', reverse=reverse)
    assert finding.evidence['signatures'] == ['generated-command-marker']
    assert finding.confidence == 'indicator'
    assert finding.evidence['parameter'] == 'host'
    marker = finding.request.metadata['commandinjection'][4]
    assert marker not in finding.evidence['payload']


@pytest.mark.parametrize('encode', [str, html.escape])
async def test_reflection_is_not_execution(tmp_path, encode):
    assert not await probe(configured(tmp_path), lambda p, marker: encode(p))


async def test_literal_marker_payload_is_not_execution_evidence(tmp_path):
    module = configured(tmp_path, ';echo {marker}')
    assert not await probe(module, lambda p, marker: marker)


@pytest.mark.parametrize('body,expected', [
    ('uid=1000(app) gid=1000(app) groups=1000(app)', 'unix-id-output'),
    ('APPHOST\\app S-1-5-21-123456-234567-345678-1001', 'windows-sid-output'),
])
async def test_wordlist_output_signatures_and_baseline_suppression(tmp_path, body, expected):
    module = configured(tmp_path, ';id')
    finding, = await probe(module, lambda p, marker: body)
    assert finding.evidence['signatures'] == [expected]
    assert not await probe(module, lambda p, marker: body, baseline=body, reverse=True)


@pytest.mark.parametrize('body', ['sh: command not found', 'syntax error near unexpected token',
    'Internal server error', 'uid=1000', 'gid=1000(app)', 'S-1-5', 'appuser', 'localhost', ''])
async def test_generic_errors_and_weak_outputs_do_not_flag(tmp_path, body):
    assert not await probe(configured(tmp_path), lambda p, marker: body, status=500)


@pytest.mark.parametrize('baseline_status,status', [(0, 200), (200, 0)])
async def test_network_errors_suppress_evidence(tmp_path, baseline_status, status):
    assert not await probe(configured(tmp_path), lambda p, marker: marker,
                           baseline_status=baseline_status, status=status, reverse=True)


async def test_custom_expected_output_and_echo_rejection(tmp_path):
    module = configured(tmp_path, ';custom-command', ['controlled-output-7392'])
    finding, = await probe(module, lambda p, marker: 'controlled-output-7392')
    assert finding.evidence['signatures'] == ['custom-marker-1']
    reflected = configured(tmp_path, ';echo controlled-output-7392', ['controlled-output-7392'])
    assert not await probe(reflected, lambda p, marker: p)


async def test_lazy_mutation_preserves_seed_and_covers_supported_inputs():
    module = CommandInjection()
    seed = request(url='https://app.test/?host=a&host=b', params=[],
                   body=RequestBody('json', {'targets': [{'host': 'localhost'}]}))
    variants = await module.mutate([seed], LeviosaContext())
    assert iter(variants) is variants
    variants = list(variants)
    assert len(variants) == 1 + 3 * len(module._payloads)
    assert seed.metadata == {}
    assert seed.body.value == {'targets': [{'host': 'localhost'}]}
    assert seed.url.endswith('host=a&host=b')
    assert all(v.metadata['commandinjection'][4] not in v.metadata['commandinjection'][3] for v in variants[1:])
    other = list(await module.mutate([seed], LeviosaContext()))
    assert variants[0].metadata['commandinjection'][4] != other[0].metadata['commandinjection'][4]


async def test_form_input_and_no_inputs(tmp_path):
    module = configured(tmp_path)
    variants = list(await module.mutate([request(params=[Param('form', 'host', 'original')])], LeviosaContext()))
    assert variants[1].params[0].value.startswith(';printf')
    assert list(await module.mutate([request(params=[])], LeviosaContext())) == []


@pytest.mark.parametrize('marker', ['', '  '])
def test_empty_markers_rejected(marker):
    with pytest.raises(ValueError, match='empty'):
        CommandInjection().setup(['--command-marker', marker])


@pytest.mark.parametrize('content', ['', '\n \n\t'])
def test_empty_payload_files_rejected(tmp_path, content):
    path = tmp_path / 'empty.txt'
    path.write_text(content)
    with pytest.raises(ValueError, match='empty'):
        CommandInjection().setup(['--command-payloads', str(path)])


def test_missing_payload_file_rejected(tmp_path):
    with pytest.raises(FileNotFoundError):
        CommandInjection().setup(['--command-payloads', str(tmp_path / 'missing')])


def test_literal_custom_payload_and_placeholders_preserved(tmp_path):
    module = configured(tmp_path, '  ;if true; then {posix}; fi # ${HOME} %0a  ')
    rendered = module._render(module._payloads[0], 'leviosa1234567890')
    assert rendered.startswith('  ;if true; then printf')
    assert rendered.endswith(' # ${HOME} %0a  ')


def test_posix_marker_command_actually_produces_expected_output():
    # Execute only the fixed built-in printf command, never wordlist contents.
    marker = 'leviosa1234567890abcdef'
    command = CommandInjection._render('{posix}', marker)
    result = subprocess.run(['/bin/sh', '-c', command], capture_output=True, text=True, check=True)
    assert result.stdout == marker
    assert marker not in command


def test_discovery_and_shared_options():
    module, = load_modules(['commandinjection'])
    assert isinstance(module, CommandInjection)
    assert module.tool == 'Intruder'
    setup_modules([module, Traversal()], [], [], ValidationParser(add_help=False))


def test_scan_relative_wordlist(tmp_path, monkeypatch):
    (tmp_path / 'payloads.txt').write_text(';{posix};#\n')
    path = tmp_path / 'scan.toml'
    path.write_text('target="https://app.test/?host=localhost"\n[[steps]]\nmodule="commandinjection"\nargs=["--command-payloads", "payloads.txt"]\n')
    monkeypatch.chdir(tmp_path.parent)
    plan = prepare_scan(read_scan(str(path)), Config(no_proxy=True),
                        ValidationParser(add_help=False, parents=[build_parser()], allow_abbrev=False))
    assert plan.steps[0].module._payloads == [';{posix};#']


async def test_transport_does_not_follow_redirects(tmp_path):
    module = configured(tmp_path, ';id')
    ctx = LeviosaContext(reporter=Reporter())
    config = Config(no_proxy=True, follow_redirects=True)
    with aioresponses() as mocked:
        mocked.get('https://app.test/?host=localhost', body='baseline')
        mocked.get('https://app.test/?host=;id', body='uid=1000(app) gid=1000(app)')
        await run_modules([module], lambda: [request()], config, ctx)
        assert len(ctx.reporter.findings) == 1
        assert all(call.kwargs['allow_redirects'] is False for calls in mocked.requests.values() for call in calls)
    assert config.follow_redirects is True

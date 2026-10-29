import base64

import pytest
from aioresponses import CallbackResult, aioresponses

from core.config import Config
from core.loader import load_modules
from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse, Param, RequestBody
from core.options import ValidationParser, setup_modules
from core.runner import run_modules
from core.scans import prepare_scan, read_scan
from leviosa import build_parser
from modules.traversal import Traversal
from modules.xsspayloads import XssPayloads


PASSWD = 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n'
WIN_INI = '; Windows configuration\r\n[fonts]\r\n[extensions]\r\n[mci extensions]\r\n'


class Reporter:
    def __init__(self):
        self.findings = []

    def report(self, finding):
        self.findings.append(finding)

    def write(self, message):
        pass


def request(**kwargs):
    return LeviosaRequest(**({'method': 'GET', 'url': 'https://app.test/', 'headers': [],
                             'params': [Param('query', 'file', 'public.txt')]} | kwargs))


def response(req, body='', status=200):
    return LeviosaResponse(status, {}, body.encode(), req)


def configured(tmp_path, payload='../../etc/passwd', markers=()):
    path = tmp_path / 'payloads.txt'
    path.write_text(payload + '\n')
    module = Traversal()
    module.setup(['--traversal-payloads', str(path)] + [arg for marker in markers for arg in ('--traversal-marker', marker)])
    return module


async def run_probe(module, body, baseline='', *, baseline_status=200, status=200, reverse=False):
    ctx = LeviosaContext(reporter=Reporter())
    variants = list(await module.mutate([request()], ctx))
    replies = [response(v, baseline if v.metadata['traversal'][1] is None else body,
                        baseline_status if v.metadata['traversal'][1] is None else status) for v in variants]
    for reply in reversed(replies) if reverse else replies:
        await module.analyze_one(reply, ctx)
    assert ctx.state['traversal.results'] == {}
    return ctx.reporter.findings


@pytest.mark.parametrize('body,signature', [(PASSWD, 'unix-passwd'),
    ('<pre>' + PASSWD + '</pre>', 'unix-passwd'),
    ('root::0:0::/root:/bin/sh\n', 'unix-passwd'),
    (WIN_INI, 'windows-win.ini'), ('<pre>[fonts]\n[extensions]</pre>', 'windows-win.ini')])
@pytest.mark.parametrize('reverse', [False, True])
async def test_file_content_evidence_with_out_of_order_baseline(tmp_path, body, signature, reverse):
    module = configured(tmp_path)
    finding, = await run_probe(module, body, reverse=reverse)
    assert signature in finding.evidence['signatures']
    assert finding.confidence == 'indicator'
    assert finding.evidence['parameter'] == 'file'
    assert finding.evidence['payload'] == '../../etc/passwd'
    assert finding.evidence['baseline_status'] == 200


@pytest.mark.parametrize('body', ['root:x:0:0', '[fonts]', '[fonts]\n[fonts]', 'root:x:1:0:root:/root:/bin/bash',
    'failed to open stream: No such file or directory', 'include(../../etc/passwd): failed',
    'File not found', 'Internal server error', 'root:x:0:0:<not a file>', ''])
async def test_errors_and_weak_patterns_are_not_file_access_evidence(tmp_path, body):
    assert not await run_probe(configured(tmp_path), body, status=500)


@pytest.mark.parametrize('reverse', [False, True])
async def test_existing_file_content_not_reported(tmp_path, reverse):
    assert not await run_probe(configured(tmp_path), PASSWD, baseline=PASSWD, reverse=reverse)


async def test_unreachable_baseline_suppresses_findings(tmp_path):
    assert not await run_probe(configured(tmp_path), PASSWD, baseline_status=0, reverse=True)


async def test_unreachable_variant_suppresses_findings(tmp_path):
    assert not await run_probe(configured(tmp_path), PASSWD, status=0)


async def test_new_signature_still_reported_when_another_exists_in_baseline(tmp_path):
    finding, = await run_probe(configured(tmp_path), PASSWD + WIN_INI, baseline=PASSWD)
    assert finding.evidence['signatures'] == ['windows-win.ini']


async def test_php_filter_base64_content_in_html(tmp_path):
    module = configured(tmp_path, 'php://filter/convert.base64-encode/resource=/etc/passwd')
    body = '<div>' + base64.b64encode(PASSWD.encode()).decode() + '</div>'
    finding, = await run_probe(module, body)
    assert finding.evidence['signatures'] == ['base64:unix-passwd']
    assert not await run_probe(module, body, baseline=PASSWD)
    assert not await run_probe(module, PASSWD, baseline=body)


@pytest.mark.parametrize('body', ['A' * 33, 'A' * 32 + '=', 'Q' * 400, 'not encoded'])
async def test_non_file_base64_does_not_flag(tmp_path, body):
    module = configured(tmp_path, 'php://filter/convert.base64-encode/resource=/etc/passwd')
    assert not await run_probe(module, body)


async def test_controlled_test_file_marker_and_payload_echo(tmp_path):
    module = configured(tmp_path, '../canary.txt', ['owned-file-7392'])
    finding, = await run_probe(module, '<pre>owned-file-7392</pre>')
    assert finding.evidence['signatures'] == ['custom-marker-1']
    assert not await run_probe(module, 'owned-file-7392', baseline='owned-file-7392')
    echo = configured(tmp_path, '../canary.txt', ['canary.txt'])
    assert not await run_probe(echo, 'You submitted ../canary.txt')


async def test_inputs_lazy_independent_and_original_untouched(tmp_path):
    module = configured(tmp_path)
    seed = request(url='https://app.test/?file=a&file=b', params=[],
                   body=RequestBody('json', {'files': [{'name': 'public'}]}))
    stream = await module.mutate([seed], LeviosaContext())
    assert iter(stream) is stream
    variants = list(stream)
    assert len(variants) == 4
    assert {v.metadata['traversal'][4] for v in variants} == {4}
    assert seed.body.value['files'][0]['name'] == 'public'
    assert seed.url.endswith('file=a&file=b')
    assert seed.metadata == {}
    assert variants[-1].body.value['files'][0]['name'] == '../../etc/passwd'


async def test_form_input_supported(tmp_path):
    module = configured(tmp_path)
    seed = request(method='POST', params=[Param('form', 'filename', 'public')])
    original, variant = list(await module.mutate([seed], LeviosaContext()))
    assert variant.params[0].value == '../../etc/passwd'
    assert original.params[0].value == 'public'


async def test_non_injectable_request_skipped():
    assert list(await Traversal().mutate([request(params=[])], LeviosaContext())) == []


async def test_custom_payloads_preserve_encoding_and_whitespace(tmp_path):
    module = configured(tmp_path, ' %252e%252e%252fetc/passwd%00 ')
    variants = list(await module.mutate([request()], LeviosaContext()))
    assert variants[1].params[0].value == ' %252e%252e%252fetc/passwd%00 '


@pytest.mark.parametrize('contents', ['', '\n  \n\t'])
def test_empty_wordlists_rejected(tmp_path, contents):
    path = tmp_path / 'empty.txt'
    path.write_text(contents)
    with pytest.raises(ValueError, match='empty'):
        Traversal().setup(['--traversal-payloads', str(path)])


def test_missing_wordlist_rejected(tmp_path):
    with pytest.raises(FileNotFoundError):
        Traversal().setup(['--traversal-payloads', str(tmp_path / 'missing')])


@pytest.mark.parametrize('marker', ['', '  '])
def test_empty_marker_rejected(marker):
    with pytest.raises(ValueError, match='empty'):
        Traversal().setup(['--traversal-marker', marker])


def test_discovery_category_and_composable_options():
    module, = load_modules(['traversal'])
    assert isinstance(module, Traversal)
    assert module.tool == 'Intruder'
    setup_modules([module, XssPayloads()], [], [], ValidationParser(add_help=False))


def test_scan_relative_payload_path(tmp_path, monkeypatch):
    (tmp_path / 'payloads.txt').write_text('../canary.txt\n')
    path = tmp_path / 'scan.toml'
    path.write_text('target="https://app.test/?file=public"\n[[steps]]\nmodule="traversal"\nargs=["--traversal-payloads", "payloads.txt", "--traversal-marker", "unique-canary"]\n')
    monkeypatch.chdir(tmp_path.parent)
    plan = prepare_scan(read_scan(str(path)), Config(no_proxy=True),
                        ValidationParser(add_help=False, parents=[build_parser()], allow_abbrev=False))
    assert plan.steps[0].module._payloads == ['../canary.txt']
    assert plan.steps[0].module._markers == ['unique-canary']


async def test_redirect_following_disabled_and_query_payload_serialized(tmp_path):
    module = configured(tmp_path)
    ctx = LeviosaContext(reporter=Reporter())
    config = Config(follow_redirects=True, no_proxy=True)
    with aioresponses() as mocked:
        mocked.get('https://app.test/?file=public.txt', body='baseline')
        mocked.get('https://app.test/?file=../../etc/passwd', body=PASSWD)
        await run_modules([module], lambda: [request()], config, ctx)
        assert len(ctx.reporter.findings) == 1
        assert all(call.kwargs['allow_redirects'] is False for calls in mocked.requests.values() for call in calls)
    assert config.follow_redirects is True

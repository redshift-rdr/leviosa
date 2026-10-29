import html
from dataclasses import replace

import pytest

from core.config import Config
from core.loader import load_modules
from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse, Param, RequestBody
from core.options import ValidationParser, setup_modules
from core.scans import prepare_scan, read_scan
from core.tooltags import BurpTool, resolve_module_tool
from leviosa import build_parser
from modules.xss import ReflectedXss
from modules.xsspayloads import XssPayloads


class Reporter:
    def __init__(self):
        self.findings = []

    def report(self, finding):
        self.findings.append(finding)

    def write(self, message):
        pass


def request(**kwargs):
    return LeviosaRequest(**({'method': 'GET', 'url': 'https://app.test/', 'headers': [],
                             'params': [Param('query', 'q', 'old')]} | kwargs))


def response(req, body='', media='text/html', status=200):
    return LeviosaResponse(status, {'Content-Type': media}, body.encode(), req)


def configured(tmp_path, payload):
    path = tmp_path / 'payloads.txt'
    path.write_text(payload + '\n')
    module = XssPayloads()
    module.setup(['--xss-payloads', str(path)])
    return module


async def run_probe(module, template, *, baseline='', media='text/html', baseline_status=200, reverse=False):
    ctx = LeviosaContext(reporter=Reporter())
    variants = list(await module.mutate([request()], ctx))
    responses = []
    for variant in variants:
        payload = variant.metadata['xsspayloads'][3]
        body = baseline if payload is None else template(payload)
        responses.append(response(variant, body, media, baseline_status if payload is None else 200))
    for reply in reversed(responses) if reverse else responses:
        await module.analyze_one(reply, ctx)
    assert ctx.state['xsspayloads.results'] == {}
    return ctx.reporter.findings


@pytest.mark.parametrize('payload,template,expected', [
    ('<script>alert(987)</script>', lambda p: '<html>' + p + '</html>', 'script text'),
    ('<img src=x onerror=alert(987)>', lambda p: '<html>' + p + '</html>', 'event handler'),
    ('<svg onload=alert(987)>', lambda p: p, 'event handler'),
    ('javascript:alert(987)', lambda p: '<a href="' + p + '">click</a>', 'JavaScript URL'),
    ("';alert(987);//", lambda p: '<script>const value=\'' + p + '\';</script>', 'script text'),
    ('<script src=//probe.invalid/x.js></script>', lambda p: p, 'script source'),
])
@pytest.mark.parametrize('reverse', [False, True])
async def test_payload_contexts_and_late_baseline(tmp_path, payload, template, expected, reverse):
    module = configured(tmp_path, payload)
    findings = await run_probe(module, template, reverse=reverse)
    finding, = findings
    assert expected in finding.evidence['contexts']
    assert finding.evidence['payload'] == payload
    assert finding.confidence == 'indicator'
    assert finding.evidence['execution_confirmed'] is False


@pytest.mark.parametrize('template,media', [
    (lambda p: html.escape(p), 'text/html'),
    (lambda p: '<div title="' + html.escape(p, quote=True) + '">ok</div>', 'text/html'),
    (lambda p: p, 'text/plain'),
    (lambda p: p, 'application/json'),
    (lambda p: '<textarea>' + p + '</textarea>', 'text/html'),
    (lambda p: '<title>' + p + '</title>', 'text/html'),
    (lambda p: '<template>' + p + '</template>', 'text/html'),
    (lambda p: '<noscript>' + p + '</noscript>', 'text/html'),
    (lambda p: 'nothing reflected', 'text/html'),
])
async def test_safe_and_inert_reflection_does_not_flag(tmp_path, template, media):
    module = configured(tmp_path, '<script>alert(987)</script>')
    assert not await run_probe(module, template, media=media)


async def test_non_javascript_script_types_are_inert(tmp_path):
    module = configured(tmp_path, 'alert(987)')
    assert not await run_probe(module, lambda p: '<script type="application/json">' + p + '</script>')


@pytest.mark.parametrize('reverse', [False, True])
async def test_existing_baseline_code_is_suppressed(tmp_path, reverse):
    payload = '<script>alert(987)</script>'
    module = configured(tmp_path, payload)
    assert not await run_probe(module, lambda p: p, baseline=payload, reverse=reverse)


async def test_failed_baseline_does_not_support_candidate(tmp_path):
    module = configured(tmp_path, '<script>alert(987)</script>')
    assert not await run_probe(module, lambda p: p, baseline_status=0, reverse=True)


async def test_default_scan_covers_each_input_without_mutating_seed():
    module, ctx = XssPayloads(), LeviosaContext()
    seed = request(url='https://app.test/?a=1&a=2', params=[],
                   body=RequestBody('json', {'items': [{'q': 'old'}]}))
    variants = list(await module.mutate([seed], ctx))
    assert len(variants) == 1 + 3 * len(module._payloads)
    assert variants[0].metadata['xsspayloads'][3] is None
    assert all(variant.metadata['xsspayloads'][4] == len(variants) for variant in variants)
    assert seed.metadata == {}
    assert seed.body.value == {'items': [{'q': 'old'}]}
    assert seed.url.endswith('a=1&a=2')
    assert all('{marker}' not in variant.metadata['xsspayloads'][3] for variant in variants[1:])
    other = list(await module.mutate([seed], ctx))
    assert variants[1].metadata['xsspayloads'][3] != other[1].metadata['xsspayloads'][3]


async def test_no_inputs_sends_nothing():
    assert list(await XssPayloads().mutate([request(params=[])], LeviosaContext())) == []


async def test_wordlist_preserves_percent_encoding_whitespace_and_js_braces(tmp_path):
    payload = '  <script>if(true){alert(987)}</script>%3C  '
    module = configured(tmp_path, payload)
    variants = list(await module.mutate([request()], LeviosaContext()))
    assert len(variants) == 2
    assert variants[1].params[0].value == payload


@pytest.mark.parametrize('contents', ['', '\n  \n\t\n'])
def test_empty_wordlists_rejected(tmp_path, contents):
    path = tmp_path / 'empty.txt'
    path.write_text(contents)
    with pytest.raises(ValueError, match='empty'):
        XssPayloads().setup(['--xss-payloads', str(path)])


def test_missing_wordlist_rejected(tmp_path):
    with pytest.raises(FileNotFoundError):
        XssPayloads().setup(['--xss-payloads', str(tmp_path / 'missing')])


def test_both_modules_can_be_selected_without_option_collisions(tmp_path):
    module = configured(tmp_path, '<script>alert(987)</script>')
    modules = [ReflectedXss(), module]
    setup_modules(modules, [], [], ValidationParser(add_help=False))
    assert [resolve_module_tool(m, Config()) for m in modules] == [BurpTool.REPEATER, BurpTool.INTRUDER]
    assert resolve_module_tool(modules[0], Config(module_tools={'xss': BurpTool.INTRUDER})) == BurpTool.INTRUDER
    assert resolve_module_tool(modules[1], Config(tool=BurpTool.REPEATER)) == BurpTool.REPEATER
    assert type(load_modules(['xsspayloads'])[0]) is XssPayloads


def test_payload_wordlist_resolves_relative_to_scan_file(tmp_path, monkeypatch):
    (tmp_path / 'payloads.txt').write_text('<script>alert(987)</script>\n')
    path = tmp_path / 'scan.toml'
    path.write_text('target="https://app.test/?q=old"\n[[steps]]\nmodule="xsspayloads"\nargs=["--xss-payloads", "payloads.txt"]\n')
    monkeypatch.chdir(tmp_path.parent)
    plan = prepare_scan(read_scan(str(path)), Config(no_proxy=True),
                        ValidationParser(add_help=False, parents=[build_parser()], allow_abbrev=False))
    assert plan.steps[0].module._payloads == ['<script>alert(987)</script>']

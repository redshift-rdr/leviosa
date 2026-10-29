"""Keep the all-module example complete, offline-valid and conservatively scoped."""
import shutil
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from core.config import Config
from core.loader import discover_modules
from core.models import LeviosaRequest, LeviosaResponse
from core.options import ValidationParser
from core.scanoutput import ScanReporter
from core.scans import prepare_scan, read_scan, run_scan, scan_config
from core.tooltags import BurpTool
from leviosa import build_parser

PROFILE = Path(__file__).resolve().parent.parent / 'examples' / 'hands-off'


@pytest.fixture
def prepared(tmp_path):
    directory = tmp_path / 'profile'
    shutil.copytree(PROFILE, directory, ignore=shutil.ignore_patterns('inputs', 'traffic.sqlite', 'traffic.sqlite-*', 'results.jsonl'))
    inputs = directory / 'inputs'
    inputs.mkdir(exist_ok=True)
    for template in (directory / 'templates').glob('*.example.json'):
        shutil.copyfile(template, inputs / template.name.replace('.example', ''))
    definition = read_scan(str(directory / 'scan.toml'))
    parser = ValidationParser(add_help=False, parents=[build_parser()], allow_abbrev=False)
    plan = prepare_scan(definition, scan_config(definition, Config()), parser)
    return directory, plan


def test_all_current_modules_included_exactly_once_and_human_paced(prepared):
    directory, plan = prepared
    names = [step.module.module_name for step in plan.steps]
    assert Counter(names) == Counter(discover_modules())
    assert plan.config.human_mode and not plan.config.random_timing
    assert plan.config.concurrency == 1
    assert plan.config.human_timing_min == 2 and plan.config.human_timing_max == 4
    assert all(step.config.tool == BurpTool.REPEATER and step.repeater_preview == 0 for step in plan.steps)
    assert plan.config.burp is False and plan.config.no_proxy is False
    assert plan.config.auth_check is False
    assert plan.config.timeout == 15 and plan.config.max_body_bytes == 262144
    assert not (directory / 'traffic.sqlite').exists()
    assert not (directory / 'results.jsonl').exists()


@pytest.mark.parametrize('path', ['/api/login', '/rest/user/login', '/auth/token', '/oauth/token',
                                  '/logout', '/account/reset-password', '/user/change_password',
                                  '/register', '/api/checkout', '/api/payment', '/api/transfer', '/api/delete'])
def test_non_authentication_steps_exclude_captured_auth_and_obvious_destructive_paths(prepared, path):
    _, plan = prepared
    for step in plan.steps:
        if step.module.module_name == 'authentication':
            continue
        for method in ('GET', 'POST'):
            req = LeviosaRequest(method, 'https://app.example' + path, [], [])
            selected = [req]
            for request_filter in step.module.cli_filters:
                selected = list(request_filter.apply(selected))
            assert not selected, (step.module.module_name, method, path)


def test_sensitive_steps_keep_complete_applicable_seed_streams(prepared):
    _, plan = prepared
    specs = {step['module']: step for step in read_scan(str(PROFILE / 'scan.toml')).data['steps']}
    for name in ('authentication', 'idor', 'jwt', 'fileupload'):
        assert 'sample' not in specs[name].get('filters', {})
    modules = {step.module.module_name: step.module for step in plan.steps}
    assert modules['authentication'].risky is False
    assert modules['methodtamper']._methods == ['OPTIONS', 'TRACE', 'FOOBAR']
    assert modules['methodtamper']._use_override is False
    assert modules['businesslogic'].max_probes == 12
    assert modules['fileupload'].skip_eicar is False
    for name in ('authz', 'idor'):
        assert {label for label, _ in modules[name]._sessions} == {'user-a', 'user-b'}
        assert modules[name]._rules and all('contains' in rule for rule in modules[name]._rules)


def test_profile_requires_real_application_input_files(tmp_path):
    directory = tmp_path / 'profile'
    shutil.copytree(PROFILE, directory, ignore=shutil.ignore_patterns('inputs', 'traffic.sqlite', 'traffic.sqlite-*', 'results.jsonl'))
    # Ignore any developer-local inputs when checking the distributed contract.
    shutil.rmtree(directory / 'inputs', ignore_errors=True)
    definition = read_scan(str(directory / 'scan.toml'))
    with pytest.raises(FileNotFoundError, match='requests.json'):
        prepare_scan(definition, scan_config(definition, Config()), ValidationParser(add_help=False))
    assert not (directory / 'traffic.sqlite').exists()
    assert not (directory / 'results.jsonl').exists()


async def test_all_steps_execute_offline_with_mocked_transport_and_do_not_submit_logins(prepared, monkeypatch):
    directory, plan = prepared
    visited, methods = [], Counter()
    count = 0
    async def fake_send(requests, config, **kwargs):
        nonlocal count
        visited.append(kwargs['module'])
        assert config.human_mode and config.concurrency == 1
        assert kwargs['tool'] == BurpTool.REPEATER
        for req in requests:
            count += 1
            methods[req.method] += 1
            # Discovery may GET login pages, but captured login submissions must
            # not reach any step; authentication only sends its anonymous GET.
            if urlsplit(req.url).path == '/api/login':
                assert req.method == 'GET' and req.body is None and not req.params
            assert req.method not in {'DELETE', 'PUT', 'PATCH', 'CONNECT'}
            yield LeviosaResponse(200, {'Content-Type': 'application/json'}, b'{}', req)
    class Quiet:
        def report(self, finding):
            pass
        def write(self, message):
            pass
    monkeypatch.setattr('core.runner.send', fake_send)
    result = await run_scan(plan, output=ScanReporter(terminal=Quiet()))
    assert result.completed == len(discover_modules()) and result.failed == 0
    assert len(visited) == len(plan.steps)
    assert count > len(plan.steps)
    assert methods['POST'] > 0
    assert not (directory / 'traffic.sqlite').exists()
    assert not (directory / 'results.jsonl').exists()

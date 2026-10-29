"""Classification and overrides must be explicit, validated, and independent of routing."""
from unittest.mock import patch

import pytest

from core.config import Config, load_config
from core.loader import load_modules
from core.models import LeviosaContext, LeviosaRequest
from core.requester import send
from core.runner import run_modules
from core.tooltags import BurpTool, parse_module_tools, resolve_module_tool
from modules.base import BaseModule


@pytest.mark.parametrize('name,tool', [
    ('passthrough', 'Repeater'), ('pathfuzz', 'Intruder'), ('adminfinder', 'Intruder'),
    ('sensitivefiles', 'Intruder'), ('authz', 'Intruder'), ('sqli', 'Scanner'),
    ('cors', 'Scanner'), ('csp', 'Scanner'), ('securityheaders', 'Scanner'),
    ('versiondisclosure', 'Scanner'), ('methodtamper', 'Scanner'), ('errorpages', 'Scanner'),
])
def test_shipped_defaults(name, tool):
    module, = load_modules([name])
    assert module.module_name == name
    assert module.tool == tool


class Probe(BaseModule):
    module_name = 'probe'
    tool = BurpTool.SCANNER

    async def mutate(self, requests, context):
        return requests


@pytest.mark.parametrize('config,expected', [
    (Config(), 'Scanner'),
    (Config(tool=BurpTool.REPEATER), 'Repeater'),
    (Config(module_tools={'probe': BurpTool.INTRUDER}), 'Intruder'),
    (Config(tool=BurpTool.REPEATER, module_tools={'probe': BurpTool.INTRUDER}), 'Intruder'),
    (Config(module_tools={'other': BurpTool.REPEATER}), 'Scanner'),
])
def test_specific_override_precedes_global_and_module_default(config, expected):
    assert resolve_module_tool(Probe(), config) == expected


def test_module_overrides_work_for_direct_builtin_instances():
    from modules.sqli import SqlInjection
    assert resolve_module_tool(SqlInjection(), Config(module_tools={'sqli': BurpTool.REPEATER})) == 'Repeater'


def test_toml_tool_defaults_and_exceptions(tmp_path):
    path = tmp_path / 'leviosa.toml'
    path.write_text('[tools]\ndefault = "Intruder"\n[tools.modules]\nsqli = "Repeater"\n')
    config = load_config(str(path))
    assert config.tool is BurpTool.INTRUDER
    assert config.module_tools == {'sqli': BurpTool.REPEATER}


@pytest.mark.parametrize('text', [
    '[tools]\ndefault = "Requester"',
    '[tools]\nmodules = ["Scanner"]',
    '[tools.modules]\nsqli = "Proxy"',
])
def test_invalid_toml_categories_are_rejected(tmp_path, text):
    path = tmp_path / 'leviosa.toml'
    path.write_text(text)
    with pytest.raises(ValueError):
        load_config(str(path))


@pytest.mark.parametrize('args', [
    ['sqli=Proxy'], ['sqli=Requester'], ['sqli'], ['../sqli=Scanner'],
    ['sqli=Scanner', 'sqli=Repeater'],
])
def test_invalid_and_duplicate_named_overrides_are_rejected(args):
    with pytest.raises(ValueError):
        parse_module_tools(args)


def test_custom_module_uses_file_name_for_override(tmp_path):
    path = tmp_path / 'custom.py'
    path.write_text('''from modules.base import BaseModule
class DifferentClassName(BaseModule):
    tool = "Scanner"
    async def mutate(self, requests, context):
        return requests
''')
    module, = load_modules(['custom'], str(tmp_path))
    assert resolve_module_tool(module, Config(module_tools={'custom': BurpTool.INTRUDER})) is BurpTool.INTRUDER
    path.write_text(path.read_text().replace('"Scanner"', '"Proxy"'))
    with pytest.raises(ValueError, match='invalid tool'):
        load_modules(['custom'], str(tmp_path))


async def test_runner_resolves_each_module_without_consuming_seed_stream():
    events = []
    first, second = Probe(), Probe()
    second.module_name = 'second'
    second.tool = BurpTool.INTRUDER

    def seeds():
        events.append('seed')
        yield LeviosaRequest('GET', 'http://example.test', [], [])

    async def fake_send(requests, config, **kwargs):
        events.append(kwargs['tool'])
        next(iter(requests))
        if False:
            yield

    config = Config(module_tools={'probe': BurpTool.REPEATER})
    with patch('core.runner.send', fake_send):
        await run_modules([first, second], seeds, config, LeviosaContext())
    assert events == ['Repeater', 'seed', 'Intruder', 'seed']


async def test_invalid_later_module_category_is_rejected_before_any_traffic():
    invalid = Probe()
    invalid.tool = 'Proxy'
    touched = []

    def seeds():
        touched.append('source')
        return []

    with pytest.raises(ValueError):
        await run_modules([Probe(), invalid], seeds, Config(), LeviosaContext())
    assert touched == []


async def test_direct_send_rejects_invalid_category_before_consuming_requests():
    touched = []

    def seeds():
        touched.append('source')
        return []
        yield

    with pytest.raises(ValueError):
        async for _ in send(seeds(), Config(), tool='Requester'):
            pass
    assert not touched

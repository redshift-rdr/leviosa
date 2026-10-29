"""Validate TOML scan definitions, then execute independent module steps in order."""
import asyncio
import copy
import inspect
import math
import os
import sqlite3
import tomllib
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from pathlib import Path
from uuid import uuid4

import aiohttp
from yarl import URL

from core.config import Config
from core.auth import AuthGuard, AuthenticationStopped
from core.filters import add_filter_args, filters_from_args
from core.loader import load_modules
from core.logdb import validate_database
from core.models import LeviosaContext, LeviosaRequest
from core.options import ValidationParser, setup_modules
from core.parsers import request_source
from core.requester import _request_options
from core.runner import run_modules
from core.scanoutput import ResultsWriteError, ScanReporter
from core.timing import HumanPacer
from core.tooltags import BurpTool, resolve_module_tool, validate_repeater_preview
from modules.base import BaseModule

_SETTINGS = {
    'concurrency', 'max_body_bytes', 'timeout', 'follow_redirects', 'no_proxy', 'proxy_url',
    'burp', 'proxy_config_path', 'burp_host', 'burp_port', 'human_mode', 'human_timing_min', 'human_timing_max',
    'random_timing', 'random_timing_min', 'random_timing_max', 'tool', 'log_enabled', 'verbose',
    'auth_check', 'auth_check_url', 'auth_success_text', 'auth_mechanism', 'auth_check_interval',
}
_ROOT_KEYS = _SETTINGS | {'name', 'target', 'database', 'results', 'modules_dir', 'steps', 'on_error', 'repeater_preview'}
_STEP_KEYS = {'name', 'module', 'args', 'filters', 'tool', 'modules_dir', 'repeater_preview'}


def _string(value, label):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f'{label} must be a non-empty string')
    return value


def _path(base, value):
    path = Path(value).expanduser()
    return str((base / path).resolve())


def _unknown(data, allowed, label):
    extra = data.keys() - allowed
    if extra:
        raise ValueError(f'{label}: unknown key(s): ' + ', '.join(sorted(extra)))


@dataclass
class ScanDefinition:
    path: Path
    name: str
    data: dict

    @property
    def module_names(self):
        return [step['module'] for step in self.data['steps']]


def read_scan(path: str) -> ScanDefinition:
    file = Path(path).expanduser().resolve()
    with file.open('rb') as stream:
        data = tomllib.load(stream)
    _unknown(data, _ROOT_KEYS, 'scan')
    if data.get('on_error', 'continue') != 'continue':
        raise ValueError('on_error must be "continue"; runtime module failures do not stop later steps')
    name = _string(data.get('name', file.stem), 'scan name')
    validate_repeater_preview(data.get('repeater_preview', 5))
    steps = data.get('steps')
    if not isinstance(steps, list) or not steps:
        raise ValueError('scan must contain at least one [[steps]] table')
    for index, step in enumerate(steps, 1):
        if not isinstance(step, dict):
            raise ValueError(f'step {index} must be a table')
        _unknown(step, _STEP_KEYS, f'step {index}')
        _string(step.get('module'), f'step {index} module')
        validate_repeater_preview(step.get('repeater_preview', data.get('repeater_preview', 5)))
        if 'name' in step:
            _string(step['name'], f'step {index} name')
        args = step.get('args', [])
        if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
            raise ValueError(f'step {index} args must be an array of strings')
        if not isinstance(step.get('filters', {}), dict):
            raise ValueError(f'step {index} filters must be a table')
    for key in ('target', 'database', 'results', 'modules_dir'):
        if key in data:
            _string(data[key], key)
    return ScanDefinition(file, name, data)


def scan_config(definition: ScanDefinition, base: Config) -> Config:
    settings = {key: value for key, value in definition.data.items() if key in _SETTINGS}
    if 'tool' in settings:
        settings['tool'] = BurpTool(settings['tool'])
        settings['module_tools'] = {}
    if 'proxy_config_path' in settings:
        settings['proxy_config_path'] = _path(definition.path.parent, _string(settings['proxy_config_path'], 'proxy_config_path'))
    if 'database' in definition.data:
        settings['log_db_path'] = _path(definition.path.parent, definition.data['database'])
    return replace(base, **settings)


def _validate_config(config):
    config.validate_timing()
    config.validate_auth()
    config.validate_proxies()
    for key in ('follow_redirects', 'no_proxy', 'log_enabled', 'verbose'):
        if type(getattr(config, key)) is not bool:
            raise ValueError(f'{key} must be true or false')
    if type(config.concurrency) is not int or config.concurrency < 1:
        raise ValueError('concurrency must be a positive integer')
    if type(config.max_body_bytes) is not int or config.max_body_bytes < 0:
        raise ValueError('max_body_bytes must be a non-negative integer')
    if type(config.timeout) not in (float, int) or not math.isfinite(config.timeout) or config.timeout <= 0:
        raise ValueError('timeout must be a finite positive number')
    if type(config.burp_port) is not int or not 1 <= config.burp_port <= 65535:
        raise ValueError('burp_port must be between 1 and 65535')
    _string(config.burp_host, 'burp_host')
    if config.proxy_url is not None:
        proxy = URL(_string(config.proxy_url, 'proxy_url'))
        if proxy.scheme not in ('http', 'https') or not proxy.host:
            raise ValueError('proxy_url must be an HTTP(S) URL with a host')
        proxy.port


def _filters(args, table):
    parser = ValidationParser(add_help=False, allow_abbrev=False)
    add_filter_args(parser)
    parsed, remaining = parser.parse_known_args(args)
    if table:
        _unknown(table, {'methods', 'path', 'sample', 'sample_seed'}, 'filters')
        if parsed.method or parsed.path is not None or parsed.sample is not None or parsed.sample_seed is not None:
            raise ValueError('use filter flags in args OR a filters table, not both')
        if 'methods' in table:
            methods = table['methods']
            if not isinstance(methods, list) or not all(isinstance(value, str) and value for value in methods):
                raise ValueError('filters.methods must be an array of method names')
            parsed.method = methods
        if 'path' in table:
            parsed.path = _string(table['path'], 'filters.path')
        for key in ('sample', 'sample_seed'):
            if key in table:
                if type(table[key]) is not int:
                    raise ValueError(f'filters.{key} must be an integer')
                setattr(parsed, key, table[key])
    if parsed.sample is not None and parsed.sample < 0:
        raise ValueError('sample must be non-negative')
    return filters_from_args(parsed), remaining


def _resolve_args(module, args, base):
    parser = module.option_parser()
    parents = [parser] if parser is not None else []
    ValidationParser(add_help=False, allow_abbrev=False, parents=parents).parse_args(args)
    paths = []
    resolved = list(args)
    for index, arg in enumerate(args):
        flag, sep, value = arg.partition('=')
        kind = module.path_options.get(flag)
        if kind is None:
            continue
        if kind not in ('file', 'session'):
            raise ValueError(f'unsupported path kind for {flag}: {kind}')
        if not sep:
            value = args[index + 1]
        label = ''
        if kind == 'session' and '=' in value:
            name, value = value.split('=', 1)
            label = name + '='
        value = _path(base, value)
        paths.append(Path(value))
        if sep:
            resolved[index] = flag + '=' + label + value
        else:
            resolved[index + 1] = label + value
    return resolved, paths


def _validate_source(source):
    loop = asyncio.new_event_loop()
    try:
        for index, req in enumerate(source(), 1):
            try:
                url = URL(req.url)
                if url.scheme not in ('http', 'https') or not url.host:
                    raise ValueError('target must be an HTTP(S) URL with a host')
                url.port
                if not isinstance(req.headers, list) or not all(isinstance(value, str) for value in req.headers):
                    raise ValueError('headers must be an array of strings')
                headers, kwargs = _request_options(req)
                for name, value in headers.items():
                    if not isinstance(value, str) or any(char in name + value for char in '\r\n'):
                        raise ValueError('HTTP header names/values must be text without CR or LF')
                if 'json' in kwargs:
                    kwargs['data'] = aiohttp.payload.JsonPayload(kwargs.pop('json'))
                # Construction validates the transport's own input contract.
                # It does not connect, resolve DNS, or send any bytes.
                aiohttp.ClientRequest(req.method, url, headers=headers, loop=loop, **kwargs)
            except Exception as exc:
                raise ValueError(f'input request {index}: {exc}') from exc
    finally:
        loop.close()


def _same_path(left, right):
    return left.resolve() == right.resolve() or (left.exists() and right.exists() and left.samefile(right))


@dataclass
class PreparedStep:
    index: int
    name: str
    module: BaseModule
    config: Config
    repeater_preview: int = 5


@dataclass
class PreparedScan:
    name: str
    target: str
    source: Callable[[], Iterable[LeviosaRequest]]
    config: Config
    steps: list[PreparedStep]
    results: str | None


def prepare_scan(definition, config, shared_parser, *, target=None, modules_dir=None,
                 results=None, filters=(), cli_tool=None, cli_module_tools=None,
                 source_transform=None, protected_paths=()):
    _validate_config(config)
    base = definition.path.parent
    target = target if target is not None else definition.data.get('target')
    target = _string(target, 'target (in the scan file or on the CLI)')
    if not target.startswith(('http://', 'https://')):
        # A target supplied on the CLI is resolved by the caller first.
        target = _path(base, target)
    source = request_source(target)
    if source_transform is not None:
        source = source_transform(source)
    _validate_source(source)  # stream validation: do not materialise an expanded scan
    if config.auth_check:
        guard = AuthGuard(config)
        for seed in source():
            guard.bind(seed)
            if guard.bound:
                break
        if not guard.bound:
            raise ValueError('No captured credentials on the authentication-check URL origin')
    inputs = [definition.path, *map(Path, protected_paths)]
    if config.proxy_config_path:
        inputs.append(Path(config.proxy_config_path))
    if not target.startswith(('http://', 'https://')):
        inputs.append(Path(target))
    steps = []
    for index, spec in enumerate(definition.data['steps'], 1):
        name = spec.get('name', spec['module'])
        try:
            directory = modules_dir
            if directory is None:
                value = spec.get('modules_dir', definition.data.get('modules_dir'))
                directory = _path(base, value) if value is not None else None
            module, = load_modules([spec['module']], directory)
            inputs.append(Path(inspect.getfile(type(module))))
            own_filters, module_args = _filters(spec.get('args', []), spec.get('filters', {}))
            module_args, paths = _resolve_args(module, module_args, base)
            for path in paths:
                if not path.is_file():
                    raise ValueError(f'input file does not exist: {path}')
            inputs.extend(paths)
            setup_modules([module], module_args, [*filters, *own_filters], shared_parser)
            if spec['module'] in (cli_module_tools or {}):
                tool = cli_module_tools[spec['module']]
            elif cli_tool is not None:
                tool = cli_tool
            elif 'tool' in spec:
                tool = BurpTool(spec['tool'])
            else:
                tool = resolve_module_tool(module, config)
            step_config = replace(config, tool=BurpTool(tool), module_tools={})
            steps.append(PreparedStep(index, name, module, step_config,
                                      spec.get('repeater_preview', definition.data.get('repeater_preview', 5))))
        except (Exception, SystemExit) as exc:
            raise ValueError(f'step {index} ({name}): {exc}') from exc
    if results is None and 'results' in definition.data:
        results = _path(base, definition.data['results'])
    outputs = [Path(config.log_db_path)] if config.log_enabled else []
    if results is not None:
        outputs.append(Path(results))
        # Never append JSONL to an existing SQLite file, even with --no-log.
        if Path(results).is_file():
            with open(results, 'rb') as stream:
                if stream.read(16) == b'SQLite format 3\x00':
                    raise ValueError('results file must be separate from SQLite databases')
    for output in outputs:
        if not output.parent.is_dir() or (output.exists() and not output.is_file()):
            raise ValueError(f'output must be a file in an existing directory: {output}')
        if not os.access(output if output.exists() else output.parent, os.W_OK):
            raise ValueError(f'output is not writable: {output}')
        if any(_same_path(output, item) for item in inputs):
            raise ValueError(f'output would overwrite or modify a scan input: {output}')
    if len(outputs) == 2 and _same_path(*outputs):
        raise ValueError('results and traffic database must be different files')
    if config.log_enabled:
        validate_database(config.log_db_path)

    def replay():
        for req in source():
            yield replace(copy.deepcopy(req))

    return PreparedScan(definition.name, target, replay, config, steps, results)


@dataclass
class ScanOutcome:
    completed: int = 0
    failed: int = 0

    @property
    def status(self):
        return 'completed_with_failures' if self.failed else 'completed'


async def run_scan(plan, *, output=None, logger=None, context=None):
    output = (output or ScanReporter()).scope(run_id=uuid4().hex, scan=plan.name)
    context = context or LeviosaContext()
    outcome = ScanOutcome()
    pacer = HumanPacer()
    auth_guard = AuthGuard(plan.config, write=output.write) if plan.config.auth_check else None
    output.progress('scan_started', f'[SCAN] {plan.name}: starting {len(plan.steps)} steps',
                    target=plan.target, total=len(plan.steps))
    try:
        for step in plan.steps:
            scoped = output.scope(step=step.index, step_name=step.name,
                                  module=step.module.module_name, tool=str(step.config.tool))
            preview = f'; first {step.repeater_preview} requests as Repeater' if step.repeater_preview and step.config.tool != BurpTool.REPEATER else ''
            scoped.progress('step_started', f'[SCAN] {step.index}/{len(plan.steps)} {step.name}: starting ({step.config.tool}{preview})',
                            repeater_preview=step.repeater_preview)
            try:
                await run_modules([step.module], plan.source, step.config,
                                  LeviosaContext(data=context.data, reporter=scoped), logger, pacer=pacer,
                                  repeater_preview=step.repeater_preview,
                                  **({"auth_guard": auth_guard} if auth_guard is not None else {}))
            except (KeyboardInterrupt, asyncio.CancelledError):
                scoped.progress('step_finished', f'[SCAN] {step.name}: interrupted', status='interrupted')
                raise
            except (sqlite3.Error, ResultsWriteError, AuthenticationStopped) as exc:
                if not isinstance(exc, ResultsWriteError):
                    scoped.emit('step_finished', status='failed',
                                error={'type': type(exc).__name__, 'message': str(exc)})
                raise
            except (Exception, SystemExit) as exc:
                outcome.failed += 1
                scoped.progress('step_finished', f'[SCAN] {step.name}: failed ({type(exc).__name__}: {exc}); continuing',
                                status='failed', error={'type': type(exc).__name__, 'message': str(exc)})
            else:
                outcome.completed += 1
                scoped.progress('step_finished', f'[SCAN] {step.name}: completed', status='completed')
    except (KeyboardInterrupt, asyncio.CancelledError):
        output.progress('scan_finished', f'[SCAN] {plan.name}: interrupted', status='interrupted',
                        completed=outcome.completed, failed=outcome.failed)
        raise
    except Exception as exc:
        output.terminal.write(f'[SCAN] {plan.name}: stopped ({exc})')
        if not isinstance(exc, ResultsWriteError):
            output.emit('scan_finished', status='failed', completed=outcome.completed, failed=outcome.failed,
                        error={'type': type(exc).__name__, 'message': str(exc)})
        raise
    output.progress('scan_finished', f'[SCAN] {plan.name}: {outcome.status} '
                    f'({outcome.completed} completed, {outcome.failed} failed)', status=outcome.status,
                    completed=outcome.completed, failed=outcome.failed)
    return outcome

import pytest

from core.loader import discover_modules, load_modules
from modules.base import BaseModule


class TestDiscoverModules:
    def test_finds_shipped_modules(self):
        names = discover_modules()
        for expected in (
            "passthrough", "pathfuzz", "adminfinder",
            "sensitivefiles", "versiondisclosure", "errorpages",
        ):
            assert expected in names

    def test_excludes_base_and_init(self):
        names = discover_modules()
        assert "base" not in names
        assert "__init__" not in names

    def test_sorted(self):
        names = discover_modules()
        assert names == sorted(names)

    def test_all_discovered_modules_load(self):
        # Every discovered name must load into exactly one BaseModule instance.
        for name in discover_modules():
            instances = load_modules([name])
            assert len(instances) == 1
            assert isinstance(instances[0], BaseModule)

VALID_MODULE_SRC = """\
from modules.base import BaseModule

class MyModule(BaseModule):
    async def mutate(self, requests, context):
        return requests
"""

NO_SUBCLASS_SRC = """\
class NotAModule:
    pass
"""

MULTIPLE_SUBCLASSES_SRC = """\
from modules.base import BaseModule

class ModuleA(BaseModule):
    async def mutate(self, requests, context):
        return requests

class ModuleB(BaseModule):
    async def mutate(self, requests, context):
        return requests
"""


@pytest.fixture
def modules_dir(tmp_path):
    d = tmp_path / "modules"
    d.mkdir()
    return d


class TestLoadModules:
    def test_loads_valid_module(self, modules_dir):
        (modules_dir / "mymodule.py").write_text(VALID_MODULE_SRC)
        result = load_modules(["mymodule"], modules_dir=str(modules_dir))
        assert len(result) == 1
        assert isinstance(result[0], BaseModule)

    def test_loads_multiple_modules(self, modules_dir):
        (modules_dir / "a.py").write_text(VALID_MODULE_SRC)
        (modules_dir / "b.py").write_text(VALID_MODULE_SRC)
        result = load_modules(["a", "b"], modules_dir=str(modules_dir))
        assert len(result) == 2

    def test_returns_instances_not_classes(self, modules_dir):
        (modules_dir / "mymodule.py").write_text(VALID_MODULE_SRC)
        result = load_modules(["mymodule"], modules_dir=str(modules_dir))
        assert isinstance(result[0], BaseModule)
        assert not isinstance(result[0], type)

    def test_missing_module_raises_file_not_found(self, modules_dir):
        with pytest.raises(FileNotFoundError) as exc:
            load_modules(["nonexistent"], modules_dir=str(modules_dir))
        assert "nonexistent" in str(exc.value)

    def test_missing_module_error_names_path(self, modules_dir):
        with pytest.raises(FileNotFoundError) as exc:
            load_modules(["missing"], modules_dir=str(modules_dir))
        assert "missing.py" in str(exc.value)

    def test_no_subclass_raises_value_error(self, modules_dir):
        (modules_dir / "bad.py").write_text(NO_SUBCLASS_SRC)
        with pytest.raises(ValueError) as exc:
            load_modules(["bad"], modules_dir=str(modules_dir))
        assert "bad" in str(exc.value).lower()

    def test_multiple_subclasses_raises_value_error(self, modules_dir):
        (modules_dir / "multi.py").write_text(MULTIPLE_SUBCLASSES_SRC)
        with pytest.raises(ValueError) as exc:
            load_modules(["multi"], modules_dir=str(modules_dir))
        assert "multiple" in str(exc.value).lower()

    def test_empty_names_returns_empty_list(self, modules_dir):
        assert load_modules([], modules_dir=str(modules_dir)) == []

    def test_passthrough_loadable_from_project_modules(self):
        result = load_modules(["passthrough"])
        assert len(result) == 1
        assert isinstance(result[0], BaseModule)

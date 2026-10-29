import importlib.util
import importlib
import inspect
import sys
from hashlib import sha256
from pathlib import Path

from modules.base import BaseModule
from core.tooltags import BurpTool


def discover_modules(modules_dir: str | None = None) -> list[str]:
    """Return the sorted names of all loadable modules in modules_dir."""
    directory = Path(modules_dir) if modules_dir else Path(__file__).resolve().parent.parent / "modules"
    return sorted(
        p.stem for p in directory.glob("*.py")
        if p.stem != "base" and p.stem.isidentifier() and not p.stem.startswith("_")
    )


def load_modules(names: list[str], modules_dir: str | None = None) -> list[BaseModule]:
    instances = []
    for name in names:
        if not name.isidentifier() or name.startswith("_") or name == "base":
            raise ValueError(f"Invalid module name: {name!r}")
        directory = Path(modules_dir) if modules_dir else Path(__file__).resolve().parent.parent / "modules"
        path = directory / f"{name}.py"
        if not path.exists():
            raise FileNotFoundError(f"Module not found: {path}")

        if modules_dir is None:
            mod = importlib.import_module(f"modules.{name}")
        else:
            suffix = sha256(str(path.resolve()).encode()).hexdigest()[:16]
            module_name = f"_leviosa_custom_{suffix}_{name}"
            spec = importlib.util.spec_from_file_location(module_name, path)
            mod = importlib.util.module_from_spec(spec)
            previous = sys.modules.get(module_name)
            sys.modules[module_name] = mod
            try:
                spec.loader.exec_module(mod)
            except BaseException:
                if previous is None:
                    sys.modules.pop(module_name, None)
                else:
                    sys.modules[module_name] = previous
                raise

        subclasses = [
            cls for _, cls in inspect.getmembers(mod, inspect.isclass)
            if issubclass(cls, BaseModule) and cls is not BaseModule
            and cls.__module__ == mod.__name__ and not inspect.isabstract(cls)
        ]

        if not subclasses:
            raise ValueError(f"No BaseModule subclass found in {path}")
        if len(subclasses) > 1:
            names_found = [c.__name__ for c in subclasses]
            raise ValueError(
                f"Multiple BaseModule subclasses found in {path}: {names_found}. Define exactly one."
            )

        instance = subclasses[0]()
        instance.module_name = name
        try:
            instance.tool = BurpTool(instance.tool)
        except (ValueError, TypeError):
            raise ValueError(f"Module {name!r} declares an invalid tool; use Repeater, Intruder or Scanner") from None
        instances.append(instance)
    return instances

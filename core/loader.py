import importlib.util
import inspect
from pathlib import Path

from modules.base import BaseModule


def discover_modules(modules_dir: str = "modules") -> list[str]:
    """Return the sorted names of all loadable modules in modules_dir."""
    directory = Path(modules_dir)
    return sorted(
        p.stem for p in directory.glob("*.py")
        if p.stem not in ("__init__", "base")
    )


def load_modules(names: list[str], modules_dir: str = "modules") -> list[BaseModule]:
    instances = []
    for name in names:
        path = Path(modules_dir) / f"{name}.py"
        if not path.exists():
            raise FileNotFoundError(f"Module not found: {path}")

        spec = importlib.util.spec_from_file_location(f"leviosa.module.{name}", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        subclasses = [
            cls for _, cls in inspect.getmembers(mod, inspect.isclass)
            if issubclass(cls, BaseModule) and cls is not BaseModule
        ]

        if not subclasses:
            raise ValueError(f"No BaseModule subclass found in {path}")
        if len(subclasses) > 1:
            names_found = [c.__name__ for c in subclasses]
            raise ValueError(
                f"Multiple BaseModule subclasses found in {path}: {names_found}. Define exactly one."
            )

        instances.append(subclasses[0]())
    return instances

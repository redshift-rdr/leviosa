"""Validate selected modules' option ownership before invoking their setup hooks."""
import argparse


class ValidationParser(argparse.ArgumentParser):
    """Argument validation for scan preparation without exiting the process."""

    def error(self, message):
        raise ValueError(message)


def setup_modules(modules, remaining, filters, parser):
    parents = []
    owners = {}
    for module in modules:
        options = module.option_parser()
        if options is None:
            continue
        options.allow_abbrev = False
        for action in options._actions:
            for flag in action.option_strings:
                if flag in parser._option_string_actions:
                    parser.error(f"module option {flag} conflicts with a shared option")
                if flag in owners:
                    parser.error(f"option {flag} is declared by both {owners[flag]} and "
                                 f"{type(module).__name__}; run these modules separately")
                owners[flag] = type(module).__name__
        parents.append(options)
    combined = ValidationParser(add_help=False, allow_abbrev=False, parents=parents)
    try:
        combined.parse_args(remaining)
    except ValueError as exc:
        parser.error(str(exc))
    for module in modules:
        try:
            module.setup(remaining)
        except (OSError, ValueError, RuntimeError) as exc:
            parser.error(f"{type(module).__name__}: {exc}")
        module.cli_filters = tuple(filters)

import argparse
from abc import ABC, abstractmethod
from collections.abc import Iterable

from core.filters import RequestFilter, add_filter_args, filters_from_args
from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse
from core.reporting import Finding
from core.tooltags import BurpTool


class BaseModule(ABC):
    # The loader supplies the file's public module name for named overrides.
    module_name: str | None = None
    tool: BurpTool = BurpTool.REPEATER
    # File-valued options resolved relative to a scan file. "session" accepts LABEL=FILE.
    path_options: dict[str, str] = {}

    # Populated by the CLI, independently of a module's custom filters.
    cli_filters: tuple[RequestFilter, ...] = ()

    def report(self, response, context, observation, *, evidence=None, confidence="observation"):
        """Emit a structured observation through the configured reporter."""
        context.reporter.report(Finding(
            module=type(self).__name__, request=response.request,
            observation=observation,
            evidence={"status": response.status, **(evidence or {})},
            confidence=confidence,
        ))

    # Whether analyze_one needs the response body. False passes b"" to the
    # module. The transport still reads capped bodies if traffic logging is on;
    # with logging off it skips reads entirely.
    # None inherits the global setting; probes can inspect the initial response.
    follow_redirects: bool | None = None
    store_response_cookies: bool = True
    # Optional per-module upper bound; never increases global concurrency.
    max_concurrency: int | None = None

    needs_body: bool = True

    # Legacy compatibility hint, ignored by routing. --burp is explicit and global.
    # Upstream rules and --no-proxy apply independently of module attributes.
    use_burp: bool = False

    def setup(self, args: list[str]) -> None:
        """Called once with remaining CLI args after main parsing. Override to handle module-specific flags."""

    def option_parser(self) -> "argparse.ArgumentParser | None":
        """
        Return an argparse parser (built with add_help=False, allow_abbrev=False) describing this
        module's own CLI options, or None if it has none. setup() parses flags
        with it and --list-modules introspects it to show the options.

        Do NOT register the standard request-filter flags here — the CLI owns
        them and applies them centrally after setup(). Use allow_abbrev=False.
        """
        return None

    def parse_request_filters(self, args: list[str]) -> None:
        """
        Parse the standard request-filter flags (--method / --path / --sample /
        --sample-seed) from the CLI args and store them for request_filters().

        Compatibility helper for callers using setup() outside the CLI. The CLI
        applies these centrally, so new modules need not call this helper.
        """
        parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
        add_filter_args(parser)
        parsed, _ = parser.parse_known_args(args)
        self._filters = filters_from_args(parsed)

    def request_filters(self) -> list[RequestFilter]:
        """
        Filters applied, in order, to the input requests before mutate() sees
        them — for sampling or restricting a module's inputs (e.g. only POSTs,
        or a random sample of 5). Default: none.

        Populated by parse_request_filters() (typically called in setup()).
        Filters are plain Iterable->Iterable objects, so they can also be applied
        by hand to a module's own output inside mutate().
        """
        return getattr(self, "_filters", [])

    @abstractmethod
    async def mutate(
        self,
        requests: Iterable[LeviosaRequest],
        context: LeviosaContext,
    ) -> Iterable[LeviosaRequest]:
        """
        Return the requests to send as a sync iterable (a list, or a generator
        for laziness so variants are produced on demand rather than all at once).
        May be the same requests, modified, or expanded.
        """
        ...

    async def analyze_one(
        self,
        response: LeviosaResponse,
        context: LeviosaContext,
    ) -> None:
        """
        Called once per response, as each one completes (completion order, not
        input order). Emit findings with self.report(response, context, message).
        Aggregate privately on context.state; context.data is explicitly shared
        between modules. Default no-op.
        """

    async def finalize(self, context: LeviosaContext) -> None:
        """Called once after all responses have been analysed. Default no-op."""

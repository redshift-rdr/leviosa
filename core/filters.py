import argparse
import random
import re
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from itertools import islice
from urllib.parse import urlparse

from core.models import LeviosaRequest


class RequestFilter(ABC):
    """
    A pluggable request filter: a lazy transformer over a stream of requests,
    Iterable[LeviosaRequest] -> Iterable[LeviosaRequest].

    Filters compose — the output of one feeds the next — so a module can stack
    several (e.g. keep only POSTs, then take a random sample of them). The
    runner applies a module's request_filters() to the input requests before
    mutate() sees them; the same objects can also be applied by hand to a
    module's own output inside mutate().

    New filters subclass this (or PredicateFilter for per-request keep/drop).
    """

    @abstractmethod
    def apply(self, requests: Iterable[LeviosaRequest]) -> Iterable[LeviosaRequest]:
        ...


class PredicateFilter(RequestFilter):
    """
    Base for per-request keep/drop filters. Subclasses implement keep(); apply()
    is a lazy generator that yields only the requests that pass.
    """

    @abstractmethod
    def keep(self, request: LeviosaRequest) -> bool:
        ...

    def apply(self, requests: Iterable[LeviosaRequest]) -> Iterator[LeviosaRequest]:
        return (r for r in requests if self.keep(r))


class MethodFilter(PredicateFilter):
    """Keep only requests whose HTTP method is in the given set (case-insensitive)."""

    def __init__(self, methods: Iterable[str]):
        self._methods = {m.upper() for m in methods}

    def keep(self, request: LeviosaRequest) -> bool:
        return request.method.upper() in self._methods


class PathFilter(PredicateFilter):
    """Keep only requests whose URL path matches the given regex (re.search)."""

    def __init__(self, pattern: str, flags: int = 0):
        self._re = re.compile(pattern, flags)

    def keep(self, request: LeviosaRequest) -> bool:
        return self._re.search(urlparse(request.url).path) is not None


class TakeFilter(RequestFilter):
    """Keep only the first n requests. Fully lazy — stops pulling after n."""

    def __init__(self, n: int):
        self._n = n

    def apply(self, requests: Iterable[LeviosaRequest]) -> Iterator[LeviosaRequest]:
        return islice(requests, max(self._n, 0))


class SampleFilter(RequestFilter):
    """
    Keep a uniform random sample of at most n requests via reservoir sampling:
    a single pass in O(n) memory with no need to know the total up front. If the
    input has n or fewer requests they are all kept.

    Reservoir sampling must consume the whole input stream to stay uniform, so
    unlike the predicate/take filters this one is eager. That is fine for its
    intended use — sampling the (small) input seeds — but avoid stacking it on a
    module's large expanded output.

    Pass seed for a reproducible sample across runs.
    """

    def __init__(self, n: int, seed: int | None = None):
        self._n = n
        self._rng = random.Random(seed)

    def apply(self, requests: Iterable[LeviosaRequest]) -> list[LeviosaRequest]:
        if self._n <= 0:
            return []
        reservoir: list[LeviosaRequest] = []
        for i, req in enumerate(requests):
            if i < self._n:
                reservoir.append(req)
            else:
                j = self._rng.randint(0, i)
                if j < self._n:
                    reservoir[j] = req
        return reservoir


def add_filter_args(parser: argparse.ArgumentParser) -> None:
    """
    Register the standard request-filter flags on a module's argparse parser.
    Pair with filters_from_args() in setup(). Modules opt in; those needing
    bespoke behaviour can instantiate filter classes directly instead.
    """
    parser.add_argument(
        "--method", action="append", default=[], metavar="M",
        help="Only process requests with this HTTP method (repeatable)",
    )
    parser.add_argument(
        "--path", default=None, metavar="REGEX",
        help="Only process requests whose URL path matches this regex",
    )
    parser.add_argument(
        "--sample", type=int, default=None, metavar="N",
        help="Randomly sample at most N of the input requests",
    )
    parser.add_argument(
        "--sample-seed", type=int, default=None, metavar="SEED",
        help="Seed for --sample, for a reproducible sample",
    )


def filters_from_args(parsed: argparse.Namespace) -> list[RequestFilter]:
    """
    Build the filter list from parsed standard flags. Selective filters
    (method, path) come before sampling, so --sample draws from the already
    narrowed set (e.g. "5 random of the POSTs").
    """
    filters: list[RequestFilter] = []
    if parsed.method:
        filters.append(MethodFilter(parsed.method))
    if parsed.path:
        filters.append(PathFilter(parsed.path))
    if parsed.sample is not None:
        filters.append(SampleFilter(parsed.sample, parsed.sample_seed))
    return filters

import argparse

import pytest

from core.filters import (
    MethodFilter,
    PathFilter,
    PredicateFilter,
    RequestFilter,
    SampleFilter,
    TakeFilter,
    add_filter_args,
    filters_from_args,
)
from core.models import LeviosaRequest


def make_request(url="http://example.com/", method="GET"):
    return LeviosaRequest(method=method, url=url, headers=[], params=[])


def parse(args):
    parser = argparse.ArgumentParser(add_help=False)
    add_filter_args(parser)
    parsed, _ = parser.parse_known_args(args)
    return parsed


# ---------------------------------------------------------------------------
# MethodFilter
# ---------------------------------------------------------------------------

class TestMethodFilter:
    def test_keeps_only_matching_methods(self):
        reqs = [
            make_request(method="GET"),
            make_request(method="POST"),
            make_request(method="PUT"),
        ]
        out = list(MethodFilter(["POST"]).apply(reqs))
        assert [r.method for r in out] == ["POST"]

    def test_case_insensitive(self):
        reqs = [make_request(method="post"), make_request(method="GET")]
        out = list(MethodFilter(["POST"]).apply(reqs))
        assert [r.method for r in out] == ["post"]

    def test_multiple_methods(self):
        reqs = [make_request(method=m) for m in ("GET", "POST", "DELETE")]
        out = list(MethodFilter(["POST", "DELETE"]).apply(reqs))
        assert [r.method for r in out] == ["POST", "DELETE"]

    def test_is_lazy(self):
        # apply() returns a generator, not a materialised list.
        assert iter(MethodFilter(["GET"]).apply(iter([]))) is not None
        result = MethodFilter(["GET"]).apply(make_request() for _ in range(3))
        assert not isinstance(result, list)


# ---------------------------------------------------------------------------
# PathFilter
# ---------------------------------------------------------------------------

class TestPathFilter:
    def test_matches_path_regex(self):
        reqs = [
            make_request("http://x.com/api/users"),
            make_request("http://x.com/static/app.js"),
            make_request("http://x.com/api/orders"),
        ]
        out = list(PathFilter(r"^/api/").apply(reqs))
        assert [r.url for r in out] == [
            "http://x.com/api/users",
            "http://x.com/api/orders",
        ]

    def test_search_not_anchored(self):
        reqs = [make_request("http://x.com/v1/admin/panel")]
        assert len(list(PathFilter(r"admin").apply(reqs))) == 1

    def test_ignores_query_and_host(self):
        # Only the path participates, not host or query string.
        reqs = [make_request("http://admin.com/public?x=admin")]
        assert list(PathFilter(r"admin").apply(reqs)) == []


# ---------------------------------------------------------------------------
# TakeFilter
# ---------------------------------------------------------------------------

class TestTakeFilter:
    def test_takes_first_n(self):
        reqs = [make_request(f"http://x/{i}") for i in range(10)]
        out = list(TakeFilter(3).apply(reqs))
        assert [r.url for r in out] == ["http://x/0", "http://x/1", "http://x/2"]

    def test_fewer_than_n_returns_all(self):
        reqs = [make_request(), make_request()]
        assert len(list(TakeFilter(5).apply(reqs))) == 2

    def test_zero_or_negative_returns_none(self):
        reqs = [make_request() for _ in range(3)]
        assert list(TakeFilter(0).apply(reqs)) == []
        assert list(TakeFilter(-2).apply(iter(reqs))) == []

    def test_lazy_stops_early(self):
        pulled = {"n": 0}

        def gen():
            for i in range(100):
                pulled["n"] += 1
                yield make_request(f"http://x/{i}")

        list(TakeFilter(2).apply(gen()))
        # islice stops pulling once it has 2 (may read up to 2).
        assert pulled["n"] == 2


# ---------------------------------------------------------------------------
# SampleFilter
# ---------------------------------------------------------------------------

class TestSampleFilter:
    def test_samples_n(self):
        reqs = [make_request(f"http://x/{i}") for i in range(20)]
        out = SampleFilter(5, seed=1).apply(reqs)
        assert len(out) == 5

    def test_fewer_than_n_returns_all(self):
        reqs = [make_request(f"http://x/{i}") for i in range(3)]
        out = SampleFilter(5, seed=1).apply(reqs)
        assert len(out) == 3

    def test_zero_returns_none(self):
        reqs = [make_request() for _ in range(5)]
        assert SampleFilter(0).apply(reqs) == []

    def test_seed_is_reproducible(self):
        reqs = [make_request(f"http://x/{i}") for i in range(50)]
        a = SampleFilter(7, seed=42).apply(list(reqs))
        b = SampleFilter(7, seed=42).apply(list(reqs))
        assert [r.url for r in a] == [r.url for r in b]

    def test_different_seeds_differ(self):
        reqs = [make_request(f"http://x/{i}") for i in range(50)]
        a = SampleFilter(7, seed=1).apply(list(reqs))
        b = SampleFilter(7, seed=2).apply(list(reqs))
        assert [r.url for r in a] != [r.url for r in b]

    def test_sample_drawn_from_input(self):
        reqs = [make_request(f"http://x/{i}") for i in range(20)]
        urls = {r.url for r in reqs}
        out = SampleFilter(5, seed=3).apply(reqs)
        assert all(r.url in urls for r in out)

    def test_consumes_a_generator(self):
        out = SampleFilter(2, seed=1).apply(make_request(f"http://x/{i}") for i in range(6))
        assert len(out) == 2


# ---------------------------------------------------------------------------
# Composition — filters chain in order
# ---------------------------------------------------------------------------

class TestComposition:
    def test_method_then_sample(self):
        reqs = (
            [make_request(f"http://x/{i}", method="POST") for i in range(10)]
            + [make_request(f"http://y/{i}", method="GET") for i in range(10)]
        )
        stream = MethodFilter(["POST"]).apply(reqs)
        out = SampleFilter(3, seed=1).apply(stream)
        assert len(out) == 3
        assert all(r.method == "POST" for r in out)


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

class TestCliHelpers:
    def test_no_flags_yields_no_filters(self):
        assert filters_from_args(parse([])) == []

    def test_method_flag(self):
        filters = filters_from_args(parse(["--method", "POST"]))
        assert len(filters) == 1
        assert isinstance(filters[0], MethodFilter)

    def test_method_repeatable(self):
        parsed = parse(["--method", "POST", "--method", "PUT"])
        f = filters_from_args(parsed)[0]
        assert f.keep(make_request(method="PUT"))
        assert not f.keep(make_request(method="GET"))

    def test_path_flag(self):
        filters = filters_from_args(parse(["--path", r"^/api"]))
        assert isinstance(filters[0], PathFilter)

    def test_sample_flag(self):
        filters = filters_from_args(parse(["--sample", "5"]))
        assert isinstance(filters[0], SampleFilter)
        assert filters[0]._n == 5

    def test_sample_seed_passed_through(self):
        f = filters_from_args(parse(["--sample", "5", "--sample-seed", "99"]))[0]
        reqs = [make_request(f"http://x/{i}") for i in range(20)]
        # Reproducible against a fresh filter built with the same seed.
        assert [r.url for r in f.apply(list(reqs))] == [
            r.url for r in SampleFilter(5, seed=99).apply(list(reqs))
        ]

    def test_selective_filters_ordered_before_sampling(self):
        filters = filters_from_args(parse(["--sample", "5", "--method", "POST", "--path", "/x"]))
        kinds = [type(f) for f in filters]
        assert kinds == [MethodFilter, PathFilter, SampleFilter]


# ---------------------------------------------------------------------------
# Extensibility — a custom filter is just a subclass
# ---------------------------------------------------------------------------

class TestExtensibility:
    def test_custom_predicate_filter(self):
        class HttpsOnly(PredicateFilter):
            def keep(self, request):
                return request.url.startswith("https://")

        reqs = [make_request("http://x/"), make_request("https://y/")]
        out = list(HttpsOnly().apply(reqs))
        assert [r.url for r in out] == ["https://y/"]

    def test_custom_stream_filter(self):
        class EveryOther(RequestFilter):
            def apply(self, requests):
                return (r for i, r in enumerate(requests) if i % 2 == 0)

        reqs = [make_request(f"http://x/{i}") for i in range(4)]
        out = list(EveryOther().apply(reqs))
        assert [r.url for r in out] == ["http://x/0", "http://x/2"]

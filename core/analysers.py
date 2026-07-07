import re as _re
from abc import ABC, abstractmethod

from core.models import LeviosaResponse


class ResponseAnalyser(ABC):
    """
    Base class for response analysers.

    matches() returns a short description string when the response satisfies
    the condition, or None when it does not. The string is intended to be used
    directly in module output, e.g.:

        for resp in responses:
            if hit := analyser.matches(resp):
                print(f"[MODULE] {hit} — {resp.request.url}")
    """

    @abstractmethod
    def matches(self, response: LeviosaResponse) -> str | None:
        ...


class StatusCodeAnalyser(ResponseAnalyser):
    """Match responses whose status code is in the supplied set."""

    def __init__(self, codes: list[int]):
        self._codes = set(codes)

    def matches(self, response: LeviosaResponse) -> str | None:
        if response.status in self._codes:
            return f"status={response.status}"
        return None


class TextMatchAnalyser(ResponseAnalyser):
    """Match responses whose body contains a literal substring."""

    def __init__(self, text: str, case_sensitive: bool = True):
        self._text = text
        self._case_sensitive = case_sensitive

    def matches(self, response: LeviosaResponse) -> str | None:
        body = response.body.decode("utf-8", errors="replace")
        if self._case_sensitive:
            found = self._text in body
        else:
            found = self._text.lower() in body.lower()
        return f"body contains {self._text!r}" if found else None


class RegexAnalyser(ResponseAnalyser):
    """Match responses whose body contains a regex pattern."""

    def __init__(self, pattern: str, flags: int = 0):
        self._re = _re.compile(pattern, flags)

    def matches(self, response: LeviosaResponse) -> str | None:
        body = response.body.decode("utf-8", errors="replace")
        if self._re.search(body):
            return f"body matches /{self._re.pattern}/"
        return None


class ResponseSizeAnalyser(ResponseAnalyser):
    """
    Match responses whose body length falls within [min_size, max_size].
    At least one bound must be provided.
    """

    def __init__(self, min_size: int | None = None, max_size: int | None = None):
        if min_size is None and max_size is None:
            raise ValueError("ResponseSizeAnalyser requires at least one of min_size or max_size")
        self._min = min_size
        self._max = max_size

    def matches(self, response: LeviosaResponse) -> str | None:
        size = len(response.body)
        if self._min is not None and size < self._min:
            return None
        if self._max is not None and size > self._max:
            return None
        return f"size={size}"


class HeaderAnalyser(ResponseAnalyser):
    """
    Match responses that include a specific header.

    Modes (mutually exclusive; pattern takes priority over value):
      - name only:        header must be present (any value)
      - name + value:     header value must equal value (case-insensitive)
      - name + pattern:   header value must match the regex pattern
    """

    def __init__(
        self,
        name: str,
        value: str | None = None,
        pattern: str | None = None,
    ):
        self._name = name
        self._value = value
        self._pattern = _re.compile(pattern) if pattern else None

    def matches(self, response: LeviosaResponse) -> str | None:
        header_val = next(
            (v for k, v in response.headers.items() if k.lower() == self._name.lower()),
            None,
        )
        if header_val is None:
            return None

        if self._pattern is not None:
            if not self._pattern.search(header_val):
                return None
        elif self._value is not None:
            if header_val.lower() != self._value.lower():
                return None

        return f"header {self._name}: {header_val}"

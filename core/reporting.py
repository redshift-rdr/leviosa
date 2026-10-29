"""Output boundary for modules. Reporters can stream findings without retaining them."""
from dataclasses import dataclass, field
from typing import Protocol

from core.models import LeviosaRequest


@dataclass
class Finding:
    module: str
    request: LeviosaRequest
    observation: str
    evidence: dict = field(default_factory=dict)
    confidence: str = "observation"
    # Tabular observations are rendered together by the terminal reporter.
    terminal_visible: bool = True


class Reporter(Protocol):
    def report(self, finding: Finding) -> None: ...
    def write(self, message: str) -> None: ...


class TerminalReporter:
    def report(self, finding: Finding) -> None:
        if finding.terminal_visible:
            self.write(finding.observation)

    def write(self, message: str) -> None:
        print(message)

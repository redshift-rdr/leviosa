"""Console output plus optional append-only JSONL results; never writes SQLite."""
import base64
import json
from datetime import datetime, timezone

from core.reporting import TerminalReporter


class ResultsWriteError(RuntimeError):
    pass


def _json_value(value):
    if isinstance(value, bytes):
        return {"encoding": "base64", "value": base64.b64encode(value).decode("ascii")}
    raise TypeError(f"Cannot serialize result value of type {type(value).__name__}")


class JsonlResults:
    def __init__(self, path):
        self.file = open(path, "a+", encoding="utf-8")
        try:
            self.file.seek(0, 2)
            if self.file.tell():
                # Keep appended runs separate without truncating existing data.
                with open(path, "rb") as existing:
                    existing.seek(-1, 2)
                    newline = existing.read(1) == b"\n"
                if not newline:
                    self.file.write("\n")
        except BaseException:
            self.file.close()
            raise

    def emit(self, event):
        try:
            line = json.dumps(event, default=_json_value, ensure_ascii=True) + "\n"
        except (TypeError, ValueError) as exc:
            # Invalid module evidence is a module failure, not an output-device failure.
            raise ValueError(f"cannot encode result: {exc}") from exc
        try:
            self.file.write(line)
            self.file.flush()
        except (OSError, ValueError) as exc:
            raise ResultsWriteError(f"cannot write results: {exc}") from exc

    def close(self):
        self.file.close()


class ScanReporter:
    def __init__(self, results=None, terminal=None, fields=None):
        self.results = results
        self.terminal = terminal if terminal is not None else TerminalReporter()
        self.fields = fields or {}

    def scope(self, **fields):
        return ScanReporter(self.results, self.terminal, {**self.fields, **fields})

    def emit(self, event, **data):
        if self.results is not None:
            self.results.emit({"event": event, "timestamp": datetime.now(timezone.utc).isoformat(),
                               **self.fields, **data})

    def progress(self, event, message, **data):
        self.terminal.write(message)
        self.emit(event, **data)

    def write(self, message):
        self.terminal.write(message)
        self.emit("message", message=message)

    def report(self, finding):
        self.terminal.report(finding)
        req = finding.request
        self.emit("finding", module_class=finding.module, request_id=req.request_id, seed_id=req.seed_id,
                  method=req.method, url=req.url, observation=finding.observation,
                  confidence=finding.confidence, evidence=finding.evidence)

"""Plain, periodic console progress without pre-consuming request generators."""
import asyncio
import sys
from time import monotonic


class ProgressWriteError(RuntimeError):
    """Progress output failed; stop the run rather than silently losing status."""


class Progress:
    def __init__(self, label, *, enabled=True, interval=5.0, write=None):
        self.label, self.enabled, self.interval = label, enabled, interval
        self.write = write or (lambda message: print(message, file=sys.stderr, flush=True))
        self.sent = self.completed = self.active = self.errors = self.cancelled = 0
        self.phase = 'preparing requests'
        self.last_response = None
        self._timer = self._error = None
        self._closed = False

    def __enter__(self):
        if self.enabled:
            self._loop = asyncio.get_running_loop()
            self._start = monotonic()
            self._emit(self.phase)
            self._timer = self._loop.call_later(self.interval, self._tick)
        return self

    def _emit(self, phase):
        now = monotonic()
        last = 'none yet' if self.last_response is None else f'{now - self.last_response:.0f}s ago'
        cancelled = f' cancelled={self.cancelled}' if self.cancelled else ''
        try:
            self.write(f'[PROGRESS] {self.label}: {phase} | sent={self.sent} completed={self.completed} '
                       f'in-flight={self.active} errors={self.errors}{cancelled} '
                       f'elapsed={now - self._start:.0f}s last-response={last}')
        except (OSError, ValueError) as exc:
            raise ProgressWriteError(f'Cannot write progress output: {exc}') from exc

    def _tick(self):
        if self._closed:
            return
        try:
            self._emit(self.phase)
        except Exception as exc:
            # Surface output failures at the next producer checkpoint, without
            # leaking an unobserved background task or callback exception.
            self._error = exc
            return
        self._timer = self._loop.call_later(self.interval, self._tick)

    def set_phase(self, phase):
        if self._error is not None:
            raise self._error
        self.phase = phase

    def started(self):
        self.set_phase('waiting for responses')
        self.sent += 1
        self.active += 1

    def finished(self, status):
        self.completed += 1
        self.active -= 1
        self.errors += status == 0
        self.last_response = monotonic()
        self.set_phase('processing responses')

    def failed(self):
        self.completed += 1
        self.active -= 1
        self.errors += 1

    def cancelled_request(self):
        self.active -= 1
        self.cancelled += 1

    def __exit__(self, exc_type, exc, traceback):
        if not self.enabled:
            return False
        self._closed = True
        if self._timer is not None:
            self._timer.cancel()
        if self._error is not None:
            if exc_type is None:
                raise self._error
            return False
        if exc_type is None:
            phase = 'finished' if self.sent else 'finished (no requests sent)'
        elif issubclass(exc_type, (asyncio.CancelledError, KeyboardInterrupt, GeneratorExit)):
            phase = 'stopped'
        else:
            phase = 'failed'
        self._emit(phase)
        return False

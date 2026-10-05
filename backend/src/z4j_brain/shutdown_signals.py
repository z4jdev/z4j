"""Learn that the process is stopping at the signal, not at the teardown.

The ASGI server owns SIGTERM and SIGINT. It reacts by draining its HTTP and
WebSocket connections and only then runs the application's lifespan teardown,
which can be many seconds later. Anything that must change the instant the
process knows it is stopping cannot wait for that.

:func:`notify_on_shutdown_signals` chains onto whatever handlers are installed:
the callback runs first, then the previous handler runs exactly as it would
have. Nothing about how the server shuts down changes.

The callback runs inside a signal handler, between two bytecodes of whatever
the main thread was doing. It must be trivial: set a flag, nothing that takes
a lock, logs, or awaits.
"""

from __future__ import annotations

import contextlib
import signal
import threading
from collections.abc import Callable
from types import FrameType
from typing import Any

#: The signals an ASGI server treats as "stop": SIGBREAK exists on Windows only.
_SHUTDOWN_SIGNAL_NAMES = ("SIGTERM", "SIGINT", "SIGBREAK")


def _noop() -> None:
    return None


def _chained(
    previous: Any, callback: Callable[[], None]
) -> Callable[[int, FrameType | None], None]:
    def _handler(signum: int, frame: FrameType | None) -> None:
        # The callback must never keep the real handler from running, and an
        # exception raised here would surface inside unrelated main-thread code.
        with contextlib.suppress(Exception):
            callback()
        if callable(previous):
            previous(signum, frame)
        elif previous == signal.SIG_DFL:
            # Nothing was handling it: put the default back and deliver the
            # signal again, so the process ends the way it would have.
            signal.signal(signum, signal.SIG_DFL)
            signal.raise_signal(signum)
        # SIG_IGN: the process was ignoring this signal and still does.

    return _handler


def notify_on_shutdown_signals(callback: Callable[[], None]) -> Callable[[], None]:
    """Call ``callback`` when a stop signal arrives, then the previous handler.

    Returns a function that removes the chain again. Wherever a handler cannot
    be installed this does nothing and returns a no-op: off the main thread
    (a test client that runs the lifespan in a worker thread), for a signal
    the platform lacks, and for a handler that was not installed from Python
    and therefore cannot be called back. The lifespan teardown closes the
    same gate as a backstop, so skipping is safe; it is only later.
    """

    if threading.current_thread() is not threading.main_thread():
        return _noop

    installed: list[tuple[int, Any, Callable[[int, FrameType | None], None]]] = []
    for name in _SHUTDOWN_SIGNAL_NAMES:
        signum = getattr(signal, name, None)
        if signum is None:
            continue
        try:
            previous = signal.getsignal(signum)
            if previous is None:
                continue
            handler = _chained(previous, callback)
            signal.signal(signum, handler)
        except (ValueError, OSError, RuntimeError):
            continue
        installed.append((int(signum), previous, handler))

    if not installed:
        return _noop

    def _restore() -> None:
        if threading.current_thread() is not threading.main_thread():
            return
        for signum, previous, handler in installed:
            # Someone else may have replaced the handler since (the server
            # puts its own originals back when it exits); leave theirs alone.
            with contextlib.suppress(ValueError, OSError, RuntimeError):
                if signal.getsignal(signum) is handler:
                    signal.signal(signum, previous)
        installed.clear()

    return _restore


__all__ = ["notify_on_shutdown_signals"]

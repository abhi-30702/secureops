import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PyQt6.QtWidgets import QApplication
from db import DB


@pytest.fixture
def db():
    return DB(":memory:")


@pytest.fixture(autouse=True)
def join_qthreads(monkeypatch):
    """Deterministically join every QThread a test starts, killing the flaky
    'Fatal Python error: Aborted' from Qt teardown.

    Root cause: tests typically ``worker = SomeWorker(...)`` (no parent) and
    ``with qtbot.waitSignal(...): worker.start()``. ``waitSignal`` returns when
    the signal is *emitted*, which happens inside ``run()`` **before** ``run()``
    unwinds — so ``isRunning()`` can still be True. The moment the test returns,
    the parentless local's refcount hits 0 and sip destroys the C++ QThread
    while it is still running → ``QThread: Destroyed while thread is still
    running`` → ``std::terminate`` → abort. ``app.findChildren(QThread)`` can't
    help: a parentless thread isn't in the object tree, and it's collected
    before any teardown code runs anyway.

    Fix: wrap ``QThread.start`` so every started thread is held by a strong ref
    for the whole test (it can't be collected mid-run), then ``wait()`` on each
    during teardown before releasing the refs. Covers parentless and parented
    workers alike, without touching individual tests.
    """
    from PyQt6.QtCore import QThread

    started: list = []
    _orig_start = QThread.start

    def _tracking_start(self, *args, **kwargs):
        started.append(self)  # strong ref: no premature GC while running
        return _orig_start(self, *args, **kwargs)

    monkeypatch.setattr(QThread, "start", _tracking_start)

    yield

    app = QApplication.instance()
    if app is not None:
        app.processEvents()
    for thread in started:
        try:
            if thread.isRunning():
                thread.wait(5000)
        except RuntimeError:
            pass  # C++ side already gone — nothing to join
    if app is not None:
        app.processEvents()
    started.clear()

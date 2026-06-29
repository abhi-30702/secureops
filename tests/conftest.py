import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PyQt6.QtWidgets import QApplication
from db import DB


@pytest.fixture
def db():
    return DB(":memory:")


@pytest.fixture(autouse=True)
def process_events():
    """Flush pending Qt events and join lingering worker threads after each test.

    Tests that .start() a QThread typically wait on a completion signal, which
    fires *before* run() fully returns. The thread can still be executing its
    final lines (e.g. a DB status write) when the test's in-memory DB is torn
    down — a rare 'Cannot operate on a closed database' race, or a segfault in
    pytestqt teardown. Draining events and waiting for any still-running
    QThreads to finish closes that window deterministically.
    """
    from PyQt6.QtCore import QThread

    yield

    app = QApplication.instance()
    if app is None:
        return
    app.processEvents()
    # Give any worker thread that just emitted its completion signal time to
    # finish run() and be joined before the next test starts.
    for obj in app.findChildren(QThread):
        if obj.isRunning():
            obj.wait(2000)
    app.processEvents()

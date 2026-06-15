import gc
import pytest
from db import DB
from screens.widgets.company_selector import CompanySelector


@pytest.fixture(autouse=True)
def _gc_after_each():
    yield
    gc.collect()


def _db_with_extra():
    db = DB(":memory:")
    db.insert_company({"name": "ZZZ Test", "domains": '["zzz.com"]'})
    return db


def test_selector_populates_from_db(qtbot):
    db = _db_with_extra()
    sel = CompanySelector(db=db)
    qtbot.addWidget(sel)
    # 9 seeded + 1 inserted = 10 companies
    assert sel._combo.count() == 10


def test_signal_emitted_on_change(qtbot):
    db = _db_with_extra()
    sel = CompanySelector(db=db)
    qtbot.addWidget(sel)
    received = []
    sel.company_selected.connect(received.append)
    if sel._combo.count() > 1:
        sel._combo.setCurrentIndex(1)
    assert len(received) >= 1
    assert "name" in received[-1]


def test_refresh_updates_items(qtbot):
    db = _db_with_extra()
    sel = CompanySelector(db=db)
    qtbot.addWidget(sel)
    initial_count = sel._combo.count()
    db.insert_company({"name": "Extra Co", "domains": '["extra.com"]'})
    sel.refresh()
    assert sel._combo.count() == initial_count + 1

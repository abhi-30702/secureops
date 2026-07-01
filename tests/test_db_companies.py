import pytest
from db import DB


@pytest.fixture
def fresh_db():
    return DB(":memory:")


def test_new_db_has_no_companies(fresh_db):
    # Companies start empty by default; the operator adds their own.
    assert fresh_db.get_companies() == []


def test_insert_and_get_company(fresh_db):
    cid = fresh_db.insert_company({
        "name": "Test Co",
        "domains": '["test.com"]',
        "ip_ranges": '["10.99.0.0/24"]',
        "firewall_type": "pfSense",
    })
    companies = fresh_db.get_companies()
    found = next((c for c in companies if c["id"] == cid), None)
    assert found is not None
    assert found["name"] == "Test Co"
    assert found["firewall_type"] == "pfSense"


def test_get_companies_ordered_by_name(fresh_db):
    companies = fresh_db.get_companies()
    names = [c["name"] for c in companies]
    assert names == sorted(names)


def test_update_company(fresh_db):
    cid = fresh_db.insert_company({"name": "Old Name", "domains": "[]"})
    fresh_db.update_company(cid, {"name": "New Name", "firewall_type": "Fortinet"})
    companies = fresh_db.get_companies()
    found = next(c for c in companies if c["id"] == cid)
    assert found["name"] == "New Name"
    assert found["firewall_type"] == "Fortinet"


def test_delete_company(fresh_db):
    initial = len(fresh_db.get_companies())
    cid = fresh_db.insert_company({"name": "To Delete", "domains": "[]"})
    assert len(fresh_db.get_companies()) == initial + 1
    fresh_db.delete_company(cid)
    assert len(fresh_db.get_companies()) == initial

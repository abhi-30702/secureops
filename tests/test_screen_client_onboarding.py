from PyQt6.QtCore import Qt
from screens.client_onboarding import ClientOnboardingScreen
from db import DB


def test_client_screen_has_name_field(qtbot):
    screen = ClientOnboardingScreen()
    qtbot.addWidget(screen)
    assert screen._name_input is not None


def test_client_screen_has_domains_field(qtbot):
    screen = ClientOnboardingScreen()
    qtbot.addWidget(screen)
    assert screen._domains_input is not None


def test_client_screen_has_firewall_combo(qtbot):
    screen = ClientOnboardingScreen()
    qtbot.addWidget(screen)
    assert screen._firewall_combo.count() > 0


def test_client_screen_has_company_list(qtbot):
    screen = ClientOnboardingScreen()
    qtbot.addWidget(screen)
    assert screen._company_list is not None


def test_client_screen_has_save_button(qtbot):
    screen = ClientOnboardingScreen()
    qtbot.addWidget(screen)
    assert screen._save_btn is not None


def test_client_screen_starts_empty(qtbot):
    db = DB(":memory:")
    screen = ClientOnboardingScreen(db=db)
    qtbot.addWidget(screen)
    # No seed data — the operator adds their own companies.
    assert screen._company_list.count() == 0


def test_client_screen_save_updates_company(qtbot):
    db = DB(":memory:")
    db.insert_company({"name": "Existing Co", "domains": '["existing.com"]'})
    screen = ClientOnboardingScreen(db=db)
    qtbot.addWidget(screen)
    screen.show()

    # First company is selected by default; edit its name and save
    screen._name_input.setText("Renamed Corp")
    qtbot.mouseClick(screen._save_btn, Qt.MouseButton.LeftButton)

    assert screen._status_label.text() == "Saved ✓"
    companies = db.get_companies()
    names = [c["name"] for c in companies]
    assert "Renamed Corp" in names


def test_client_screen_add_new_company(qtbot):
    db = DB(":memory:")
    screen = ClientOnboardingScreen(db=db)
    qtbot.addWidget(screen)
    screen.show()

    qtbot.mouseClick(screen._add_btn, Qt.MouseButton.LeftButton)
    screen._name_input.setText("Brand New Co")
    screen._domains_input.setText("brandnew.com")
    qtbot.mouseClick(screen._save_btn, Qt.MouseButton.LeftButton)

    companies = db.get_companies()
    names = [c["name"] for c in companies]
    assert "Brand New Co" in names

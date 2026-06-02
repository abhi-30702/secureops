from PyQt6.QtCore import Qt
from screens.client_onboarding import ClientOnboardingScreen


def test_client_screen_has_company_name_field(qtbot):
    screen = ClientOnboardingScreen()
    qtbot.addWidget(screen)
    assert screen._company_name_input is not None


def test_client_screen_has_domain_field(qtbot):
    screen = ClientOnboardingScreen()
    qtbot.addWidget(screen)
    assert screen._domain_input is not None


def test_client_screen_has_firewall_combo(qtbot):
    screen = ClientOnboardingScreen()
    qtbot.addWidget(screen)
    assert screen._firewall_combo.count() > 0


def test_client_screen_has_notes_field(qtbot):
    screen = ClientOnboardingScreen()
    qtbot.addWidget(screen)
    assert screen._notes_input is not None


def test_client_screen_has_save_button(qtbot):
    screen = ClientOnboardingScreen()
    qtbot.addWidget(screen)
    assert screen._save_btn is not None


def test_client_screen_save_shows_confirmation(qtbot):
    screen = ClientOnboardingScreen()
    qtbot.addWidget(screen)
    screen.show()

    assert not screen._confirmation_label.isVisible()
    qtbot.mouseClick(screen._save_btn, Qt.MouseButton.LeftButton)
    assert screen._confirmation_label.isVisible()


def test_client_screen_save_persists_to_db(qtbot):
    from db import DB
    from models import Client

    db = DB(":memory:")
    screen = ClientOnboardingScreen(db=db)
    qtbot.addWidget(screen)
    screen.show()

    screen._company_name_input.setText("Acme Corp")
    screen._domain_input.setText("acme.com")

    qtbot.mouseClick(screen._save_btn, Qt.MouseButton.LeftButton)

    clients = db.query_clients()
    assert len(clients) == 1
    assert clients[0].name == "Acme Corp"
    assert clients[0].domain == "acme.com"


def test_client_screen_save_without_db_shows_confirmation_no_crash(qtbot):
    screen = ClientOnboardingScreen(db=None)
    qtbot.addWidget(screen)
    screen.show()

    screen._company_name_input.setText("Test Co")
    qtbot.mouseClick(screen._save_btn, Qt.MouseButton.LeftButton)

    assert screen._confirmation_label.isVisible()

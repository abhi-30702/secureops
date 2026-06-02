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

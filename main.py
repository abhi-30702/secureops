import sys
from app import create_app
from tool_checker import check_tools
from main_window import MainWindow


def build_window() -> MainWindow:
    tool_results = check_tools()
    return MainWindow(tool_results)


def main():
    app = create_app(sys.argv)
    window = build_window()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

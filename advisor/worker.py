from PyQt6.QtCore import QThread, pyqtSignal
from datetime import datetime, timezone
from models import AdvisoryItem


def parse_advisor_response(text: str, scan_id: int) -> list[AdvisoryItem]:
    tier_map = {
        "IMMEDIATE:": "immediate",
        "SHORT_TERM:": "short_term",
        "PREVENTIVE:": "preventive",
    }
    items: list[AdvisoryItem] = []
    current_tier: str | None = None

    for line in text.splitlines():
        stripped = line.strip()
        if stripped in tier_map:
            current_tier = tier_map[stripped]
        elif current_tier and stripped and stripped[0].isdigit() and ". " in stripped:
            _, item_text = stripped.split(". ", 1)
            if item_text.strip():
                items.append(AdvisoryItem(
                    id=None,
                    scan_id=scan_id,
                    tier=current_tier,
                    text=item_text.strip(),
                    accepted=False,
                    created_at=datetime.now(timezone.utc).isoformat(),
                ))

    required = {"immediate", "short_term", "preventive"}
    if not required.issubset({i.tier for i in items}):
        return []
    return items


class AdvisorWorker(QThread):
    item_ready = pyqtSignal(object)
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, scan_id: int, db, api_key: str, parent=None):
        super().__init__(parent)
        self._scan_id = scan_id
        self._db = db
        self._api_key = api_key
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def run(self) -> None:
        try:
            scan = self._resolve_scan()
            if scan is None or self._cancelled:
                return

            client = self._resolve_client(scan.client_id)
            hosts = self._db.query_hosts_by_scan(self._scan_id)
            findings = self._db.query_findings_by_scan(self._scan_id)

            if self._cancelled:
                return

            from advisor.prompt_builder import PromptBuilder
            from advisor.gemini_client import GeminiClient

            prompt = PromptBuilder().build(scan, client, hosts, findings)
            response = GeminiClient(self._api_key).generate(prompt)

            if self._cancelled:
                return

            items = parse_advisor_response(response, self._scan_id)
            if not items:
                self.error.emit("Could not parse advisor response — try again")
                return

            for item in items:
                if self._cancelled:
                    break
                item.id = self._db.insert_advisory_item(item)
                self.item_ready.emit(item)

        except RuntimeError as exc:
            self.error.emit(str(exc))
        except Exception as exc:
            self.error.emit(f"Unexpected error: {exc}")
        finally:
            self.finished.emit()

    def _resolve_scan(self):
        for c in self._db.query_clients():
            for s in self._db.query_scans_by_client(c.id):
                if s.id == self._scan_id:
                    return s
        for s in self._db.query_scans_by_client(None):
            if s.id == self._scan_id:
                return s
        return None

    def _resolve_client(self, client_id):
        if client_id is None:
            return None
        for c in self._db.query_clients():
            if c.id == client_id:
                return c
        return None

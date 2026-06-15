import threading
from datetime import datetime, timezone

from PyQt6.QtCore import QThread, pyqtSignal

from db import DB
from models import Finding
from workers.tools import aws_auditor, gcp_auditor


class CloudWorker(QThread):
    """QThread worker that audits AWS and GCP cloud environments.

    Emits findings as they are discovered and persists them to SQLite
    immediately — one at a time — so a crash loses nothing.
    """

    finding_discovered = pyqtSignal(dict)
    tool_progress      = pyqtSignal(str, int, str)
    tool_log           = pyqtSignal(str)
    scan_complete      = pyqtSignal(dict)
    error_occurred     = pyqtSignal(str, str)

    def __init__(
        self,
        scan_id: int,
        db: DB,
        aws_profile: str,
        aws_region: str,
        gcp_project: str,
        gcp_creds_file: str,
        parent=None,
    ):
        super().__init__(parent)
        self._scan_id = scan_id
        self._db = db
        self._aws_profile = aws_profile
        self._aws_region = aws_region
        self._gcp_project = gcp_project
        self._gcp_creds_file = gcp_creds_file
        self._stop = threading.Event()

    def stop(self) -> None:
        """Signal the worker to stop after the current tool finishes."""
        self._stop.set()

    # ── main thread entry ────────────────────────────────────────────────────

    def run(self) -> None:  # noqa: C901
        total = 0

        if self._stop.is_set():
            self._db.update_scan_status(self._scan_id, "cancelled")
            return

        # ── Stage 1: AWS audit ──────────────────────────────────────────────
        if self._aws_profile or self._aws_region:
            self.tool_log.emit("[cloud] Stage 1 — AWS audit")
            self.tool_progress.emit("aws_auditor", 0, "running")
            try:
                aws_findings = aws_auditor.run(
                    profile=self._aws_profile,
                    region=self._aws_region,
                )
                for f in aws_findings:
                    finding = self._save_finding(f)
                    self.finding_discovered.emit({
                        "title": finding.title,
                        "severity": finding.severity,
                        "tool": finding.tool,
                        "description": finding.description,
                        "host": f.get("host", ""),
                    })
                    total += 1
                self.tool_log.emit(f"[cloud] AWS audit complete — {len(aws_findings)} findings")
                self.tool_progress.emit("aws_auditor", len(aws_findings), "done")
            except Exception as exc:
                self.tool_log.emit(f"[cloud] AWS audit error: {exc}")
                self.error_occurred.emit("aws_auditor", str(exc))

        if self._stop.is_set():
            self._db.update_scan_status(self._scan_id, "cancelled")
            return

        # ── Stage 2: GCP audit ──────────────────────────────────────────────
        if self._gcp_project:
            self.tool_log.emit("[cloud] Stage 2 — GCP audit")
            self.tool_progress.emit("gcp_auditor", 0, "running")
            try:
                gcp_findings = gcp_auditor.run(
                    project_id=self._gcp_project,
                    credentials_file=self._gcp_creds_file,
                )
                for f in gcp_findings:
                    finding = self._save_finding(f)
                    self.finding_discovered.emit({
                        "title": finding.title,
                        "severity": finding.severity,
                        "tool": finding.tool,
                        "description": finding.description,
                        "host": f.get("host", ""),
                    })
                    total += 1
                self.tool_log.emit(f"[cloud] GCP audit complete — {len(gcp_findings)} findings")
                self.tool_progress.emit("gcp_auditor", len(gcp_findings), "done")
            except Exception as exc:
                self.tool_log.emit(f"[cloud] GCP audit error: {exc}")
                self.error_occurred.emit("gcp_auditor", str(exc))

        self._db.update_scan_status(self._scan_id, "complete")
        self.scan_complete.emit({"total": total})

    # ── helpers ──────────────────────────────────────────────────────────────

    def _save_finding(self, f: dict) -> Finding:
        """Wrap a tool finding dict in a Finding dataclass and persist it."""
        finding = Finding(
            id=None,
            scan_id=self._scan_id,
            host_id=None,
            tool=f.get("tool", "cloud_auditor"),
            severity=f.get("severity", "info"),
            title=f.get("title", ""),
            description=f.get("description", ""),
            raw_json=f.get("raw", ""),
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        finding.id = self._db.insert_finding(finding)
        return finding

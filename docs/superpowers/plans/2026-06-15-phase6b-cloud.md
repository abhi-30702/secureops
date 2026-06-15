# Phase 6b — Cloud Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Cloud Audit module to SecureOps that checks AWS (S3, IAM, Security Groups) and GCP (GCS buckets, service account roles) for misconfigurations, streams findings into the existing `findings` table, and surfaces results on a new `CloudPage`.

**Architecture:** Two tool wrappers (`aws_auditor.py`, `gcp_auditor.py`) feed a `CloudWorker` QThread which writes findings to SQLite and emits signals to `CloudPage`. Either provider can be skipped by leaving credentials blank.

**Tech Stack:** PyQt6, boto3, google-cloud-storage, google-cloud-resource-manager, google-cloud-iam, SQLite

---

## Task 1: AWS tool wrapper (TDD)

**Files:**
- Create: `workers/tools/aws_auditor.py`
- Create: `tests/test_aws_auditor.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_aws_auditor.py
import pytest
from unittest.mock import patch, MagicMock
from botocore.exceptions import NoCredentialsError
from workers.tools import aws_auditor


def test_returns_empty_on_no_credentials():
    with patch("workers.tools.aws_auditor.boto3.Session") as mock_session:
        mock_session.return_value.client.side_effect = NoCredentialsError()
        result = aws_auditor.run("bad-profile", "us-east-1")
    assert result == []


def test_finds_public_s3_bucket():
    with patch("workers.tools.aws_auditor.boto3.Session") as mock_session:
        s3 = MagicMock()
        s3.list_buckets.return_value = {"Buckets": [{"Name": "my-public-bucket"}]}
        s3.get_bucket_acl.return_value = {
            "Grants": [{
                "Grantee": {
                    "Type": "Group",
                    "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                },
                "Permission": "READ",
            }]
        }
        iam = MagicMock()
        iam.list_users.return_value = {"Users": []}
        ec2 = MagicMock()
        ec2.describe_security_groups.return_value = {"SecurityGroups": []}

        def client_factory(service, **kwargs):
            return {"s3": s3, "iam": iam, "ec2": ec2}[service]

        mock_session.return_value.client.side_effect = client_factory
        result = aws_auditor.run("", "us-east-1")

    assert len(result) == 1
    assert result[0]["severity"] == "critical"
    assert result[0]["title"] == "Public S3 bucket"
    assert "my-public-bucket" in result[0]["description"]


def test_finds_iam_admin_user():
    with patch("workers.tools.aws_auditor.boto3.Session") as mock_session:
        s3 = MagicMock()
        s3.list_buckets.return_value = {"Buckets": []}
        iam = MagicMock()
        iam.list_users.return_value = {"Users": [{"UserName": "admin-user"}]}
        iam.list_attached_user_policies.return_value = {
            "AttachedPolicies": [{"PolicyName": "AdministratorAccess"}]
        }
        ec2 = MagicMock()
        ec2.describe_security_groups.return_value = {"SecurityGroups": []}

        def client_factory(service, **kwargs):
            return {"s3": s3, "iam": iam, "ec2": ec2}[service]

        mock_session.return_value.client.side_effect = client_factory
        result = aws_auditor.run("", "us-east-1")

    assert len(result) == 1
    assert result[0]["severity"] == "high"
    assert result[0]["title"] == "IAM user with direct AdministratorAccess"
    assert "admin-user" in result[0]["description"]


def test_finds_open_security_group():
    with patch("workers.tools.aws_auditor.boto3.Session") as mock_session:
        s3 = MagicMock()
        s3.list_buckets.return_value = {"Buckets": []}
        iam = MagicMock()
        iam.list_users.return_value = {"Users": []}
        ec2 = MagicMock()
        ec2.describe_security_groups.return_value = {
            "SecurityGroups": [{
                "GroupId": "sg-12345",
                "IpPermissions": [{
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }],
            }]
        }

        def client_factory(service, **kwargs):
            return {"s3": s3, "iam": iam, "ec2": ec2}[service]

        mock_session.return_value.client.side_effect = client_factory
        result = aws_auditor.run("", "us-east-1")

    assert len(result) == 1
    assert result[0]["severity"] == "high"
    assert result[0]["title"] == "Unrestricted inbound rule in security group"
    assert "sg-12345" in result[0]["description"]
```

- [ ] **Step 2: Run to confirm failures**

```bash
source venv/bin/activate && pytest tests/test_aws_auditor.py -v
```
Expected: 4 errors (module not found)

- [ ] **Step 3: Implement `workers/tools/aws_auditor.py`**

```python
import json
import boto3
from botocore.exceptions import NoCredentialsError

_PUBLIC_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
_OPEN_PORTS = {0, 22, 3389}


def run(profile: str, region: str) -> list[dict]:
    findings = []
    try:
        session = boto3.Session(
            profile_name=profile or None,
            region_name=region or "us-east-1",
        )
        s3  = session.client("s3")
        iam = session.client("iam")
        ec2 = session.client("ec2")
    except NoCredentialsError:
        return []
    except Exception:
        return []

    # S3 public buckets
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            name = bucket["Name"]
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl.get("Grants", []):
                    uri = grant.get("Grantee", {}).get("URI", "")
                    if uri == _PUBLIC_URI:
                        findings.append({
                            "tool": "aws_auditor",
                            "severity": "critical",
                            "title": "Public S3 bucket",
                            "description": f"Bucket '{name}' grants public READ access.",
                            "host": name,
                            "port": None,
                            "raw": json.dumps({"bucket": name, "grant": grant}),
                        })
                        break
            except Exception:
                pass
    except Exception:
        pass

    # IAM direct admin
    try:
        users = iam.list_users().get("Users", [])
        for user in users:
            uname = user["UserName"]
            try:
                policies = iam.list_attached_user_policies(UserName=uname).get("AttachedPolicies", [])
                for p in policies:
                    if p["PolicyName"] == "AdministratorAccess":
                        findings.append({
                            "tool": "aws_auditor",
                            "severity": "high",
                            "title": "IAM user with direct AdministratorAccess",
                            "description": f"User '{uname}' has AdministratorAccess attached directly.",
                            "host": uname,
                            "port": None,
                            "raw": json.dumps({"user": uname}),
                        })
                        break
            except Exception:
                pass
    except Exception:
        pass

    # EC2 security groups
    try:
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        for sg in sgs:
            sg_id = sg["GroupId"]
            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                for cidr in rule.get("IpRanges", []):
                    if cidr.get("CidrIp") == "0.0.0.0/0" and from_port in _OPEN_PORTS:
                        findings.append({
                            "tool": "aws_auditor",
                            "severity": "high",
                            "title": "Unrestricted inbound rule in security group",
                            "description": f"Security group '{sg_id}' allows 0.0.0.0/0 on port {from_port}.",
                            "host": sg_id,
                            "port": from_port if from_port else None,
                            "raw": json.dumps({"sg": sg_id, "port": from_port}),
                        })
                        break
                for cidr6 in rule.get("Ipv6Ranges", []):
                    if cidr6.get("CidrIpv6") == "::/0" and from_port in _OPEN_PORTS:
                        findings.append({
                            "tool": "aws_auditor",
                            "severity": "high",
                            "title": "Unrestricted inbound rule in security group",
                            "description": f"Security group '{sg_id}' allows ::/0 on port {from_port}.",
                            "host": sg_id,
                            "port": from_port if from_port else None,
                            "raw": json.dumps({"sg": sg_id, "port": from_port, "ipv6": True}),
                        })
                        break
    except Exception:
        pass

    return findings
```

- [ ] **Step 4: Run to confirm passing**

```bash
pytest tests/test_aws_auditor.py -v
```
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add workers/tools/aws_auditor.py tests/test_aws_auditor.py
git commit -m "feat: add AWS auditor tool wrapper (S3, IAM, security groups)"
```

---

## Task 2: GCP tool wrapper (TDD)

**Files:**
- Create: `workers/tools/gcp_auditor.py`
- Create: `tests/test_gcp_auditor.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_gcp_auditor.py
import json
import pytest
from unittest.mock import patch, MagicMock
from workers.tools import gcp_auditor


def test_returns_empty_on_no_credentials():
    with patch("workers.tools.gcp_auditor.storage.Client") as mock_client:
        from google.auth.exceptions import DefaultCredentialsError
        mock_client.side_effect = DefaultCredentialsError()
        result = gcp_auditor.run("my-project", "")
    assert result == []


def test_finds_public_gcs_bucket():
    with patch("workers.tools.gcp_auditor.storage.Client") as mock_storage_cls, \
         patch("workers.tools.gcp_auditor.resourcemanager_v3.ProjectsClient") as mock_rm_cls:

        mock_bucket = MagicMock()
        mock_bucket.name = "public-bucket"
        policy = MagicMock()
        policy.bindings = [
            MagicMock(role="roles/storage.objectViewer", members=["allUsers"])
        ]
        mock_bucket.get_iam_policy.return_value = policy

        mock_storage = MagicMock()
        mock_storage.list_buckets.return_value = [mock_bucket]
        mock_storage_cls.return_value = mock_storage

        mock_rm = MagicMock()
        mock_rm.get_iam_policy.return_value = MagicMock(bindings=[])
        mock_rm_cls.return_value = mock_rm

        result = gcp_auditor.run("my-project", "")

    assert len(result) == 1
    assert result[0]["severity"] == "critical"
    assert result[0]["title"] == "Public GCS bucket"
    assert "public-bucket" in result[0]["description"]


def test_finds_privileged_service_account():
    with patch("workers.tools.gcp_auditor.storage.Client") as mock_storage_cls, \
         patch("workers.tools.gcp_auditor.resourcemanager_v3.ProjectsClient") as mock_rm_cls:

        mock_storage = MagicMock()
        mock_storage.list_buckets.return_value = []
        mock_storage_cls.return_value = mock_storage

        mock_rm = MagicMock()
        binding = MagicMock()
        binding.role = "roles/owner"
        binding.members = ["serviceAccount:deploy@my-project.iam.gserviceaccount.com"]
        mock_rm.get_iam_policy.return_value = MagicMock(bindings=[binding])
        mock_rm_cls.return_value = mock_rm

        result = gcp_auditor.run("my-project", "")

    assert len(result) == 1
    assert result[0]["severity"] == "high"
    assert result[0]["title"] == "Service account with owner/editor role"
    assert "deploy@my-project" in result[0]["description"]
```

- [ ] **Step 2: Run to confirm failures**

```bash
pytest tests/test_gcp_auditor.py -v
```
Expected: 3 errors (module not found)

- [ ] **Step 3: Implement `workers/tools/gcp_auditor.py`**

```python
import json
from google.cloud import storage, resourcemanager_v3
from google.auth.exceptions import DefaultCredentialsError

_PRIVILEGED_ROLES = {"roles/owner", "roles/editor"}
_PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


def run(project_id: str, credentials_file: str) -> list[dict]:
    findings = []
    try:
        if credentials_file:
            from google.oauth2 import service_account
            creds = service_account.Credentials.from_service_account_file(credentials_file)
            storage_client = storage.Client(project=project_id, credentials=creds)
            rm_client = resourcemanager_v3.ProjectsClient(credentials=creds)
        else:
            storage_client = storage.Client(project=project_id)
            rm_client = resourcemanager_v3.ProjectsClient()
    except DefaultCredentialsError:
        return []
    except Exception:
        return []

    # GCS public buckets
    try:
        for bucket in storage_client.list_buckets(project=project_id):
            try:
                policy = bucket.get_iam_policy()
                for binding in policy.bindings:
                    if any(m in _PUBLIC_MEMBERS for m in binding.members):
                        findings.append({
                            "tool": "gcp_auditor",
                            "severity": "critical",
                            "title": "Public GCS bucket",
                            "description": f"Bucket '{bucket.name}' has public IAM binding (role: {binding.role}).",
                            "host": bucket.name,
                            "port": None,
                            "raw": json.dumps({"bucket": bucket.name, "role": binding.role}),
                        })
                        break
            except Exception:
                pass
    except Exception:
        pass

    # GCP IAM: service accounts with owner/editor
    try:
        policy = rm_client.get_iam_policy(request={"resource": f"projects/{project_id}"})
        for binding in policy.bindings:
            if binding.role in _PRIVILEGED_ROLES:
                for member in binding.members:
                    if member.startswith("serviceAccount:"):
                        findings.append({
                            "tool": "gcp_auditor",
                            "severity": "high",
                            "title": "Service account with owner/editor role",
                            "description": f"'{member}' has role '{binding.role}' on project '{project_id}'.",
                            "host": member,
                            "port": None,
                            "raw": json.dumps({"member": member, "role": binding.role}),
                        })
    except Exception:
        pass

    return findings
```

- [ ] **Step 4: Run to confirm passing**

```bash
pytest tests/test_gcp_auditor.py -v
```
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add workers/tools/gcp_auditor.py tests/test_gcp_auditor.py
git commit -m "feat: add GCP auditor tool wrapper (GCS public buckets, IAM roles)"
```

---

## Task 3: CloudWorker (TDD)

**Files:**
- Create: `workers/cloud_worker.py`
- Create: `tests/test_cloud_worker.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_cloud_worker.py
import gc
import pytest
from unittest.mock import patch, MagicMock
from PyQt6.QtWidgets import QApplication
from db import DB
from workers.cloud_worker import CloudWorker

FAKE_AWS_FINDINGS = [
    {"tool": "aws_auditor", "severity": "critical", "title": "Public S3 bucket",
     "description": "Bucket 'bad'", "host": "bad", "port": None, "raw": "{}"},
]
FAKE_GCP_FINDINGS = [
    {"tool": "gcp_auditor", "severity": "high", "title": "Service account with owner/editor role",
     "description": "deploy@ has roles/owner", "host": "deploy@", "port": None, "raw": "{}"},
]


@pytest.fixture(autouse=True)
def _gc_after_each():
    yield
    gc.collect()


def _make_db_with_scan():
    db = DB(":memory:")
    db._conn.execute(
        "INSERT INTO scans (id, client_id, status, scan_type, target, created_at) "
        "VALUES (1, 1, 'running', 'cloud', 'cloud', '')"
    )
    db._conn.commit()
    return db


def test_findings_emitted_for_aws():
    db = _make_db_with_scan()
    emitted = []

    with patch("workers.cloud_worker.aws_auditor.run", return_value=FAKE_AWS_FINDINGS), \
         patch("workers.cloud_worker.gcp_auditor.run", return_value=[]):
        worker = CloudWorker(
            scan_id=1, db=db,
            aws_profile="test", aws_region="us-east-1",
            gcp_project="", gcp_creds_file="",
        )
        worker.finding_discovered.connect(emitted.append)
        worker.run()

    assert len(emitted) == 1
    assert emitted[0]["title"] == "Public S3 bucket"


def test_findings_written_to_db():
    db = _make_db_with_scan()

    with patch("workers.cloud_worker.aws_auditor.run", return_value=FAKE_AWS_FINDINGS), \
         patch("workers.cloud_worker.gcp_auditor.run", return_value=FAKE_GCP_FINDINGS):
        worker = CloudWorker(
            scan_id=1, db=db,
            aws_profile="test", aws_region="us-east-1",
            gcp_project="my-project", gcp_creds_file="",
        )
        worker.run()

    rows = db._conn.execute("SELECT * FROM findings WHERE scan_id=1").fetchall()
    assert len(rows) == 2


def test_gcp_skipped_when_no_project():
    db = _make_db_with_scan()

    with patch("workers.cloud_worker.aws_auditor.run", return_value=[]) as mock_aws, \
         patch("workers.cloud_worker.gcp_auditor.run", return_value=[]) as mock_gcp:
        worker = CloudWorker(
            scan_id=1, db=db,
            aws_profile="test", aws_region="us-east-1",
            gcp_project="", gcp_creds_file="",
        )
        worker.run()

    mock_gcp.assert_not_called()


def test_aws_skipped_when_no_credentials():
    db = _make_db_with_scan()

    with patch("workers.cloud_worker.aws_auditor.run", return_value=[]) as mock_aws, \
         patch("workers.cloud_worker.gcp_auditor.run", return_value=[]) as mock_gcp:
        worker = CloudWorker(
            scan_id=1, db=db,
            aws_profile="", aws_region="",
            gcp_project="my-project", gcp_creds_file="",
        )
        worker.run()

    mock_aws.assert_not_called()


def test_scan_complete_fires():
    db = _make_db_with_scan()
    completed = []

    with patch("workers.cloud_worker.aws_auditor.run", return_value=FAKE_AWS_FINDINGS), \
         patch("workers.cloud_worker.gcp_auditor.run", return_value=FAKE_GCP_FINDINGS):
        worker = CloudWorker(
            scan_id=1, db=db,
            aws_profile="test", aws_region="us-east-1",
            gcp_project="my-project", gcp_creds_file="",
        )
        worker.scan_complete.connect(completed.append)
        worker.run()

    assert len(completed) == 1
    assert completed[0]["total"] == 2
```

- [ ] **Step 2: Run to confirm failures**

```bash
pytest tests/test_cloud_worker.py -v
```
Expected: 5 errors (module not found)

- [ ] **Step 3: Read db.py to check `insert_finding` signature**

Read `db.py` and find the `insert_finding` method. Note its parameter names. The `findings` table has columns: `scan_id, tool, severity, title, description, host, port, raw, created_at`.

- [ ] **Step 4: Implement `workers/cloud_worker.py`**

```python
import threading
from datetime import datetime, timezone
from PyQt6.QtCore import QThread, pyqtSignal
from db import DB
from workers.tools import aws_auditor, gcp_auditor


class CloudWorker(QThread):
    finding_discovered = pyqtSignal(dict)
    tool_progress      = pyqtSignal(str, int, str)
    tool_log           = pyqtSignal(str)
    scan_complete      = pyqtSignal(dict)
    error_occurred     = pyqtSignal(str, str)

    def __init__(self, scan_id: int, db: DB,
                 aws_profile: str, aws_region: str,
                 gcp_project: str, gcp_creds_file: str,
                 parent=None):
        super().__init__(parent)
        self._scan_id = scan_id
        self._db = db
        self._aws_profile = aws_profile
        self._aws_region = aws_region
        self._gcp_project = gcp_project
        self._gcp_creds_file = gcp_creds_file
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        total = 0

        if self._stop.is_set():
            self._db.update_scan_status(self._scan_id, "cancelled")
            return

        # AWS stage
        if self._aws_profile or self._aws_region:
            self.tool_log.emit("[cloud] running AWS audit…")
            self.tool_progress.emit("aws_auditor", 0, "running")
            try:
                findings = aws_auditor.run(self._aws_profile, self._aws_region)
                for f in findings:
                    f["scan_id"] = self._scan_id
                    f["created_at"] = datetime.now(timezone.utc).isoformat()
                    self._db.insert_finding(f)
                    self.finding_discovered.emit(f)
                    total += 1
                self.tool_progress.emit("aws_auditor", len(findings), "complete")
            except Exception as e:
                self.error_occurred.emit("aws_auditor", str(e))

        if self._stop.is_set():
            self._db.update_scan_status(self._scan_id, "cancelled")
            return

        # GCP stage
        if self._gcp_project:
            self.tool_log.emit("[cloud] running GCP audit…")
            self.tool_progress.emit("gcp_auditor", 0, "running")
            try:
                findings = gcp_auditor.run(self._gcp_project, self._gcp_creds_file)
                for f in findings:
                    f["scan_id"] = self._scan_id
                    f["created_at"] = datetime.now(timezone.utc).isoformat()
                    self._db.insert_finding(f)
                    self.finding_discovered.emit(f)
                    total += 1
                self.tool_progress.emit("gcp_auditor", len(findings), "complete")
            except Exception as e:
                self.error_occurred.emit("gcp_auditor", str(e))

        self._db.update_scan_status(self._scan_id, "complete")
        self.scan_complete.emit({"total": total})
```

**IMPORTANT:** Before writing the final code, read `db.py` to check the exact `insert_finding` signature. It may take a `Finding` dataclass or a dict. Adjust accordingly.

- [ ] **Step 5: Run to confirm passing**

```bash
pytest tests/test_cloud_worker.py -v
```
Expected: 5 passed

- [ ] **Step 6: Commit**

```bash
git add workers/cloud_worker.py tests/test_cloud_worker.py
git commit -m "feat: add CloudWorker QThread with AWS and GCP audit stages"
```

---

## Task 4: CloudPage UI

**Files:**
- Create: `screens/cloud_page.py`

Read `screens/incident_page.py` and `screens/osint_page.py` first for patterns.

- [ ] **Step 1: Implement `screens/cloud_page.py`**

```python
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QPlainTextEdit, QGroupBox, QFileDialog, QSplitter
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from db import DB
from workers.cloud_worker import CloudWorker
from screens.widgets.finding_cards import FindingCards

BG      = "#FEFACD"
ACCENT  = "#5F4A8B"
TEXT    = "#2A1F45"
SURFACE = "#FFFEF2"
BORDER  = "#C8B8E8"


class CloudPage(QWidget):
    def __init__(self, db: DB = None, parent=None):
        super().__init__(parent)
        self._db = db
        self._worker = None
        self._scan_id = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        # Header
        header = QLabel("Cloud Audit")
        header.setFont(QFont("DM Sans", 18, QFont.Weight.Bold))
        layout.addWidget(header)

        # AWS group
        aws_group = QGroupBox("AWS")
        aws_layout = QVBoxLayout(aws_group)
        profile_row = QHBoxLayout()
        profile_row.addWidget(QLabel("Profile:"))
        self._aws_profile = QLineEdit()
        self._aws_profile.setPlaceholderText("default (leave blank to skip AWS)")
        profile_row.addWidget(self._aws_profile)
        aws_layout.addLayout(profile_row)
        region_row = QHBoxLayout()
        region_row.addWidget(QLabel("Region:"))
        self._aws_region = QLineEdit()
        self._aws_region.setPlaceholderText("us-east-1")
        region_row.addWidget(self._aws_region)
        aws_layout.addLayout(region_row)
        layout.addWidget(aws_group)

        # GCP group
        gcp_group = QGroupBox("GCP")
        gcp_layout = QVBoxLayout(gcp_group)
        proj_row = QHBoxLayout()
        proj_row.addWidget(QLabel("Project ID:"))
        self._gcp_project = QLineEdit()
        self._gcp_project.setPlaceholderText("my-project-123 (leave blank to skip GCP)")
        proj_row.addWidget(self._gcp_project)
        gcp_layout.addLayout(proj_row)
        creds_row = QHBoxLayout()
        creds_row.addWidget(QLabel("Creds JSON:"))
        self._gcp_creds = QLineEdit()
        self._gcp_creds.setPlaceholderText("path/to/service-account.json (optional)")
        creds_row.addWidget(self._gcp_creds)
        browse_btn = QPushButton("Browse…")
        browse_btn.clicked.connect(self._browse_creds)
        creds_row.addWidget(browse_btn)
        gcp_layout.addLayout(creds_row)
        layout.addWidget(gcp_group)

        # Start button
        self._start_btn = QPushButton("▶ Start Audit")
        self._start_btn.setEnabled(self._db is not None)
        layout.addWidget(self._start_btn)
        self._start_btn.clicked.connect(self._on_start_stop)

        # Status
        self._status_label = QLabel("Idle — configure credentials and click Start Audit")
        layout.addWidget(self._status_label)

        # Splitter: findings + terminal
        splitter = QSplitter(Qt.Orientation.Vertical)
        self._finding_cards = FindingCards()
        splitter.addWidget(self._finding_cards)
        self._terminal = QPlainTextEdit()
        self._terminal.setReadOnly(True)
        self._terminal.setFont(QFont("Monospace", 9))
        self._terminal.setMaximumHeight(150)
        splitter.addWidget(self._terminal)
        layout.addWidget(splitter)

        self._apply_styles()

    def _apply_styles(self):
        self.setStyleSheet(f"""
            QWidget {{ background: {BG}; color: {TEXT}; font-family: 'DM Sans'; }}
            QGroupBox {{
                border: 1px solid {BORDER}; border-radius: 6px;
                margin-top: 8px; padding: 8px;
                font-weight: bold; color: {ACCENT};
            }}
            QGroupBox::title {{ subcontrol-origin: margin; left: 8px; }}
            QLineEdit {{
                background: {SURFACE}; border: 1px solid {BORDER};
                border-radius: 4px; padding: 4px 8px; color: {TEXT};
            }}
            QPushButton {{
                background: {ACCENT}; color: white; border: none;
                border-radius: 4px; padding: 6px 16px; font-weight: bold;
            }}
            QPushButton:hover {{ background: #8B75C2; }}
            QPushButton:disabled {{ background: #C8B8E8; color: #888; }}
            QLabel {{ color: {TEXT}; }}
            QPlainTextEdit {{
                background: #1a1a2e; color: #e2eaf4;
                font-family: Monospace; border: 1px solid {BORDER};
            }}
        """)

    def _browse_creds(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Service Account JSON", "", "JSON Files (*.json)"
        )
        if path:
            self._gcp_creds.setText(path)

    def _on_start_stop(self):
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._start_btn.setText("Stopping…")
            self._start_btn.setEnabled(False)
            return

        aws_profile = self._aws_profile.text().strip()
        aws_region  = self._aws_region.text().strip()
        gcp_project = self._gcp_project.text().strip()
        gcp_creds   = self._gcp_creds.text().strip()

        if not aws_profile and not aws_region and not gcp_project:
            self._status_label.setText("Error: configure at least one provider (AWS profile/region or GCP project)")
            return

        from models import Scan
        from datetime import datetime, timezone
        scan = Scan(
            id=None, client_id=1, scan_type="cloud",
            target=f"aws={aws_profile or 'default'} gcp={gcp_project or 'none'}",
            status="running", created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._scan_id = self._db.insert_scan(scan)

        self._worker = CloudWorker(
            scan_id=self._scan_id, db=self._db,
            aws_profile=aws_profile, aws_region=aws_region or "us-east-1",
            gcp_project=gcp_project, gcp_creds_file=gcp_creds,
        )
        self._worker.finding_discovered.connect(self._on_finding)
        self._worker.tool_log.connect(self._on_log)
        self._worker.scan_complete.connect(self._on_complete)
        self._worker.error_occurred.connect(self._on_error)
        self._worker.finished.connect(self._on_worker_finished)
        self._finding_cards.reset()
        self._terminal.clear()
        self._status_label.setText("Running cloud audit…")
        self._start_btn.setText("■ Stop")
        self._worker.start()

    def _on_finding(self, finding: dict):
        self._finding_cards.add_finding(finding)

    def _on_log(self, line: str):
        self._terminal.appendPlainText(line)

    def _on_complete(self, summary: dict):
        total = summary.get("total", 0)
        self._status_label.setText(f"Complete — {total} findings")

    def _on_error(self, tool: str, msg: str):
        self._terminal.appendPlainText(f"[error] {tool}: {msg}")

    def _on_failed(self, msg: str):
        self._status_label.setText(f"Error: {msg}")
        self._scan_id = None

    def _on_worker_finished(self):
        if self._worker is not None:
            self._worker.deleteLater()
            self._worker = None
        self._start_btn.setText("▶ Start Audit")
        self._start_btn.setEnabled(True)
```

**IMPORTANT:** Before finalising, read `models.py` to check the `Scan` dataclass field order and `db.py`'s `insert_scan` signature. Adjust the `Scan(...)` call to match exactly.

- [ ] **Step 2: Verify import**

```bash
QT_QPA_PLATFORM=offscreen python -c "from screens.cloud_page import CloudPage; print('OK')"
```

- [ ] **Step 3: Commit**

```bash
git add screens/cloud_page.py
git commit -m "feat: add CloudPage UI with AWS/GCP inputs, FindingCards, and terminal"
```

---

## Task 5: Sidebar + MainWindow wiring

**Files:**
- Modify: `sidebar.py`
- Modify: `main_window.py`
- Modify: `tests/test_sidebar.py`
- Modify: `tests/test_main_window.py`

- [ ] **Step 1: Update sidebar count test (8→9)**

In `tests/test_sidebar.py`, change the nav button count assertion from 8 to 9.

- [ ] **Step 2: Update main_window count test (8→9)**

In `tests/test_main_window.py`, change `win._stack.count() == 8` to `== 9`.

- [ ] **Step 3: Run to confirm failures**

```bash
pytest tests/test_sidebar.py tests/test_main_window.py -v
```
Expected: 2 failures

- [ ] **Step 4: Apply production changes**

`sidebar.py` — append `("☁", "Cloud", 8)` to `_NAV_ITEMS`.

`main_window.py`:
```python
from screens.cloud_page import CloudPage
# in __init__, after self._osint:
self._cloud = CloudPage(db=db)
self._stack.addWidget(self._cloud)
```

- [ ] **Step 5: Run to confirm passing**

```bash
pytest tests/test_sidebar.py tests/test_main_window.py -v
```
Expected: all pass

- [ ] **Step 6: Commit**

```bash
git add sidebar.py main_window.py tests/test_sidebar.py tests/test_main_window.py
git commit -m "feat: wire CloudPage into sidebar nav and main window stack at index 8"
```

---

## Task 6: Full test suite + smoke test

**Files:** None new.

- [ ] **Step 1: Run full suite**

```bash
source venv/bin/activate && pytest tests/ -p no:randomly -q
```
Expected: **331 tests passed** (319 + 4 aws + 3 gcp + 5 cloud_worker = 331), no errors, no segfault.

- [ ] **Step 2: Smoke test CloudPage instantiation**

```bash
QT_QPA_PLATFORM=offscreen python -c "
from PyQt6.QtWidgets import QApplication
import sys
app = QApplication.instance() or QApplication(sys.argv)
from db import DB
from screens.cloud_page import CloudPage
db = DB(':memory:')
page = CloudPage(db=db)
assert page._aws_profile is not None
assert page._gcp_project is not None
assert page._start_btn.isEnabled()
print('CloudPage smoke test PASSED')
"
```

- [ ] **Step 3: Final commit**

```bash
git add -A
git commit -m "feat: Phase 6b complete — cloud audit module with AWS and GCP support"
```

Only commit files that are part of Phase 6b. Check `git status` first and exclude unrelated untracked files.

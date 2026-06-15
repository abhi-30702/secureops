# Phase 6b — Cloud Audit Module Design Spec

**Version:** 1.0  
**Date:** 2026-06-15  
**Owner:** Abhishek K — Fidelitus Corp  
**Status:** Approved — ready to plan  

---

## 1. Overview

Phase 6b adds a Cloud Audit module to SecureOps. It uses `boto3` (AWS) and `google-cloud` (GCP) to check for common misconfigurations — public buckets, overly-permissive IAM, and exposed security groups — and streams findings into the `findings` SQLite table. Results appear live on `CloudPage`.

**PRD requirements covered:** FR-26, FR-27, FR-28, FR-29, FR-30.

---

## 2. Architecture

```
aws_auditor.run(profile, region) → list[dict]   # S3, IAM, Security Groups
gcp_auditor.run(project_id, creds_file) → list[dict]  # GCS, IAM service accounts
        ↓ (both tools)
CloudWorker.run() [QThread]
        ↓ (per finding)
db.insert_finding()  →  SQLite findings table
finding_discovered.emit(dict)  →  CloudPage._on_finding() → FindingCards row
        ↓ (on finish)
scan_complete.emit(dict)  →  CloudPage._on_complete()
```

`CloudPage` has two credential input groups (AWS + GCP), a unified FindingCards stream, severity rings, and a terminal strip. Either provider can be run alone by leaving the other's fields blank.

---

## 3. Data layer

Re-uses the existing `findings` table. No new tables needed.

Each finding dict passed to `db.insert_finding()`:
```python
{
    "scan_id": int,
    "tool": "aws_auditor" | "gcp_auditor",
    "severity": "critical" | "high" | "medium" | "low" | "info",
    "title": str,          # short description, e.g. "Public S3 bucket"
    "description": str,    # detail, e.g. bucket name, resource ARN
    "host": str,           # resource identifier (bucket name, SG id, etc.)
    "port": None,
    "raw": str,            # JSON-serialised raw finding dict
}
```

Look at `db.py` for the exact `insert_finding` signature.

---

## 4. Tool wrappers

### 4.1 `workers/tools/aws_auditor.py`

```python
def run(profile: str, region: str) -> list[dict]:
    """
    Audit AWS account for common misconfigurations.
    profile: AWS profile name (from ~/.aws/credentials); "" = default
    region: AWS region, e.g. "us-east-1"; "" = "us-east-1"
    Returns list of finding dicts. Returns [] on any error — never raises.
    """
```

**Checks (3 sub-checks):**

**S3 public buckets:**
- List all buckets via `s3.list_buckets()`
- For each bucket, call `s3.get_bucket_acl(Bucket=name)`
- If any grant has `Grantee.URI` == `"http://acs.amazonaws.com/groups/global/AllUsers"` → finding severity `"critical"`, title `"Public S3 bucket"`, description includes bucket name

**IAM users with admin policy:**
- List users via `iam.list_users()`
- For each user, call `iam.list_attached_user_policies(UserName=name)`
- If `AdministratorAccess` policy is attached directly → finding severity `"high"`, title `"IAM user with direct AdministratorAccess"`, description includes username

**EC2 security groups with unrestricted ingress:**
- Call `ec2.describe_security_groups()`
- For each SG, for each ingress rule where `CidrIpv4 == "0.0.0.0/0"` or `CidrIpv6 == "::/0"` and `FromPort` in `[22, 3389, 0]` (0 = all traffic rule) → finding severity `"high"`, title `"Unrestricted inbound rule in security group"`, description includes SG id + port

**Error handling:**
- Wrap each check in its own `try/except Exception` — one check failure must not stop others
- `botocore.exceptions.NoCredentialsError` → return `[]` immediately (no credentials configured)
- All exceptions caught; return collected findings so far
- **NEVER include credential values in any finding's description or raw field**

**Session setup:**
```python
import boto3
session = boto3.Session(profile_name=profile or None, region_name=region or "us-east-1")
s3  = session.client("s3")
iam = session.client("iam")
ec2 = session.client("ec2")
```

### 4.2 `workers/tools/gcp_auditor.py`

```python
def run(project_id: str, credentials_file: str) -> list[dict]:
    """
    Audit GCP project for common misconfigurations.
    project_id: GCP project ID, e.g. "my-project-123"
    credentials_file: path to service account JSON; "" = application default credentials
    Returns list of finding dicts. Returns [] on any error — never raises.
    """
```

**Checks (2 sub-checks):**

**GCS public buckets:**
- Use `google.cloud.storage.Client` (with credentials if file provided, else default)
- `client.list_buckets(project=project_id)`
- For each bucket, `bucket.get_iam_policy()`
- If `allUsers` or `allAuthenticatedUsers` in any binding's `members` → finding severity `"critical"`, title `"Public GCS bucket"`, description includes bucket name

**GCP IAM: service accounts with owner/editor role:**
- Use `google.cloud.resourcemanager_v3.ProjectsClient` to get IAM policy for the project
- `policy.get_iam_policy(request={"resource": f"projects/{project_id}"})`
- For each binding where `role` in `["roles/owner", "roles/editor"]`, if any member starts with `"serviceAccount:"` → finding severity `"high"`, title `"Service account with owner/editor role"`, description includes member + role

**Error handling:**
- Wrap each check in its own `try/except Exception`
- `google.auth.exceptions.DefaultCredentialsError` → return `[]` immediately
- **NEVER include credential file paths or content in any finding**

**Client setup:**
```python
from google.cloud import storage
from google.oauth2 import service_account

if credentials_file:
    creds = service_account.Credentials.from_service_account_file(credentials_file)
    storage_client = storage.Client(project=project_id, credentials=creds)
else:
    storage_client = storage.Client(project=project_id)
```

---

## 5. Worker: `workers/cloud_worker.py`

```python
class CloudWorker(QThread):
    finding_discovered = pyqtSignal(dict)
    tool_progress      = pyqtSignal(str, int, str)   # tool_name, count, status
    tool_log           = pyqtSignal(str)
    scan_complete      = pyqtSignal(dict)
    error_occurred     = pyqtSignal(str, str)
```

**`__init__(scan_id, db, aws_profile, aws_region, gcp_project, gcp_creds_file, parent=None)`**

**`run()`:**
1. Check cancel (threading.Event)
2. If `aws_profile` or `aws_region` non-empty (at least one AWS field set): run `aws_auditor.run(profile, region)`, emit `tool_progress("aws_auditor", 0, "running")`, for each finding: `db.insert_finding(f)` → `finding_discovered.emit(f)`, emit `tool_progress("aws_auditor", count, "complete")`
3. Check cancel
4. If `gcp_project` non-empty: run `gcp_auditor.run(project_id, creds_file)`, same pattern
5. Build summary dict, `db.update_scan_status(scan_id, "complete")`, `scan_complete.emit(summary)`
6. On exception: `error_occurred.emit(tool_name, str(e))`, continue to next tool (isolated failures)

`stop()` sets a `threading.Event`.

---

## 6. UI: `screens/cloud_page.py`

### 6.1 Layout

```
QVBoxLayout
├── QLabel "Cloud Audit"  (header)
├── QGroupBox "AWS"
│   ├── QHBoxLayout: QLabel "Profile:" | QLineEdit _aws_profile (placeholder: "default")
│   └── QHBoxLayout: QLabel "Region:"  | QLineEdit _aws_region  (placeholder: "us-east-1")
├── QGroupBox "GCP"
│   ├── QHBoxLayout: QLabel "Project ID:" | QLineEdit _gcp_project
│   └── QHBoxLayout: QLabel "Creds JSON:" | QLineEdit _gcp_creds | QPushButton "Browse…"
├── QPushButton _start_btn  "▶ Start Audit"
├── QLabel _status_label
├── QSplitter (Vertical)
│   ├── FindingCards _finding_cards  (imported from screens/widgets/finding_cards.py)
│   └── QPlainTextEdit _terminal  (read-only, monospace)
```

### 6.2 Behaviour

- `_on_start_stop`: validates at least one provider has credentials, creates Scan in DB, creates CloudWorker, connects signals, starts worker
- `_on_finding(finding)`: calls `self._finding_cards.add_finding(finding)`
- `_on_log(line)`: appends to `_terminal`
- `_on_complete(summary)`: updates status label, resets button
- `_on_worker_finished()`: `deleteLater()`, reset `_worker = None`, re-enable button
- Stop: `worker.stop()`, button → "Stopping…"
- Browse button: `QFileDialog.getOpenFileName()` → fills `_gcp_creds`

### 6.3 Colour palette

Same Lemon Chiffon palette as Phases 4–6a (BG `#FEFACD`, accent `#5F4A8B`, text `#2A1F45`).

---

## 7. Sidebar + MainWindow wiring

- `sidebar.py`: append `("☁", "Cloud", 8)` to `_NAV_ITEMS` (9 entries total)
- `main_window.py`: `self._cloud = CloudPage(db=self._db)` at stack index 8

---

## 8. Testing

### `tests/test_aws_auditor.py` (4 tests)

| Test | What it checks |
|------|---------------|
| `test_returns_empty_on_no_credentials` | Mock `boto3.Session` to raise `NoCredentialsError` → `[]` |
| `test_finds_public_s3_bucket` | Mock S3 `list_buckets` + `get_bucket_acl` with AllUsers grant → 1 critical finding |
| `test_finds_iam_admin_user` | Mock IAM `list_users` + `list_attached_user_policies` with AdministratorAccess → 1 high finding |
| `test_finds_open_security_group` | Mock EC2 `describe_security_groups` with 0.0.0.0/0 on port 22 → 1 high finding |

### `tests/test_gcp_auditor.py` (3 tests)

| Test | What it checks |
|------|---------------|
| `test_returns_empty_on_no_credentials` | Mock `storage.Client` to raise `DefaultCredentialsError` → `[]` |
| `test_finds_public_gcs_bucket` | Mock `list_buckets` + IAM policy with `allUsers` → 1 critical finding |
| `test_finds_privileged_service_account` | Mock project IAM policy with service account in `roles/owner` → 1 high finding |

### `tests/test_cloud_worker.py` (5 tests)

| Test | What it checks |
|------|---------------|
| `test_findings_emitted_for_aws` | Mock aws_auditor.run → `finding_discovered` fires |
| `test_findings_written_to_db` | Mock both auditors → findings in `db.get_findings(scan_id)` |
| `test_gcp_skipped_when_no_project` | gcp_project="" → gcp_auditor.run not called |
| `test_aws_skipped_when_no_profile_and_no_region` | Both aws fields "" → aws_auditor.run not called |
| `test_scan_complete_fires` | Mock both → `scan_complete` signal fires |

---

## 9. File map

| Action | Path |
|--------|------|
| Create | `workers/tools/aws_auditor.py` |
| Create | `workers/tools/gcp_auditor.py` |
| Create | `workers/cloud_worker.py` |
| Create | `screens/cloud_page.py` |
| Modify | `sidebar.py` |
| Modify | `main_window.py` |
| Create | `tests/test_aws_auditor.py` |
| Create | `tests/test_gcp_auditor.py` |
| Create | `tests/test_cloud_worker.py` |

---

## 10. Constraints

- **Never log credentials** — AWS profile names may appear in logs; AWS/GCP keys, secrets, service account JSON content must never appear
- **Credential errors return []** — not finding of type "error"; tool wrappers return empty silently
- **Either provider is optional** — skip AWS stage if both `aws_profile` and `aws_region` are empty; skip GCP if `gcp_project` is empty
- **Findings re-use `findings` table** — no new schema changes needed
- **No exploitation** — read-only API calls only (list, describe, get); no modification of cloud resources

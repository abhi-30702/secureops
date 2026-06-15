import json
from google.cloud import storage, resourcemanager_v3
from google.auth.exceptions import DefaultCredentialsError

_PRIVILEGED_ROLES = {"roles/owner", "roles/editor"}
_PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


def run(project_id: str, credentials_file: str) -> list[dict]:
    """
    Audit GCP for public GCS buckets and privileged service accounts.
    Returns [] on any error — never raises. Never includes credentials in output.
    """
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

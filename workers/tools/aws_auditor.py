import json
import boto3
from botocore.exceptions import NoCredentialsError

_PUBLIC_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
_OPEN_PORTS = {0, 22, 3389}


def run(profile: str, region: str) -> list[dict]:
    """
    Audit AWS for S3 public buckets, IAM admin users, open security groups.
    Returns [] on any error — never raises. Never includes credentials in output.
    """
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
                            "raw": json.dumps({"bucket": name}),
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

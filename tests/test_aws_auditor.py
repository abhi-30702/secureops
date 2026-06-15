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

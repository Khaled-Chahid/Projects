from __future__ import annotations

from fnmatch import fnmatchcase
from typing import Any

from cloud_risk_tool.analysis.common import as_list, make_finding, public_statement, statements


ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTHENTICATED_USERS_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
PUBLIC_URIS = {ALL_USERS_URI, AUTHENTICATED_USERS_URI}
READ_OPERATIONS = {"s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket"}
WRITE_OPERATIONS = {"s3:PutObject", "s3:DeleteObject", "s3:PutBucketPolicy", "s3:PutBucketAcl"}


class S3Analyzer:
    def analyze(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        account_block = data.get("account_public_access_block") or {}
        for bucket in data.get("buckets", []):
            findings.extend(self._analyze_bucket(bucket, account_block))
        return findings

    def _analyze_bucket(self, bucket: dict[str, Any], account_block: dict[str, Any]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        bucket_block = bucket.get("public_access_block") or {}
        effective = {
            key: bool(bucket_block.get(key) or account_block.get(key))
            for key in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
        }
        acl_read, acl_write, acl_evidence = self._public_acl(bucket.get("acl") or {})
        policy_read, policy_write, policy_evidence = self._public_policy(bucket.get("policy") or {})
        status_public = bool((bucket.get("policy_status") or {}).get("IsPublic"))

        effective_public_acl_read = acl_read and not effective["IgnorePublicAcls"]
        effective_public_acl_write = acl_write and not effective["IgnorePublicAcls"]
        effective_public_policy_read = (policy_read or status_public) and not effective["RestrictPublicBuckets"]
        effective_public_policy_write = policy_write and not effective["RestrictPublicBuckets"]

        public_read = effective_public_acl_read or effective_public_policy_read
        public_write = effective_public_acl_write or effective_public_policy_write
        resource_id = bucket.get("arn") or bucket.get("name")
        region = bucket.get("region")
        tags = bucket.get("tags", {})

        if public_write:
            findings.append(
                make_finding(
                    rule_id="S3-001",
                    category="Exposed Bucket",
                    resource_type="S3Bucket",
                    resource_id=resource_id,
                    title="S3 bucket permits public write operations",
                    description="An anonymous or broadly authenticated principal can modify data or bucket configuration.",
                    evidence={
                        "bucket": bucket.get("name"),
                        "acl": acl_evidence,
                        "policy_statements": policy_evidence,
                        "effective_public_access_block": effective,
                    },
                    recommendation="Remove public write grants and enable all four S3 Block Public Access settings.",
                    impact=5,
                    likelihood=5,
                    exposure=1,
                    region=region,
                    tags=tags,
                )
            )
        elif public_read:
            findings.append(
                make_finding(
                    rule_id="S3-002",
                    category="Exposed Bucket",
                    resource_type="S3Bucket",
                    resource_id=resource_id,
                    title="S3 bucket is publicly readable",
                    description="The bucket policy or ACL grants public read access that is not neutralized by effective Block Public Access settings.",
                    evidence={
                        "bucket": bucket.get("name"),
                        "acl": acl_evidence,
                        "policy_status": bucket.get("policy_status"),
                        "policy_statements": policy_evidence,
                        "effective_public_access_block": effective,
                    },
                    recommendation="Remove public principals unless explicitly required, then enable all four Block Public Access settings.",
                    impact=4,
                    likelihood=5,
                    exposure=1,
                    region=region,
                    tags=tags,
                )
            )

        if not all(effective.values()):
            disabled = [key for key, enabled in effective.items() if not enabled]
            findings.append(
                make_finding(
                    rule_id="S3-003",
                    category="S3 Hardening",
                    resource_type="S3Bucket",
                    resource_id=resource_id,
                    title="S3 Block Public Access is incomplete",
                    description="One or more effective S3 Block Public Access controls are not enabled.",
                    evidence={"bucket": bucket.get("name"), "disabled_controls": disabled, "effective_configuration": effective},
                    recommendation="Enable BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets at account or bucket level.",
                    impact=3,
                    likelihood=3,
                    exposure=0,
                    region=region,
                    tags=tags,
                )
            )
        return findings

    @staticmethod
    def _public_acl(acl: dict[str, Any]) -> tuple[bool, bool, list[dict[str, Any]]]:
        read = False
        write = False
        evidence: list[dict[str, Any]] = []
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI")
            if uri not in PUBLIC_URIS:
                continue
            permission = str(grant.get("Permission", "")).upper()
            evidence.append({"uri": uri, "permission": permission})
            if permission in {"READ", "READ_ACP", "FULL_CONTROL"}:
                read = True
            if permission in {"WRITE", "WRITE_ACP", "FULL_CONTROL"}:
                write = True
        return read, write, evidence

    @staticmethod
    def _grants_any(policy_actions: set[str], concrete_operations: set[str]) -> bool:
        return any(
            fnmatchcase(operation.lower(), policy_action.lower())
            for policy_action in policy_actions
            for operation in concrete_operations
        )

    @staticmethod
    def _public_policy(policy: dict[str, Any]) -> tuple[bool, bool, list[dict[str, Any]]]:
        read = False
        write = False
        evidence: list[dict[str, Any]] = []
        for statement in statements(policy):
            if not public_statement(statement):
                continue
            actions = {str(action) for action in as_list(statement.get("Action"))}
            statement_read = S3Analyzer._grants_any(actions, READ_OPERATIONS)
            statement_write = S3Analyzer._grants_any(actions, WRITE_OPERATIONS)
            read = read or statement_read
            write = write or statement_write
            evidence.append(
                {
                    "sid": statement.get("Sid"),
                    "actions": sorted(actions),
                    "resources": as_list(statement.get("Resource")),
                    "read": statement_read,
                    "write": statement_write,
                }
            )
        return read, write, evidence

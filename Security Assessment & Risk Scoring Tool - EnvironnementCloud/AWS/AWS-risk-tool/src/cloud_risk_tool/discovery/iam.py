from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from cloud_risk_tool.aws import AWSClientFactory, error_record
from cloud_risk_tool.serialization import normalize_policy_document


class IAMDiscovery:
    def __init__(self, factory: AWSClientFactory) -> None:
        self.client = factory.client("iam")
        self.errors: list[dict[str, Any]] = []

    def discover(self) -> dict[str, Any]:
        try:
            result = self._discover_authorization_details()
        except Exception as exc:
            self.errors.append(error_record("iam", "GetAccountAuthorizationDetails", exc))
            result = self._discover_fallback()

        self._enrich_users(result.get("users", []))
        self._enrich_missing_managed_policies(result)
        result["errors"] = self.errors
        return result

    def _discover_authorization_details(self) -> dict[str, Any]:
        users: list[dict[str, Any]] = []
        roles: list[dict[str, Any]] = []
        groups: list[dict[str, Any]] = []
        policies: list[dict[str, Any]] = []
        paginator = self.client.get_paginator("get_account_authorization_details")
        for page in paginator.paginate():
            users.extend(self._normalize_user(item) for item in page.get("UserDetailList", []))
            roles.extend(self._normalize_role(item) for item in page.get("RoleDetailList", []))
            groups.extend(self._normalize_group(item) for item in page.get("GroupDetailList", []))
            policies.extend(self._normalize_managed_policy(item) for item in page.get("Policies", []))
        return {"users": users, "roles": roles, "groups": groups, "managed_policies": policies}

    def _discover_fallback(self) -> dict[str, Any]:
        return {
            "users": self._fallback_users(),
            "roles": self._fallback_roles(),
            "groups": self._fallback_groups(),
            "managed_policies": self._fallback_policies(),
        }

    def _fallback_users(self) -> list[dict[str, Any]]:
        users: list[dict[str, Any]] = []
        try:
            paginator = self.client.get_paginator("list_users")
            raw_users = [item for page in paginator.paginate() for item in page.get("Users", [])]
        except Exception as exc:
            self.errors.append(error_record("iam", "ListUsers", exc))
            return users
        for item in raw_users:
            name = item["UserName"]
            inline = self._inline_policies("user", name)
            attached = self._attached_policies("user", name)
            try:
                groups = self.client.list_groups_for_user(UserName=name).get("Groups", [])
            except Exception as exc:
                self.errors.append(error_record("iam", "ListGroupsForUser", exc, name))
                groups = []
            users.append(
                {
                    "user_name": name,
                    "arn": item.get("Arn"),
                    "path": item.get("Path"),
                    "create_date": item.get("CreateDate"),
                    "groups": [group.get("GroupName") for group in groups],
                    "inline_policies": inline,
                    "attached_policies": attached,
                    "permissions_boundary": item.get("PermissionsBoundary"),
                    "tags": self._tags("user", name),
                }
            )
        return users

    def _fallback_roles(self) -> list[dict[str, Any]]:
        roles: list[dict[str, Any]] = []
        try:
            paginator = self.client.get_paginator("list_roles")
            raw_roles = [item for page in paginator.paginate() for item in page.get("Roles", [])]
        except Exception as exc:
            self.errors.append(error_record("iam", "ListRoles", exc))
            return roles
        for item in raw_roles:
            name = item["RoleName"]
            roles.append(
                {
                    "role_name": name,
                    "arn": item.get("Arn"),
                    "path": item.get("Path"),
                    "create_date": item.get("CreateDate"),
                    "assume_role_policy": normalize_policy_document(item.get("AssumeRolePolicyDocument")),
                    "inline_policies": self._inline_policies("role", name),
                    "attached_policies": self._attached_policies("role", name),
                    "permissions_boundary": item.get("PermissionsBoundary"),
                    "tags": self._tags("role", name),
                }
            )
        return roles

    def _fallback_groups(self) -> list[dict[str, Any]]:
        groups: list[dict[str, Any]] = []
        try:
            paginator = self.client.get_paginator("list_groups")
            raw_groups = [item for page in paginator.paginate() for item in page.get("Groups", [])]
        except Exception as exc:
            self.errors.append(error_record("iam", "ListGroups", exc))
            return groups
        for item in raw_groups:
            name = item["GroupName"]
            groups.append(
                {
                    "group_name": name,
                    "arn": item.get("Arn"),
                    "path": item.get("Path"),
                    "create_date": item.get("CreateDate"),
                    "inline_policies": self._inline_policies("group", name),
                    "attached_policies": self._attached_policies("group", name),
                }
            )
        return groups

    def _fallback_policies(self) -> list[dict[str, Any]]:
        policies: list[dict[str, Any]] = []
        try:
            paginator = self.client.get_paginator("list_policies")
            raw = [item for page in paginator.paginate(Scope="All") for item in page.get("Policies", [])]
        except Exception as exc:
            self.errors.append(error_record("iam", "ListPolicies", exc))
            return policies
        for item in raw:
            policy = self._get_managed_policy(item.get("Arn"))
            if policy:
                policies.append(policy)
        return policies

    def _inline_policies(self, entity_type: str, name: str) -> list[dict[str, Any]]:
        list_method = getattr(self.client, f"list_{entity_type}_policies")
        get_method = getattr(self.client, f"get_{entity_type}_policy")
        name_key = f"{entity_type.title()}Name"
        try:
            names_key = "PolicyNames"
            policy_names = list_method(**{name_key: name}).get(names_key, [])
        except Exception as exc:
            self.errors.append(error_record("iam", f"List{entity_type.title()}Policies", exc, name))
            return []
        policies = []
        for policy_name in policy_names:
            try:
                response = get_method(**{name_key: name, "PolicyName": policy_name})
                policies.append(
                    {
                        "policy_name": policy_name,
                        "document": normalize_policy_document(response.get("PolicyDocument")),
                    }
                )
            except Exception as exc:
                self.errors.append(error_record("iam", f"Get{entity_type.title()}Policy", exc, name))
        return policies

    def _attached_policies(self, entity_type: str, name: str) -> list[dict[str, Any]]:
        method = getattr(self.client, f"list_attached_{entity_type}_policies")
        name_key = f"{entity_type.title()}Name"
        try:
            response = method(**{name_key: name})
            return [
                {"policy_name": item.get("PolicyName"), "policy_arn": item.get("PolicyArn")}
                for item in response.get("AttachedPolicies", [])
            ]
        except Exception as exc:
            self.errors.append(error_record("iam", f"ListAttached{entity_type.title()}Policies", exc, name))
            return []

    def _tags(self, entity_type: str, name: str) -> dict[str, str]:
        method_name = f"list_{entity_type}_tags"
        if not hasattr(self.client, method_name):
            return {}
        method = getattr(self.client, method_name)
        key = f"{entity_type.title()}Name"
        try:
            return {item["Key"]: item["Value"] for item in method(**{key: name}).get("Tags", [])}
        except Exception:
            return {}

    def _enrich_users(self, users: list[dict[str, Any]]) -> None:
        for user in users:
            name = user["user_name"]
            try:
                response = self.client.list_access_keys(UserName=name)
                user["access_keys"] = [
                    {
                        "access_key_id": item.get("AccessKeyId"),
                        "status": item.get("Status"),
                        "create_date": item.get("CreateDate"),
                    }
                    for item in response.get("AccessKeyMetadata", [])
                ]
            except Exception as exc:
                user["access_keys"] = []
                self.errors.append(error_record("iam", "ListAccessKeys", exc, name))
            try:
                response = self.client.list_mfa_devices(UserName=name)
                user["mfa_devices"] = [item.get("SerialNumber") for item in response.get("MFADevices", [])]
            except Exception as exc:
                user["mfa_devices"] = []
                self.errors.append(error_record("iam", "ListMFADevices", exc, name))
            try:
                self.client.get_login_profile(UserName=name)
                user["has_console_password"] = True
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code in {"NoSuchEntity", "NoSuchEntityException"}:
                    user["has_console_password"] = False
                else:
                    user["has_console_password"] = None
                    self.errors.append(error_record("iam", "GetLoginProfile", exc, name))
            except Exception as exc:
                user["has_console_password"] = None
                self.errors.append(error_record("iam", "GetLoginProfile", exc, name))

    def _enrich_missing_managed_policies(self, result: dict[str, Any]) -> None:
        existing = {item.get("arn") for item in result.get("managed_policies", [])}
        referenced: set[str] = set()
        for collection in ("users", "roles", "groups"):
            for entity in result.get(collection, []):
                referenced.update(
                    item.get("policy_arn")
                    for item in entity.get("attached_policies", [])
                    if item.get("policy_arn")
                )
        for arn in sorted(referenced - existing):
            policy = self._get_managed_policy(arn)
            if policy:
                result.setdefault("managed_policies", []).append(policy)

    def _get_managed_policy(self, arn: str | None) -> dict[str, Any] | None:
        if not arn:
            return None
        try:
            metadata = self.client.get_policy(PolicyArn=arn).get("Policy", {})
            version_id = metadata.get("DefaultVersionId")
            version = self.client.get_policy_version(PolicyArn=arn, VersionId=version_id).get("PolicyVersion", {})
            return {
                "policy_name": metadata.get("PolicyName"),
                "arn": arn,
                "path": metadata.get("Path"),
                "default_version_id": version_id,
                "attachment_count": metadata.get("AttachmentCount"),
                "is_attachable": metadata.get("IsAttachable"),
                "document": normalize_policy_document(version.get("Document")),
            }
        except Exception as exc:
            self.errors.append(error_record("iam", "GetPolicyVersion", exc, arn))
            return None

    @staticmethod
    def _normalize_user(item: dict[str, Any]) -> dict[str, Any]:
        return {
            "user_name": item.get("UserName"),
            "arn": item.get("Arn"),
            "path": item.get("Path"),
            "create_date": item.get("CreateDate"),
            "groups": item.get("GroupList", []),
            "inline_policies": [
                {
                    "policy_name": policy.get("PolicyName"),
                    "document": normalize_policy_document(policy.get("PolicyDocument")),
                }
                for policy in item.get("UserPolicyList", [])
            ],
            "attached_policies": [
                {"policy_name": policy.get("PolicyName"), "policy_arn": policy.get("PolicyArn")}
                for policy in item.get("AttachedManagedPolicies", [])
            ],
            "permissions_boundary": item.get("PermissionsBoundary"),
            "tags": {tag["Key"]: tag["Value"] for tag in item.get("Tags", [])},
        }

    @staticmethod
    def _normalize_role(item: dict[str, Any]) -> dict[str, Any]:
        return {
            "role_name": item.get("RoleName"),
            "arn": item.get("Arn"),
            "path": item.get("Path"),
            "create_date": item.get("CreateDate"),
            "assume_role_policy": normalize_policy_document(item.get("AssumeRolePolicyDocument")),
            "inline_policies": [
                {
                    "policy_name": policy.get("PolicyName"),
                    "document": normalize_policy_document(policy.get("PolicyDocument")),
                }
                for policy in item.get("RolePolicyList", [])
            ],
            "attached_policies": [
                {"policy_name": policy.get("PolicyName"), "policy_arn": policy.get("PolicyArn")}
                for policy in item.get("AttachedManagedPolicies", [])
            ],
            "permissions_boundary": item.get("PermissionsBoundary"),
            "tags": {tag["Key"]: tag["Value"] for tag in item.get("Tags", [])},
        }

    @staticmethod
    def _normalize_group(item: dict[str, Any]) -> dict[str, Any]:
        return {
            "group_name": item.get("GroupName"),
            "arn": item.get("Arn"),
            "path": item.get("Path"),
            "create_date": item.get("CreateDate"),
            "inline_policies": [
                {
                    "policy_name": policy.get("PolicyName"),
                    "document": normalize_policy_document(policy.get("PolicyDocument")),
                }
                for policy in item.get("GroupPolicyList", [])
            ],
            "attached_policies": [
                {"policy_name": policy.get("PolicyName"), "policy_arn": policy.get("PolicyArn")}
                for policy in item.get("AttachedManagedPolicies", [])
            ],
        }

    @staticmethod
    def _normalize_managed_policy(item: dict[str, Any]) -> dict[str, Any]:
        versions = item.get("PolicyVersionList", [])
        default = next((version for version in versions if version.get("IsDefaultVersion")), versions[0] if versions else {})
        return {
            "policy_name": item.get("PolicyName"),
            "arn": item.get("Arn"),
            "path": item.get("Path"),
            "default_version_id": default.get("VersionId"),
            "attachment_count": item.get("AttachmentCount"),
            "is_attachable": item.get("IsAttachable"),
            "document": normalize_policy_document(default.get("Document")),
        }

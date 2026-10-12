from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from cloud_risk_tool.analysis.common import (
    any_action_matches,
    as_list,
    contains_wildcard_action,
    contains_wildcard_resource,
    make_finding,
    principal_is_public,
    statements,
)


DANGEROUS_ACTIONS = {
    "iam:PassRole",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:UpdateAssumeRolePolicy",
    "iam:CreateAccessKey",
    "sts:AssumeRole",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
}


class IAMAnalyzer:
    def __init__(self, *, access_key_max_age_days: int = 90) -> None:
        self.access_key_max_age_days = access_key_max_age_days

    def analyze(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        policy_map = {
            policy.get("arn"): policy
            for policy in data.get("managed_policies", [])
            if policy.get("arn")
        }
        group_map = {group.get("group_name"): group for group in data.get("groups", [])}

        for user in data.get("users", []):
            policies = self._entity_policies(user, policy_map)
            for group_name in user.get("groups", []):
                group = group_map.get(group_name)
                if group:
                    policies.extend(self._entity_policies(group, policy_map, source_prefix=f"group:{group_name}"))
            findings.extend(
                self._permission_findings(
                    "IAMUser",
                    user.get("arn") or user.get("user_name"),
                    user.get("user_name"),
                    user.get("tags", {}),
                    policies,
                )
            )
            findings.extend(self._user_hygiene_findings(user))

        for role in data.get("roles", []):
            policies = self._entity_policies(role, policy_map)
            findings.extend(
                self._permission_findings(
                    "IAMRole",
                    role.get("arn") or role.get("role_name"),
                    role.get("role_name"),
                    role.get("tags", {}),
                    policies,
                )
            )
            trust = role.get("assume_role_policy") or {}
            for statement in statements(trust):
                if (
                    str(statement.get("Effect", "")).lower() == "allow"
                    and principal_is_public(statement.get("Principal"))
                    and not statement.get("Condition")
                ):
                    findings.append(
                        make_finding(
                            rule_id="IAM-004",
                            category="IAM Misconfiguration",
                            resource_type="IAMRole",
                            resource_id=role.get("arn") or role.get("role_name"),
                            title="Role trust policy allows an unrestricted principal",
                            description="The role can be assumed by a wildcard principal without a restricting condition.",
                            evidence={"role_name": role.get("role_name"), "statement": statement},
                            recommendation="Restrict Principal to trusted account or service ARNs and add appropriate conditions.",
                            impact=5,
                            likelihood=4,
                            exposure=1,
                            tags=role.get("tags", {}),
                        )
                    )
                    break
        return self._deduplicate(findings)

    def _permission_findings(
        self,
        resource_type: str,
        resource_id: str,
        display_name: str,
        tags: dict[str, str],
        policies: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for policy in policies:
            arn = policy.get("policy_arn")
            if arn and arn.endswith("/AdministratorAccess"):
                findings.append(
                    make_finding(
                        rule_id="IAM-002",
                        category="IAM Misconfiguration",
                        resource_type=resource_type,
                        resource_id=resource_id,
                        title="AdministratorAccess policy is attached",
                        description=f"{display_name} has the AWS AdministratorAccess managed policy attached.",
                        evidence={"policy_name": policy.get("policy_name"), "policy_arn": arn, "source": policy.get("source")},
                        recommendation="Replace AdministratorAccess with a least-privilege policy limited to required actions and resources.",
                        impact=5,
                        likelihood=5,
                        exposure=1,
                        tags=tags,
                    )
                )
                continue

            for statement in statements(policy.get("document")):
                if str(statement.get("Effect", "")).lower() != "allow":
                    continue
                actions = [str(item) for item in as_list(statement.get("Action"))]
                resources = [str(item) for item in as_list(statement.get("Resource"))]
                if contains_wildcard_action(actions) and contains_wildcard_resource(resources):
                    findings.append(
                        make_finding(
                            rule_id="IAM-001",
                            category="IAM Misconfiguration",
                            resource_type=resource_type,
                            resource_id=resource_id,
                            title="Unrestricted wildcard permissions",
                            description=f"{display_name} is allowed to perform all actions against all resources.",
                            evidence={
                                "policy_name": policy.get("policy_name"),
                                "source": policy.get("source"),
                                "statement": statement,
                            },
                            recommendation="Replace Action and Resource wildcards with the minimum required permissions.",
                            impact=5,
                            likelihood=5,
                            exposure=1,
                            tags=tags,
                        )
                    )
                    continue
                matched = sorted(
                    action
                    for action in DANGEROUS_ACTIONS
                    if any_action_matches(actions, [action])
                )
                if matched and contains_wildcard_resource(resources):
                    findings.append(
                        make_finding(
                            rule_id="IAM-003",
                            category="IAM Misconfiguration",
                            resource_type=resource_type,
                            resource_id=resource_id,
                            title="Privilege-escalation-capable actions use wildcard resources",
                            description=f"{display_name} can perform sensitive IAM or execution actions without resource restriction.",
                            evidence={
                                "policy_name": policy.get("policy_name"),
                                "source": policy.get("source"),
                                "matched_actions": matched,
                                "statement": statement,
                            },
                            recommendation="Limit sensitive actions to explicit resource ARNs and add restrictive conditions.",
                            impact=5,
                            likelihood=4,
                            exposure=0,
                            tags=tags,
                        )
                    )
        return findings

    def _user_hygiene_findings(self, user: dict[str, Any]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        resource_id = user.get("arn") or user.get("user_name")
        if user.get("has_console_password") is True and not user.get("mfa_devices"):
            findings.append(
                make_finding(
                    rule_id="IAM-005",
                    category="IAM Misconfiguration",
                    resource_type="IAMUser",
                    resource_id=resource_id,
                    title="Console user does not have MFA",
                    description="The IAM user has a console password but no registered MFA device.",
                    evidence={"user_name": user.get("user_name"), "mfa_devices": []},
                    recommendation="Require MFA for interactive IAM users or migrate workforce access to IAM Identity Center.",
                    impact=4,
                    likelihood=4,
                    exposure=0,
                    tags=user.get("tags", {}),
                )
            )

        now = datetime.now(timezone.utc)
        for key in user.get("access_keys", []):
            created = key.get("create_date")
            if key.get("status") != "Active" or not created:
                continue
            if isinstance(created, str):
                try:
                    created = datetime.fromisoformat(created.replace("Z", "+00:00"))
                except ValueError:
                    continue
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age = (now - created).days
            if age > self.access_key_max_age_days:
                findings.append(
                    make_finding(
                        rule_id="IAM-006",
                        category="IAM Misconfiguration",
                        resource_type="IAMAccessKey",
                        resource_id=key.get("access_key_id") or resource_id,
                        title="Active access key exceeds the configured age threshold",
                        description="Long-lived access keys increase the impact of unnoticed credential exposure.",
                        evidence={
                            "user_name": user.get("user_name"),
                            "access_key_id": key.get("access_key_id"),
                            "age_days": age,
                            "threshold_days": self.access_key_max_age_days,
                        },
                        recommendation="Rotate or remove the key and prefer temporary credentials through IAM roles.",
                        impact=4,
                        likelihood=3,
                        exposure=0,
                        tags=user.get("tags", {}),
                    )
                )
        return findings

    @staticmethod
    def _entity_policies(
        entity: dict[str, Any],
        policy_map: dict[str, dict[str, Any]],
        *,
        source_prefix: str = "identity",
    ) -> list[dict[str, Any]]:
        result = [
            {
                "policy_name": policy.get("policy_name"),
                "document": policy.get("document", {}),
                "source": f"{source_prefix}:inline",
            }
            for policy in entity.get("inline_policies", [])
        ]
        for attachment in entity.get("attached_policies", []):
            arn = attachment.get("policy_arn")
            managed = policy_map.get(arn, {})
            result.append(
                {
                    "policy_name": attachment.get("policy_name"),
                    "policy_arn": arn,
                    "document": managed.get("document", {}),
                    "source": f"{source_prefix}:managed",
                }
            )
        return result

    @staticmethod
    def _deduplicate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: set[tuple[str, str]] = set()
        result = []
        for finding in findings:
            key = (finding["rule_id"], finding["resource_id"])
            if key not in seen:
                seen.add(key)
                result.append(finding)
        return result

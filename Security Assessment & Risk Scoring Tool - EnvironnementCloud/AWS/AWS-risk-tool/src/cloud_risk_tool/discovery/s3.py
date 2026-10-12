from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from cloud_risk_tool.aws import AWSClientFactory, error_record
from cloud_risk_tool.serialization import normalize_policy_document


class S3Discovery:
    def __init__(self, factory: AWSClientFactory, account_id: str | None) -> None:
        self.factory = factory
        self.client = factory.client("s3")
        self.account_id = account_id
        self.errors: list[dict[str, Any]] = []

    def discover(self) -> dict[str, Any]:
        buckets: list[dict[str, Any]] = []
        try:
            response = self.client.list_buckets()
        except Exception as exc:
            self.errors.append(error_record("s3", "ListBuckets", exc))
            return {"account_public_access_block": None, "buckets": [], "errors": self.errors}

        account_block = self._account_public_access_block()
        for item in response.get("Buckets", []):
            name = item.get("Name")
            if not name:
                continue
            buckets.append(self._discover_bucket(name, item.get("CreationDate")))
        return {
            "account_public_access_block": account_block,
            "buckets": buckets,
            "errors": self.errors,
        }

    def _discover_bucket(self, name: str, creation_date: Any) -> dict[str, Any]:
        region = self._bucket_region(name)
        regional_client = self.factory.client("s3", region_name=region)
        return {
            "name": name,
            "arn": f"arn:aws:s3:::{name}",
            "creation_date": creation_date,
            "region": region,
            "public_access_block": self._optional_call(
                regional_client,
                "get_public_access_block",
                "GetPublicAccessBlock",
                name,
                response_key="PublicAccessBlockConfiguration",
                default=None,
                Bucket=name,
                absent_codes={"NoSuchPublicAccessBlockConfiguration", "NoSuchPublicAccessBlock"},
            ),
            "policy_status": self._optional_call(
                regional_client,
                "get_bucket_policy_status",
                "GetBucketPolicyStatus",
                name,
                response_key="PolicyStatus",
                default=None,
                Bucket=name,
                absent_codes={"NoSuchBucketPolicy"},
            ),
            "policy": self._bucket_policy(regional_client, name),
            "acl": self._optional_call(
                regional_client,
                "get_bucket_acl",
                "GetBucketAcl",
                name,
                default={"Grants": []},
                Bucket=name,
            ),
            "tags": self._bucket_tags(regional_client, name),
        }

    def _bucket_region(self, name: str) -> str:
        try:
            response = self.client.get_bucket_location(Bucket=name)
            location = response.get("LocationConstraint")
            if location in {None, ""}:
                return "us-east-1"
            if location == "EU":
                return "eu-west-1"
            return str(location)
        except Exception as exc:
            self.errors.append(error_record("s3", "GetBucketLocation", exc, name))
            return self.factory.settings.region

    def _bucket_policy(self, client: Any, name: str) -> dict[str, Any] | None:
        try:
            response = client.get_bucket_policy(Bucket=name)
            raw = response.get("Policy")
            if isinstance(raw, str):
                try:
                    return json.loads(raw)
                except json.JSONDecodeError:
                    return normalize_policy_document(raw)
            return normalize_policy_document(raw)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in {"NoSuchBucketPolicy", "NoSuchPolicy"}:
                return None
            self.errors.append(error_record("s3", "GetBucketPolicy", exc, name))
            return None
        except Exception as exc:
            self.errors.append(error_record("s3", "GetBucketPolicy", exc, name))
            return None

    def _bucket_tags(self, client: Any, name: str) -> dict[str, str]:
        try:
            response = client.get_bucket_tagging(Bucket=name)
            return {item["Key"]: item["Value"] for item in response.get("TagSet", [])}
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in {"NoSuchTagSet", "NoSuchTagSetError"}:
                return {}
            self.errors.append(error_record("s3", "GetBucketTagging", exc, name))
            return {}
        except Exception as exc:
            self.errors.append(error_record("s3", "GetBucketTagging", exc, name))
            return {}

    def _account_public_access_block(self) -> dict[str, Any] | None:
        if not self.account_id:
            return None
        try:
            client = self.factory.client("s3control")
            response = client.get_public_access_block(AccountId=self.account_id)
            return response.get("PublicAccessBlockConfiguration")
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in {"NoSuchPublicAccessBlockConfiguration", "NoSuchPublicAccessBlock"}:
                return None
            self.errors.append(error_record("s3control", "GetPublicAccessBlock", exc, self.account_id))
            return None
        except Exception as exc:
            self.errors.append(error_record("s3control", "GetPublicAccessBlock", exc, self.account_id))
            return None

    def _optional_call(
        self,
        client: Any,
        method_name: str,
        operation_name: str,
        resource: str,
        *,
        response_key: str | None = None,
        default: Any = None,
        absent_codes: set[str] | None = None,
        **kwargs: Any,
    ) -> Any:
        try:
            response = getattr(client, method_name)(**kwargs)
            return response.get(response_key) if response_key else response
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in (absent_codes or set()):
                return default
            self.errors.append(error_record("s3", operation_name, exc, resource))
            return default
        except Exception as exc:
            self.errors.append(error_record("s3", operation_name, exc, resource))
            return default

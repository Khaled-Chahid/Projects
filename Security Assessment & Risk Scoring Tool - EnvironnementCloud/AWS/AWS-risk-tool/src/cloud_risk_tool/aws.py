from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from cloud_risk_tool.config import Settings


@dataclass(slots=True)
class AWSClientFactory:
    settings: Settings
    session: Any = field(init=False, repr=False)
    botocore_config: Config = field(init=False, repr=False)

    def __post_init__(self) -> None:
        session_kwargs: dict[str, Any] = {"region_name": self.settings.region}
        if self.settings.target == "localstack":
            session_kwargs.update(
                aws_access_key_id="test",
                aws_secret_access_key="test",
                aws_session_token="test",
            )
        elif self.settings.profile:
            session_kwargs["profile_name"] = self.settings.profile
        self.session = boto3.Session(**session_kwargs)
        self.botocore_config = Config(
            retries={"max_attempts": 5, "mode": "standard"},
            connect_timeout=self.settings.connect_timeout_seconds,
            read_timeout=self.settings.read_timeout_seconds,
            user_agent_extra="cloud-risk-tool/0.1.0",
        )

    def client(self, service_name: str, *, region_name: str | None = None):
        kwargs: dict[str, Any] = {
            "service_name": service_name,
            "region_name": region_name or self.settings.region,
            "config": self.botocore_config,
        }
        if self.settings.endpoint_url:
            kwargs["endpoint_url"] = self.settings.endpoint_url
        return self.session.client(**kwargs)

    def identity(self) -> dict[str, Any]:
        return self.client("sts").get_caller_identity()


def error_record(component: str, operation: str, error: Exception, resource: str | None = None) -> dict[str, Any]:
    code = type(error).__name__
    message = str(error)
    if isinstance(error, ClientError):
        details = error.response.get("Error", {})
        code = details.get("Code", code)
        message = details.get("Message", message)
    elif isinstance(error, BotoCoreError):
        message = str(error)
    record: dict[str, Any] = {
        "component": component,
        "operation": operation,
        "code": code,
        "message": message,
    }
    if resource:
        record["resource"] = resource
    return record

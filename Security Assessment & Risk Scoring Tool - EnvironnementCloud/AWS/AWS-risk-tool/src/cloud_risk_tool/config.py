from __future__ import annotations

import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _split_regions(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(dict.fromkeys(part.strip() for part in value.split(",") if part.strip()))


@dataclass(frozen=True, slots=True)
class Settings:
    target: str = "localstack"
    region: str = "us-east-1"
    regions: tuple[str, ...] = ()
    all_regions: bool = False
    endpoint_url: str | None = "http://localhost:4566"
    profile: str | None = None
    output_dir: Path = Path("output")
    access_key_max_age_days: int = 90
    connect_timeout_seconds: int = 5
    read_timeout_seconds: int = 30

    @classmethod
    def from_env(cls) -> "Settings":
        target = os.getenv("CLOUD_RISK_TARGET", "localstack").strip().lower()
        endpoint = os.getenv("LOCALSTACK_ENDPOINT", "http://localhost:4566")
        if target == "aws":
            endpoint = None
        return cls(
            target=target,
            region=os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
            regions=_split_regions(os.getenv("CLOUD_RISK_REGIONS")),
            all_regions=_env_bool("CLOUD_RISK_ALL_REGIONS", False),
            endpoint_url=endpoint,
            profile=os.getenv("AWS_PROFILE") or None,
            output_dir=Path(os.getenv("CLOUD_RISK_OUTPUT_DIR", "output")),
            access_key_max_age_days=int(os.getenv("CLOUD_RISK_ACCESS_KEY_MAX_AGE_DAYS", "90")),
        )

    def with_overrides(
        self,
        *,
        target: str | None = None,
        region: str | None = None,
        regions: Iterable[str] | None = None,
        all_regions: bool | None = None,
        endpoint_url: str | None = None,
        profile: str | None = None,
        output_dir: str | Path | None = None,
        access_key_max_age_days: int | None = None,
    ) -> "Settings":
        next_target = (target or self.target).lower()
        next_endpoint = self.endpoint_url
        if target is not None:
            next_endpoint = "http://localhost:4566" if next_target == "localstack" else None
        if endpoint_url is not None:
            next_endpoint = endpoint_url
        return replace(
            self,
            target=next_target,
            region=region or self.region,
            regions=tuple(regions) if regions is not None else self.regions,
            all_regions=self.all_regions if all_regions is None else all_regions,
            endpoint_url=next_endpoint,
            profile=self.profile if profile is None else profile,
            output_dir=Path(output_dir) if output_dir is not None else self.output_dir,
            access_key_max_age_days=(
                self.access_key_max_age_days
                if access_key_max_age_days is None
                else access_key_max_age_days
            ),
        )

    def validate(self) -> None:
        if self.target not in {"localstack", "aws"}:
            raise ValueError("target must be 'localstack' or 'aws'")
        if self.target == "localstack" and not self.endpoint_url:
            raise ValueError("LocalStack target requires an endpoint URL")
        if self.access_key_max_age_days < 1:
            raise ValueError("access key age threshold must be at least one day")

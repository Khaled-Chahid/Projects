from __future__ import annotations

import base64
import hashlib
import hmac
import time
from datetime import datetime, timezone
from email.utils import format_datetime
from typing import Any

import requests
import urllib3

from azure_risk_tool.config import Settings

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class AzureApiError(RuntimeError):
    def __init__(self, method: str, url: str, status: int, body: str) -> None:
        super().__init__(f"{method} {url} returned HTTP {status}: {body[:800]}")
        self.status = status
        self.body = body


class AzureApi:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json", "Host": "topaz.local.dev:8899"})
        self._token = self._create_token()

    def _create_token(self) -> str:
        try:
            from topaz_sdk import AzureLocalCredential, GLOBAL_ADMIN_ID
        except ImportError as exc:
            raise RuntimeError("The topaz-sdk package is required. Run: pip install -e .") from exc
        credential = AzureLocalCredential(GLOBAL_ADMIN_ID)
        return credential.get_token(self.settings.credential_scope).token

    def close(self) -> None:
        self.session.close()

    def health(self) -> dict[str, Any]:
        response = self.session.get(
            f"{self.settings.endpoint}/health",
            timeout=self.settings.timeout,
            verify=self.settings.verify_tls,
        )
        if response.status_code != 200:
            raise AzureApiError("GET", response.url, response.status_code, response.text)
        return response.json()

    def wait_until_ready(self, attempts: int = 60, delay: float = 2.0) -> dict[str, Any]:
        last_error: Exception | None = None
        for _ in range(attempts):
            try:
                return self.health()
            except Exception as exc:
                last_error = exc
                time.sleep(delay)
        raise RuntimeError(f"Topaz did not become ready: {last_error}")

    def request(
        self,
        method: str,
        path: str,
        *,
        api_version: str | None = None,
        params: dict[str, Any] | None = None,
        body: Any = None,
        expected: tuple[int, ...] = (200, 201, 202, 204),
    ) -> Any:
        query = dict(params or {})
        if api_version:
            query["api-version"] = api_version
        url = path if path.startswith("http") else f"{self.settings.endpoint}{path}"
        headers = {"Authorization": f"Bearer {self._token}"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        response = self.session.request(
            method,
            url,
            params=query,
            json=body,
            headers=headers,
            timeout=self.settings.timeout,
            verify=self.settings.verify_tls,
        )
        if response.status_code not in expected:
            raise AzureApiError(method, response.url, response.status_code, response.text)
        if not response.content:
            return None
        content_type = response.headers.get("Content-Type", "")
        if "json" in content_type.lower() or response.text.lstrip().startswith(("{", "[")):
            return response.json()
        return response.text

    def list_all(
        self,
        path: str,
        *,
        api_version: str | None = None,
        params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        values: list[dict[str, Any]] = []
        next_url: str | None = path
        next_api = api_version
        next_params = params
        while next_url:
            payload = self.request("GET", next_url, api_version=next_api, params=next_params)
            if isinstance(payload, list):
                values.extend(item for item in payload if isinstance(item, dict))
                break
            if not isinstance(payload, dict):
                break
            batch = payload.get("value", [])
            if isinstance(batch, list):
                values.extend(item for item in batch if isinstance(item, dict))
            next_url = payload.get("nextLink") or payload.get("@odata.nextLink")
            next_api = None
            next_params = None
        return values

    def storage_request(
        self,
        account_name: str,
        account_key: str,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        data: bytes = b"",
        expected: tuple[int, ...] = (200, 201, 202, 204),
    ) -> requests.Response:
        request_headers = {
            "x-ms-date": format_datetime(datetime.now(timezone.utc), usegmt=True),
            "x-ms-version": "2023-11-03",
            "Host": f"{account_name}.blob.storage.topaz.local.dev:8891",
        }
        request_headers.update(headers or {})
        if data:
            request_headers["Content-Length"] = str(len(data))
        authorization = self._shared_key(
            account_name,
            account_key,
            method,
            path,
            params or {},
            request_headers,
            len(data),
        )
        request_headers["Authorization"] = authorization
        response = self.session.request(
            method,
            f"{self.settings.storage_endpoint}{path}",
            params=params,
            headers=request_headers,
            data=data,
            timeout=self.settings.timeout,
            verify=False,
        )
        if response.status_code not in expected:
            raise AzureApiError(method, response.url, response.status_code, response.text)
        return response

    def _shared_key(
        self,
        account_name: str,
        account_key: str,
        method: str,
        path: str,
        params: dict[str, str],
        headers: dict[str, str],
        content_length: int,
    ) -> str:
        normalized_headers: dict[str, str] = {}
        for key, value in headers.items():
            lower = key.lower()
            if lower.startswith("x-ms-"):
                normalized_headers[lower] = " ".join(str(value).split())
        canonical_headers = "".join(
            f"{key}:{normalized_headers[key]}\n" for key in sorted(normalized_headers)
        )
        canonical_resource = f"/{account_name}{path}"
        for key in sorted(params, key=str.lower):
            canonical_resource += f"\n{key.lower()}:{params[key]}"
        content_encoding = headers.get("Content-Encoding", "")
        content_language = headers.get("Content-Language", "")
        content_md5 = headers.get("Content-MD5", "")
        content_type = headers.get("Content-Type", "")
        date_header = ""
        if_modified_since = headers.get("If-Modified-Since", "")
        if_match = headers.get("If-Match", "")
        if_none_match = headers.get("If-None-Match", "")
        if_unmodified_since = headers.get("If-Unmodified-Since", "")
        range_header = headers.get("Range", "")
        length_value = str(content_length) if content_length else ""
        string_to_sign = "\n".join(
            [
                method.upper(),
                content_encoding,
                content_language,
                length_value,
                content_md5,
                content_type,
                date_header,
                if_modified_since,
                if_match,
                if_none_match,
                if_unmodified_since,
                range_header,
                f"{canonical_headers}{canonical_resource}",
            ]
        )
        decoded_key = base64.b64decode(account_key)
        signature = base64.b64encode(
            hmac.new(decoded_key, string_to_sign.encode("utf-8"), hashlib.sha256).digest()
        ).decode("ascii")
        return f"SharedKey {account_name}:{signature}"

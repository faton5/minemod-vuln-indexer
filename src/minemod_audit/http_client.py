import hashlib
import json
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential


class RateLimitError(RuntimeError):
    def __init__(self, retry_after: float | None = None) -> None:
        super().__init__("HTTP rate limit reached")
        self.retry_after = retry_after


def parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    if value.isdigit():
        return float(value)
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return max(0.0, (parsed - datetime.now(UTC)).total_seconds())


def _header_value(headers: Mapping[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def rate_limit_delay_from_headers(headers: Mapping[str, str]) -> float | None:
    retry_after = parse_retry_after(_header_value(headers, "Retry-After"))
    if retry_after is not None:
        return retry_after
    reset_at = _header_value(headers, "X-RateLimit-Reset")
    if not reset_at:
        return None
    try:
        return max(0.0, float(reset_at) - time.time())
    except ValueError:
        return None


def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    secret_names = {"authorization", "x-api-key", "api-key"}
    return {
        key: "<redacted>" if key.lower() in secret_names else value
        for key, value in headers.items()
    }


class HttpClient:
    def __init__(
        self,
        *,
        base_url: str,
        headers: Mapping[str, str] | None = None,
        cache_directory: Path | None = None,
        timeout_seconds: float = 30.0,
        offline: bool = False,
        refresh: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.headers = dict(headers or {})
        self.cache_directory = cache_directory
        self.offline = offline
        self.refresh = refresh
        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=timeout_seconds,
            headers=self.headers,
        )

    def close(self) -> None:
        self._client.close()

    def _cache_path(self, method: str, path: str, params: Mapping[str, Any] | None) -> Path | None:
        if self.cache_directory is None:
            return None
        key_payload = json.dumps(
            {"method": method, "path": path, "params": params or {}},
            sort_keys=True,
        )
        digest = hashlib.sha256(key_payload.encode("utf-8")).hexdigest()
        return self.cache_directory / f"{digest}.json"

    @retry(
        retry=retry_if_exception_type((httpx.TransportError, RateLimitError)),
        wait=wait_exponential(multiplier=1, min=1, max=30),
        stop=stop_after_attempt(4),
        reraise=True,
    )
    def get_json(self, path: str, *, params: Mapping[str, Any] | None = None) -> Any:
        cache_path = self._cache_path("GET", path, params)
        if cache_path is not None and cache_path.exists() and not self.refresh:
            return json.loads(cache_path.read_text(encoding="utf-8"))
        if self.offline:
            raise FileNotFoundError(f"No cached response for GET {path}")

        response = self._client.get(path, params=params)
        if response.status_code == 429:
            retry_after = rate_limit_delay_from_headers(response.headers)
            if retry_after:
                time.sleep(retry_after)
            raise RateLimitError(retry_after)
        if response.status_code == 403 and response.headers.get("X-RateLimit-Remaining") == "0":
            retry_after = rate_limit_delay_from_headers(response.headers)
            if retry_after:
                time.sleep(retry_after)
            raise RateLimitError(retry_after)
        if response.status_code in {500, 502, 503, 504}:
            retry_after = rate_limit_delay_from_headers(response.headers)
            if retry_after:
                time.sleep(retry_after)
            raise RateLimitError(retry_after)
        response.raise_for_status()
        payload = response.json()
        if cache_path is not None:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        return payload

    def post_json(self, path: str, *, json_body: Mapping[str, Any]) -> Any:
        if self.offline:
            raise FileNotFoundError(f"No cached response for POST {path}")
        response = self._client.post(path, json=json_body)
        if response.status_code == 429:
            retry_after = rate_limit_delay_from_headers(response.headers)
            if retry_after:
                time.sleep(retry_after)
            raise RateLimitError(retry_after)
        response.raise_for_status()
        return response.json()

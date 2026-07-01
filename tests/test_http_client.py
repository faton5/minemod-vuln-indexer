from pytest import MonkeyPatch

from minemod_audit.http_client import (
    parse_retry_after,
    rate_limit_delay_from_headers,
    redact_headers,
)


def test_parse_retry_after_delta_seconds() -> None:
    assert parse_retry_after("12") == 12.0


def test_redact_secret_headers() -> None:
    redacted = redact_headers(
        {"x-api-key": "secret", "Authorization": "Bearer abc", "Accept": "json"}
    )

    assert redacted["x-api-key"] == "<redacted>"
    assert redacted["Authorization"] == "<redacted>"
    assert redacted["Accept"] == "json"


def test_rate_limit_delay_uses_x_rate_limit_reset(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr("minemod_audit.http_client.time.time", lambda: 100.0)

    delay = rate_limit_delay_from_headers({"X-RateLimit-Reset": "105"})

    assert delay == 5.0


def test_rate_limit_delay_prefers_retry_after(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr("minemod_audit.http_client.time.time", lambda: 100.0)

    delay = rate_limit_delay_from_headers(
        {
            "Retry-After": "2",
            "X-RateLimit-Reset": "105",
        }
    )

    assert delay == 2.0

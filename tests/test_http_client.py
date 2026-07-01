from minemod_audit.http_client import parse_retry_after, redact_headers


def test_parse_retry_after_delta_seconds() -> None:
    assert parse_retry_after("12") == 12.0


def test_redact_secret_headers() -> None:
    redacted = redact_headers(
        {"x-api-key": "secret", "Authorization": "Bearer abc", "Accept": "json"}
    )

    assert redacted["x-api-key"] == "<redacted>"
    assert redacted["Authorization"] == "<redacted>"
    assert redacted["Accept"] == "json"

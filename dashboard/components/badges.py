from html import escape


def status_badge(value: str | None) -> str:
    status = (value or "unknown").lower()
    palette = {
        "confirmed": "#d64545",
        "candidate": "#c58a2b",
        "likely": "#b96ad9",
        "unclear": "#6b7280",
        "fixed": "#2f9e66",
    }
    color = palette.get(status, "#6b7280")
    return (
        f"<span style='display:inline-block;padding:0.15rem 0.5rem;"
        f"border-radius:999px;background:{color};color:white;font-size:0.78rem'>"
        f"{escape(status)}</span>"
    )


def severity_badge(value: str | None) -> str:
    return status_badge(value or "unknown")

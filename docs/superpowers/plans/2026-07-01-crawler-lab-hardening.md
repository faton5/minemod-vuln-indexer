# Crawler And Local Lab Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the crawler reliable with authenticated GitHub rate limits and prepare a defensive local validation lab structure.

**Architecture:** Keep the crawler passive and data-oriented. Fix rate-limit behavior in the shared HTTP client, make SQLite replacement resilient to duplicate generated keys, and add a documented local lab area for owner-authorized validation workflows only.

**Tech Stack:** Python, Typer, SQLAlchemy, Pydantic, pytest, Streamlit.

---

### Task 1: HTTP Rate-Limit Delay

**Files:**
- Modify: `src/minemod_audit/http_client.py`
- Test: `tests/test_http_client.py`

- [ ] Write a failing test proving `X-RateLimit-Reset` is converted to a wait delay.
- [ ] Implement a small helper that prefers `Retry-After`, then falls back to `X-RateLimit-Reset`.
- [ ] Use the helper for 429, exhausted 403, and transient 5xx responses.
- [ ] Run `uv run --extra dev python -m pytest tests/test_http_client.py`.

### Task 2: Duplicate Record Keys

**Files:**
- Modify: `src/minemod_audit/database.py`
- Test: `tests/test_database.py`

- [ ] Write a failing test where two models generate the same `(kind, key)` in `replace_models`.
- [ ] Deduplicate payloads before insert, with later items replacing earlier items.
- [ ] Apply the same behavior to `append_models`.
- [ ] Run `uv run --extra dev python -m pytest tests/test_database.py`.

### Task 3: Defensive Lab Structure

**Files:**
- Create: `docs/SAFETY_SCOPE.md`
- Create: `docs/LOCAL_LAB.md`
- Create: `docs/ROADMAP.md`
- Create: `examples/lab/README.md`
- Create: `src/minemod_audit/lab/__init__.py`
- Create: `src/minemod_audit/lab/inventory.py`
- Create: `src/minemod_audit/lab/validation.py`
- Test: `tests/test_lab_validation.py`

- [ ] Add lab APIs that classify validation targets as local/authorized only.
- [ ] Reject public server targeting in validation configuration.
- [ ] Document that exploit development against third-party servers is out of scope.
- [ ] Run `uv run --extra dev python -m pytest tests/test_lab_validation.py`.

### Task 4: Verification And Crawler Run

**Files:**
- Modify: `.gitignore`

- [ ] Ignore local `logs/`.
- [ ] Run ruff, mypy, pytest and format check.
- [ ] Relaunch the crawler with bounded limits.
- [ ] Confirm the dashboard still responds on `127.0.0.1:8501`.

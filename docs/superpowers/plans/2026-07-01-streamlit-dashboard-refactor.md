# Streamlit Dashboard Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor only the Streamlit dashboard so MineModVulnIndexer reads like an analysis workspace instead of raw SQLite dumps.

**Architecture:** Keep all data collection, models, crawler and correlation untouched. Add dashboard-only presentation helpers for table preparation, pagination, column schemas, page configuration and details panels. Each page composes shared helpers with page-specific columns and filters.

**Tech Stack:** Streamlit 1.58, pandas, SQLite read-only dashboard queries, pytest, Streamlit AppTest.

---

### Task 1: Presentation Helpers

**Files:**
- Create: `dashboard/components/page.py`
- Create: `dashboard/components/pagination.py`
- Create: `dashboard/data/presentation.py`
- Modify: `dashboard/components/tables.py`
- Test: `tests/test_dashboard_presentation.py`

- [ ] **Step 1: Write failing tests**

Tests cover readable list formatting, truncation, hidden raw fields, stable original-row selection, and page clamping.

- [ ] **Step 2: Run red tests**

Run `uv run --extra dev python -m pytest tests/test_dashboard_presentation.py -q`; expected failure because helpers do not exist.

- [ ] **Step 3: Implement helpers**

Create `configure_page`, table preparation helpers, pagination state helpers, and a configurable `render_table` using `width="stretch"`.

- [ ] **Step 4: Run green tests**

Run the same test command and expect pass.

### Task 2: Details And Filters

**Files:**
- Modify: `dashboard/components/details.py`
- Modify: `dashboard/components/filters.py`
- Test: `tests/test_dashboard_presentation.py`

- [ ] **Step 1: Write failing tests**

Tests verify relevant filter capability detection and safe handling of missing values.

- [ ] **Step 2: Implement minimal helpers**

Add relevant sidebar filters, reset button support, and a details panel with expanders for evidence, changed files, score reasons and raw metadata.

### Task 3: Page Schemas

**Files:**
- Create: `dashboard/data/schemas.py`
- Modify: `dashboard/app.py`
- Modify: `dashboard/pages/*.py`
- Test: `tests/test_dashboard_pages.py`

- [ ] **Step 1: Write AppTest smoke tests**

Use a fixture SQLite database and verify each dashboard page runs without exception.

- [ ] **Step 2: Implement page-specific layouts**

Apply wide layout, table/details columns, page-specific schemas, modpack details tabs, and overview metrics/charts.

### Task 4: Verification And Manual Dashboard Check

**Files:**
- All dashboard files

- [ ] **Step 1: Run full verification**

Run format, lint, mypy and pytest.

- [ ] **Step 2: Start dashboard**

Run Streamlit and inspect Mods, Vulnerabilities, Modpacks, Findings and Recent Fix Candidates.

- [ ] **Step 3: Commit and push**

Commit only dashboard/test changes and push to `origin/main`.

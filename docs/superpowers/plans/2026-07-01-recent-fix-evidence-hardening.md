# Recent Fix Evidence Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make recent-fix evidence reliable enough to avoid wrong GHSA versions, weak release associations, and misleading PR metadata.

**Architecture:** Keep the crawler passive and evidence-first. Normalize GitHub advisories into version fields, enrich PR search results with the full pull request object, and accept release-to-fix links only when the release explicitly references the PR or commit. Do not infer affected ranges from loose text.

**Tech Stack:** Python, Typer CLI, Pydantic models, GitHub REST API via the existing cached `HttpClient`, pytest, ruff, mypy.

---

### Task 1: GHSA Version Parsing

**Files:**
- Modify: `src/minemod_audit/pipeline.py`
- Test: `tests/test_recent_fix_discovery.py`

- [ ] **Step 1: Write failing test**

Add a test where an advisory contains `vulnerabilities[].first_patched_version` and `vulnerabilities[].vulnerable_version_range`, then assert the generated `SecurityEvidenceBundle` has `fixed_versions` and `affected_versions`.

- [ ] **Step 2: Run red test**

Run: `uv run --extra dev python -m pytest tests/test_recent_fix_discovery.py::test_github_advisory_versions_are_read_from_vulnerabilities -q`
Expected: FAIL because current code reads root-level `fixed_versions` and `affected_versions`.

- [ ] **Step 3: Implement minimal parser**

Add helper functions that extract string versions and ranges from advisory `vulnerabilities`.

- [ ] **Step 4: Run green test**

Run the same pytest command and expect PASS.

### Task 2: PR Details And Release Matching

**Files:**
- Modify: `src/minemod_audit/advisories.py`
- Modify: `src/minemod_audit/pipeline.py`
- Test: `tests/test_recent_fix_discovery.py`
- Test: `tests/test_targeted_mining.py`

- [ ] **Step 1: Write failing tests**

Add tests proving a generic shared term such as `security fix` does not attach a release, while a release body mentioning `#42` or `pull/42` does. Update the fake GitHub client to expose `get_pull_request`.

- [ ] **Step 2: Run red tests**

Run targeted pytest commands and expect failure because `_matching_release` currently accepts generic term overlap and `_bundles_from_pull_requests` uses the first PR commit.

- [ ] **Step 3: Implement PR enrichment**

Add `GitHubClient.get_pull_request()` and use `merge_commit_sha`, `merged_at`, and all PR commits. Prefer merge commit details for the canonical commit, but analyze patches from every PR commit.

- [ ] **Step 4: Implement strict release matching**

Replace generic term matching with explicit evidence: release text contains the selected commit SHA, release text cites PR number, or release text contains the PR URL.

- [ ] **Step 5: Run green tests**

Run targeted pytest commands and expect PASS.

### Task 3: Status And Term Quality

**Files:**
- Modify: `src/minemod_audit/security_discovery.py`
- Modify: `src/minemod_audit/pipeline.py`
- Test: `tests/test_recent_fix_discovery.py`
- Test: `tests/test_targeted_mining.py`

- [ ] **Step 1: Write failing tests**

Add tests proving `item duplication`, `duping`, `invalid slot`, `sender permissions`, and `client supplied amount` are matched. Add a test proving `Vulnerability.status` preserves the bundle status.

- [ ] **Step 2: Run red tests**

Run targeted pytest commands and expect failure for missing variants and status conversion.

- [ ] **Step 3: Implement minimal changes**

Expand concept terms conservatively and map bundle statuses into vulnerability statuses instead of forcing `candidate`.

- [ ] **Step 4: Run green tests**

Run targeted pytest commands and expect PASS.

### Task 4: Full Verification And Publish

**Files:**
- All modified files

- [ ] **Step 1: Run verification**

Run:
`uv run --extra dev ruff format .`
`uv run --extra dev ruff check .`
`uv run --extra dev mypy src tests`
`uv run --extra dev python -m pytest`

- [ ] **Step 2: Commit and push**

If all commands pass, commit with `Harden recent fix evidence linking` and push to `origin/main`.

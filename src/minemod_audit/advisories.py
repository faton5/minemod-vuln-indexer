from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

from minemod_audit.http_client import HttpClient
from minemod_audit.models import RepositoryResolution, SourceType, Vulnerability
from minemod_audit.security import (
    classify_impact,
    confidence_for_source,
    deduplicate_vulnerabilities,
)

SECURITY_TERMS = [
    "security",
    "vulnerability",
    "CVE",
    "GHSA",
    "exploit",
    "unsafe",
    "authorization",
    "validation",
    "bypass",
    "dupe",
    "duplication",
    "NBT",
    "packet",
    "permission bypass",
    "deserialization",
    "server crash",
]


class GitHubClient:
    def __init__(
        self,
        *,
        token: str | None,
        cache_directory: Path,
        timeout_seconds: float,
        offline: bool = False,
        refresh: bool = False,
    ) -> None:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self.http = HttpClient(
            base_url="https://api.github.com",
            headers=headers,
            cache_directory=cache_directory / "github",
            timeout_seconds=timeout_seconds,
            offline=offline,
            refresh=refresh,
        )

    def close(self) -> None:
        self.http.close()

    def search_repositories(
        self,
        mod_name: str,
        slug: str,
        authors: list[str],
    ) -> list[dict[str, Any]]:
        queries = [f'"{mod_name}"', slug, *(author for author in authors[:2])]
        results: list[dict[str, Any]] = []
        for query in queries:
            payload = self.http.get_json("/search/repositories", params={"q": query, "per_page": 5})
            results.extend(payload.get("items", []))
        return results

    def collect_repository_signals(self, repository: str) -> list[dict[str, Any]]:
        owner, repo = repository.split("/", maxsplit=1)
        signals: list[dict[str, Any]] = []
        for term in SECURITY_TERMS:
            issue_payload = self.http.get_json(
                "/search/issues",
                params={"q": f"repo:{repository} {term}", "per_page": 10},
            )
            signals.extend(issue_payload.get("items", []))
        releases = self.http.get_json(f"/repos/{owner}/{repo}/releases", params={"per_page": 30})
        signals.extend(releases if isinstance(releases, list) else releases.get("data", []))
        return signals

    def search_security_issues(
        self,
        repository: str,
        *,
        terms: tuple[str, ...],
        per_term: int = 5,
    ) -> list[dict[str, Any]]:
        results_by_url: dict[str, dict[str, Any]] = {}
        for term in terms:
            payload = self.http.get_json(
                "/search/issues",
                params={
                    "q": f"repo:{repository} {term} in:title,body is:issue",
                    "per_page": per_term,
                },
            )
            for item in payload.get("items", []):
                url = str(item.get("html_url") or item.get("url") or item.get("id"))
                enriched = dict(item)
                matched = set(enriched.get("matched_terms") or [])
                matched.add(term)
                if url in results_by_url:
                    matched.update(results_by_url[url].get("matched_terms") or [])
                enriched["matched_terms"] = sorted(matched)
                results_by_url[url] = enriched
        return list(results_by_url.values())

    def search_recent_pull_requests(
        self,
        repository: str,
        *,
        terms: tuple[str, ...],
        since_date: str,
        per_term: int = 5,
    ) -> list[dict[str, Any]]:
        return self._search_recent_issue_like(
            repository,
            terms=terms,
            qualifier=f"is:pr is:merged merged:>={since_date}",
            per_term=per_term,
        )

    def search_recent_issues(
        self,
        repository: str,
        *,
        terms: tuple[str, ...],
        since_date: str,
        per_term: int = 5,
    ) -> list[dict[str, Any]]:
        return self._search_recent_issue_like(
            repository,
            terms=terms,
            qualifier=f"is:issue updated:>={since_date}",
            per_term=per_term,
        )

    def _search_recent_issue_like(
        self,
        repository: str,
        *,
        terms: tuple[str, ...],
        qualifier: str,
        per_term: int,
    ) -> list[dict[str, Any]]:
        results_by_url: dict[str, dict[str, Any]] = {}
        for term in terms:
            payload = self.http.get_json(
                "/search/issues",
                params={
                    "q": f"repo:{repository} {term} in:title,body {qualifier}",
                    "per_page": per_term,
                    "sort": "updated",
                    "order": "desc",
                },
            )
            for item in payload.get("items", []):
                url = str(item.get("html_url") or item.get("url") or item.get("id"))
                enriched = dict(item)
                matched = set(enriched.get("matched_terms") or [])
                matched.add(term)
                if url in results_by_url:
                    matched.update(results_by_url[url].get("matched_terms") or [])
                enriched["matched_terms"] = sorted(matched)
                results_by_url[url] = enriched
        return list(results_by_url.values())

    def list_recent_commits(
        self, repository: str, *, since: str, per_page: int = 30
    ) -> list[dict[str, Any]]:
        owner, repo = repository.split("/", maxsplit=1)
        payload = self.http.get_json(
            f"/repos/{owner}/{repo}/commits",
            params={"since": since, "per_page": per_page},
        )
        return [dict(item) for item in payload]

    def get_commit_details(self, repository: str, sha: str) -> dict[str, Any]:
        owner, repo = repository.split("/", maxsplit=1)
        payload = self.http.get_json(f"/repos/{owner}/{repo}/commits/{sha}")
        return dict(payload)

    def list_pull_request_commits(self, repository: str, pull_number: int) -> list[dict[str, Any]]:
        owner, repo = repository.split("/", maxsplit=1)
        payload = self.http.get_json(f"/repos/{owner}/{repo}/pulls/{pull_number}/commits")
        return [dict(item) for item in payload]

    def list_recent_releases(
        self, repository: str, *, since: str, per_page: int = 30
    ) -> list[dict[str, Any]]:
        owner, repo = repository.split("/", maxsplit=1)
        payload = self.http.get_json(
            f"/repos/{owner}/{repo}/releases",
            params={"per_page": per_page},
        )
        since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
        releases = payload if isinstance(payload, list) else payload.get("data", [])
        recent: list[dict[str, Any]] = []
        for item in releases:
            published = str(item.get("published_at") or item.get("created_at") or "")
            try:
                published_dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
            except ValueError:
                continue
            if published_dt >= since_dt:
                recent.append(dict(item))
        return recent

    def collect_global_advisories(self, repository: str) -> list[dict[str, Any]]:
        payload = self.http.get_json(
            "/advisories",
            params={"query": f"repo:{repository}", "per_page": 30},
        )
        if isinstance(payload, list):
            return [dict(item) for item in payload]
        return list(payload.get("data", []))

    def collect_repository_advisories(self, repository: str) -> list[dict[str, Any]]:
        owner, repo = repository.split("/", maxsplit=1)
        try:
            payload = self.http.get_json(
                f"/repos/{owner}/{repo}/security-advisories",
                params={"per_page": 30},
            )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in {403, 404}:
                return []
            raise
        if isinstance(payload, list):
            return [dict(item) for item in payload]
        return list(payload.get("data", []))


class OsvClient:
    def __init__(
        self,
        *,
        cache_directory: Path,
        timeout_seconds: float,
        offline: bool = False,
    ) -> None:
        self.http = HttpClient(
            base_url="https://api.osv.dev",
            cache_directory=cache_directory / "osv",
            timeout_seconds=timeout_seconds,
            offline=offline,
        )

    def close(self) -> None:
        self.http.close()

    def query_by_commit(self, commit: str) -> list[dict[str, Any]]:
        payload = self.http.post_json("/v1/query", json_body={"commit": commit})
        return list(payload.get("vulns", []))


class NvdClient:
    def __init__(
        self,
        *,
        api_key: str | None,
        cache_directory: Path,
        timeout_seconds: float,
        offline: bool = False,
        refresh: bool = False,
    ) -> None:
        headers = {"apiKey": api_key} if api_key else {}
        self.http = HttpClient(
            base_url="https://services.nvd.nist.gov/rest/json",
            headers=headers,
            cache_directory=cache_directory / "nvd",
            timeout_seconds=timeout_seconds,
            offline=offline,
            refresh=refresh,
        )

    def close(self) -> None:
        self.http.close()

    def search_keyword(self, keyword: str) -> list[dict[str, Any]]:
        payload = self.http.get_json("/cves/2.0", params={"keywordSearch": keyword})
        return list(payload.get("vulnerabilities", []))


def normalize_advisory(
    raw: dict[str, Any],
    *,
    repository: RepositoryResolution,
    source_type: SourceType,
) -> Vulnerability:
    title = str(raw.get("summary") or raw.get("title") or raw.get("ghsaId") or "Untitled advisory")
    description = str(raw.get("description") or raw.get("body") or "")
    source_url = str(raw.get("html_url") or raw.get("url") or raw.get("permalink") or "")
    affected = [str(item) for item in raw.get("affected_versions", [])]
    fixed = [str(item) for item in raw.get("fixed_versions", [])]
    text = f"{title}\n{description}"
    confidence = confidence_for_source(source_type, has_version_range=bool(affected or fixed))
    identifier = raw.get("ghsa_id") or raw.get("id") or source_url or title
    return Vulnerability(
        internal_id=f"{source_type.value}:{identifier}",
        mod_project_id=repository.mod_project_id,
        mod_name=repository.mod_name,
        repository=repository.repository,
        title=title,
        description=description,
        source_type=source_type,
        source_url=source_url or "https://example.invalid/unresolved-source",
        ghsa_id=raw.get("ghsa_id") or raw.get("ghsaId"),
        cve_id=raw.get("cve_id") or raw.get("cveId"),
        osv_id=raw.get("osv_id") or raw.get("id"),
        severity=raw.get("severity"),
        impact_category=classify_impact(text),
        affected_versions=affected,
        fixed_versions=fixed,
        status="confirmed" if confidence >= 90 and (affected or fixed) else "candidate",
        confidence=confidence,
        evidence=[source_url] if source_url else [],
        requires_manual_review=not bool(affected or fixed),
    )


def deduplicate_models(vulnerabilities: list[Vulnerability]) -> list[Vulnerability]:
    payloads = [item.model_dump(mode="json") for item in vulnerabilities]
    return [Vulnerability.model_validate(item) for item in deduplicate_vulnerabilities(payloads)]

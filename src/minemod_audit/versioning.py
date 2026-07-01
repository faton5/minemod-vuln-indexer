import re
from enum import StrEnum

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version


class VersionDecision(StrEnum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    MANUAL_REVIEW = "manual_review"


_NUMERIC_RE = re.compile(r"^\d+(?:[._-]\d+)*$")
_CLAUSE_RE = re.compile(r"^(<=|>=|<|>|==|=)\s*(.+)$")


def _clean_version(value: str) -> str:
    value = value.strip()
    return value[1:] if value.startswith("v") and len(value) > 1 else value


def _numeric_tuple(value: str) -> tuple[int, ...] | None:
    cleaned = _clean_version(value)
    if not _NUMERIC_RE.fullmatch(cleaned):
        return None
    return tuple(int(part) for part in re.split(r"[._-]", cleaned))


def _compare_numeric(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    width = max(len(left), len(right))
    padded_left = left + (0,) * (width - len(left))
    padded_right = right + (0,) * (width - len(right))
    return (padded_left > padded_right) - (padded_left < padded_right)


def _satisfies_numeric(version: str, clause: str) -> bool | None:
    match = _CLAUSE_RE.fullmatch(clause.strip())
    if match is None:
        return None
    operator, raw_bound = match.groups()
    bound = _numeric_tuple(raw_bound)
    current = _numeric_tuple(version)
    if bound is None or current is None:
        return None
    comparison = _compare_numeric(current, bound)
    if operator == "<":
        return comparison < 0
    if operator == "<=":
        return comparison <= 0
    if operator == ">":
        return comparison > 0
    if operator == ">=":
        return comparison >= 0
    return comparison == 0


def _satisfies(version: str, specifier: str) -> bool | None:
    cleaned = _clean_version(version)
    try:
        return Version(cleaned) in SpecifierSet(specifier)
    except (InvalidSpecifier, InvalidVersion):
        parts = [part.strip() for part in specifier.split(",") if part.strip()]
        if not parts:
            return None
        results = [_satisfies_numeric(cleaned, part) for part in parts]
        if any(result is None for result in results):
            return None
        return all(bool(result) for result in results)


def is_version_affected(
    version: str,
    *,
    affected: str | None = None,
    fixed: str | None = None,
) -> VersionDecision:
    if affected:
        affected_match = _satisfies(version, affected)
        if affected_match is None:
            return VersionDecision.MANUAL_REVIEW
        if not affected_match:
            return VersionDecision.NOT_AFFECTED

    if fixed:
        fixed_match = _satisfies(version, f">={fixed}")
        if fixed_match is None:
            return VersionDecision.MANUAL_REVIEW
        if fixed_match:
            return VersionDecision.NOT_AFFECTED

    return VersionDecision.AFFECTED if affected or fixed else VersionDecision.MANUAL_REVIEW

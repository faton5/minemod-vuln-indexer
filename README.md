# MineModVulnIndexer

> Archived prototype. This repository is kept for reference only and is no
> longer actively developed.

MineModVulnIndexer is a passive Python prototype for indexing Minecraft mod
metadata, public security-fix signals, and exact modpack component versions.

## Scope

The project only uses public metadata and local analysis.

It does not:

- scan Minecraft servers;
- connect to multiplayer servers;
- execute proof-of-concepts;
- exploit third-party systems;
- mirror or redistribute mod files.

See `docs/SAFETY_SCOPE.md` and `docs/LOCAL_LAB.md` for the defensive local lab
scope that was used during development.

## What Was Implemented

- Modrinth and CurseForge provider clients.
- CurseForge modpack manifest indexing.
- Exact modpack component extraction with project IDs, file IDs, versions and hashes.
- Public recent-fix hunting from changelogs, linked issues, PRs and commits.
- Optional Gemini triage for candidate explanation.
- Release-lag hunting prototypes.
- A local read-only Streamlit dashboard.
- JSON/CSV/Markdown report helpers.

## Current Status

The project is not production-ready. The crawler can collect data, but the
signal quality is inconsistent and too dependent on public changelog wording,
repository metadata, API availability and exact modpack manifests.

The last validated workflow prioritized highly downloaded mods first, then
looked for recent public fixes and correlated the previous version with indexed
modpacks. In the final crawl, the system produced candidates, but no actionable
exposure was confirmed.

## Setup

```bash
uv sync --extra dev
```

Create a local `.env` file if you want to run the archived prototype:

```env
MODRINTH_ENABLED=true
CURSEFORGE_ENABLED=true
CURSEFORGE_API_KEY=
GITHUB_TOKEN=
GEMINI_API_KEY=
GEMINI_AI_ENABLED=false
```

Do not commit `.env`. API keys are intentionally ignored by Git.

## Useful Commands

```bash
minemod-audit providers status
minemod-audit collect-mods --provider all --limit 20
minemod-audit collect-modpacks --provider modrinth --limit 100
minemod-audit index-curseforge-packs --limit 200 --releases 3
minemod-audit hunt-recent-security-fixes --provider all --updated-within-days 14 --popular-mods 200 --popular-modpacks 200 --top 50 --ai
minemod-audit dashboard --database ./data/minemod.sqlite
```

Dashboard:

```bash
streamlit run dashboard/app.py
```

## Dashboard Pages

- `Overview`: high-level counts, crawl status and AI usage.
- `Vulnerabilities`: candidate detail, public evidence, AI verdicts, modpack exposure and structured crawler logs.
- `Mods`: indexed mods.
- `Modpacks`: indexed modpacks and releases.
- `AI`: Gemini cache and candidate annotations.

## Repository Layout

```text
src/minemod_audit/       Python package and CLI
dashboard/               Streamlit read-only dashboard
tests/                   Unit and integration tests
docs/                    Safety and lab notes
examples/lab/            Local lab notes
index.html               Static GitHub Pages landing page
```

Generated local data is intentionally ignored:

```text
data/
logs/
cache/
output/
.env
```

## Verification

The final cleanup was validated with:

```bash
python -m ruff format src dashboard tests
python -m ruff check src dashboard tests
python -m mypy src dashboard
python -m pytest -q
```

## License

MIT

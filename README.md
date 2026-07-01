# MineModVulnIndexer

MineModVulnIndexer is a passive, open-source security and dependency
analysis tool for Minecraft mods and modpacks.

## Objectives

- Retrieve public CurseForge metadata.
- Identify official source repositories.
- Collect publicly documented CVEs, GHSAs and security fixes.
- Correlate affected mod versions with public modpack releases.
- Generate JSON, CSV and Markdown reports.

## Safety scope

This project does not scan Minecraft servers, connect to multiplayer
servers, execute proof-of-concepts or exploit third-party systems.

It does not mirror or redistribute mod files.

See `docs/SAFETY_SCOPE.md` and `docs/LOCAL_LAB.md` for the defensive local lab
scope.

## Status

Initial development and API integration.

## Configuration

Modrinth is the primary provider and works without an API token.

```env
MODRINTH_ENABLED=true
MODRINTH_BASE_URL=https://api.modrinth.com/v2
MODRINTH_CONTACT_EMAIL=
MODRINTH_REQUESTS_PER_MINUTE=120

CURSEFORGE_ENABLED=auto
CURSEFORGE_API_KEY=
CURSEFORGE_BASE_URL=https://api.curseforge.com

GITHUB_TOKEN=
NVD_API_KEY=

PROVIDER_PRIORITY=modrinth,curseforge
```

`CURSEFORGE_ENABLED=auto` enables CurseForge only when `CURSEFORGE_API_KEY`
is configured. If the key is missing, the crawler logs that CurseForge is
disabled and continues with Modrinth.

## CLI

```bash
minemod-audit providers status
minemod-audit collect-mods --provider modrinth --limit 20
minemod-audit collect-modpacks --provider modrinth --limit 100
minemod-audit collect-mods --provider all --limit 20
minemod-audit run --providers modrinth
minemod-audit run --providers all
minemod-audit dashboard
```

Example provider status:

```text
Provider     Status      Priority Reason
Modrinth     enabled     1        Public API available
CurseForge   disabled    2        API key not configured
GitHub       enabled     -        Token configured
NVD          enabled     -        API key configured
```

## Known limits

Modrinth and CurseForge do not expose identical catalogs. A project can exist
on one platform but not the other, or expose different metadata. MineModVulnIndexer
keeps provider IDs and raw metadata so conflicts can be reviewed instead of
silently overwritten.

## Local dashboard

The local dashboard is a read-only Streamlit interface for inspecting the SQLite
database created by the crawler. It does not start crawler jobs, does not call
external APIs on page load, and opens on `127.0.0.1` by default.

Install dependencies and launch:

```bash
uv sync --extra dev
minemod-audit dashboard --database ./data/minemod.sqlite
```

Direct Streamlit launch is also supported:

```bash
streamlit run dashboard/app.py
```

Dashboard pages:

- Overview: index counts, vulnerability charts, provider distribution and last run.
- Mods: searchable project table with provider, loader and Minecraft filters.
- Vulnerabilities: confirmed, candidate and unclear records remain visually separate.
- Modpacks: indexed packs, releases and selected release details.
- Findings: exact vulnerable-version matches with CSV, JSON and Markdown exports.
- Manual Review: unresolved repositories, non-comparable versions and provider conflicts.
- Runs: stored execution history when run records are available.

GitHub Pages remains the static public project page. The Streamlit dashboard is
the local dynamic viewer for SQLite data.

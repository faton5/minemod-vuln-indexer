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

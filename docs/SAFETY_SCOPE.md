# Safety Scope

MineModVulnIndexer is a passive security and dependency analysis tool.

Allowed work:

- Collect public mod, modpack, repository and advisory metadata.
- Correlate vulnerable mod versions with public modpack releases.
- Audit inventories supplied by a server owner or an authorized operator.
- Validate findings in a local lab controlled by the project operator.
- Produce reports that help maintainers and administrators patch safely.

Out of scope:

- Scanning public Minecraft servers.
- Connecting to third-party servers to identify installed mods.
- Building exploit payloads or proof-of-concept mods for use against others.
- Automating target discovery.
- Redistributing mod files.

The local lab exists to reduce false positives and document remediation. It is
not a staging area for attacking public servers.

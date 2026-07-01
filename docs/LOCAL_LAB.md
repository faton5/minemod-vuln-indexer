# Local Lab

The local lab is for owner-authorized validation only. Use it with a Minecraft
server running on `localhost`, `127.0.0.1`, `::1`, or a private LAN address.

Recommended workflow:

1. Run the crawler and dashboard.
2. Select a finding that requires manual review.
3. Recreate the relevant mod version in a disposable local server.
4. Use non-exploit validation checks to confirm version, configuration and
   exposure.
5. Record the result as manual evidence and update remediation notes.

Do not use this project to find public servers with vulnerable mods. For
administrator notification, use public project issue trackers, maintainer
contacts, modpack pages, or responsible disclosure channels.

Future validation helpers should answer defensive questions:

- Is this exact mod and version present in my local lab inventory?
- Is the vulnerable feature enabled?
- Is a fixed version available?
- What should an administrator patch or disable?

They should not generate payloads that exploit the vulnerability.

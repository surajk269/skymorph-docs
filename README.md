# SkyMorph Documents

Quotation, Proforma Invoice and Tax Invoice tools for the SkyMorph team, published with GitHub Pages. There is no server.

| File | What it is |
|---|---|
| `index.html` | Home page with the three tools |
| `quotation.html`, `proforma.html`, `invoice.html` | The tools |
| `team.js` | Passcode screen, shared serial numbers, team documents |
| `team-config.js` | Where the team store lives, plus the access key encrypted with the passcode |
| `setup.html` | One-time admin page that creates `team-config.js` |

## How sharing works
- Shared numbers and saved documents live in a separate **private** repository (the "team store").
- The site reaches it with a GitHub access key limited to that one repository. The key is stored encrypted; only the team passcode unlocks it.
- **New** in a tool takes the next number for the whole team. Typing a different number asks whether the team count should continue from it.
- **Print / Save PDF** and **Save file** keep a team copy. **Team documents** lists them for reopening and reprinting.
- Without `team-config.js` set up, the tools still work but only on each person's own computer.

## One-time setup
1. Create a private repository for the team store (for example `skymorph-data`).
2. Create a fine-grained access token: only that repository, permission **Contents: Read and write**.
3. Open `setup.html`, enter the repository, the token and the team passcode. It downloads `team-config.js`.
4. Replace `team-config.js` in this folder with the downloaded file and publish.

When the token expires, repeat steps 2 to 4.

## Changing the passcode
The passcode check value is in `team.js` (`VERIFY`). Changing the passcode means updating that value and running the setup again.

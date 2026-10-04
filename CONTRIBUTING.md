# Contributing

Thanks for helping. A few ground rules keep these extensions installable and dependable.

## Adding an extension

Create `<name>/` containing at least:

| File | Purpose |
|---|---|
| `manifest.json` | Cockpit manifest; `"name"` must equal the directory name |
| `index.html` + assets | The page |
| `install.sh`, `uninstall.sh` | Copy `samba-adc/install.sh` and edit the `EXT` and `RUNTIME_FILES` list |
| `VERSION`, `CHANGELOG.md` | SemVer; the top changelog entry must match `VERSION` |
| `README.md` | What it does, requirements, install, limits, **what is tested and what is not** |

`python3 scripts/check_package.py <name>` verifies that the installer's file list matches what the page loads.

## Before opening a PR

```bash
make lint check                 # shellcheck, syntax, package consistency
cd <name> && npm ci && npm test # unit tests
```

- Do not add runtime dependencies or a build step to an extension without discussing it first.
- Anything that changes a customer's directory (GPOs, SYSVOL, `smb.conf`) needs a test against a throwaway
  Samba AD DC, and the PR should say what was run.
- Never put passwords on a command line; pass secrets over stdin.

## Releases

Bump `VERSION`, `package.json` and the top of `CHANGELOG.md`, then tag `<name>-vX.Y.Z`
(for example `samba-adc-v1.0.1`). The release workflow builds and attaches the tarball.

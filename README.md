# Cockpit Samba AD DC

A collection of extensions for [Cockpit](https://cockpit-project.org), the web console for Linux servers.
Each extension is a self-contained directory with its own installer, tests and changelog.

| Extension | What it does | Version |
|---|---|---|
| [`samba-adc`](samba-adc/) | Administer a **Samba Active Directory Domain Controller**: users, groups, DNS, FSMO, a GPMC/GPME-style **Group Policy** editor with the full Windows 11 policy set, and diagnostics for "visible in Explorer but can't open" and `gpupdate` connectivity errors | 1.0.1 |

## Quick start

```bash
git clone https://github.com/XHiddenProjects/cockpit-samba-ad-dc.git
cd cockpit-samba-ad-dc

./install.sh --list                    # what is available
./install.sh samba-adc --check         # pre-flight checks only; changes nothing
sudo ./install.sh samba-adc            # install system-wide
```

Then open Cockpit (`https://<server>:9090`) and look for the extension in the menu.
No Cockpit restart is needed; hard-refresh the browser if it does not show up yet.

Common installer options (same for every extension; `./install.sh <name> --help` lists them all):

| Option | Meaning |
|---|---|
| `--user` | Install for the current user only (`~/.local/share/cockpit`), no root needed |
| `--prefix DIR` | Install into `DIR/<name>` (packaging, testing) |
| `--dev` | Symlink the checkout instead of copying, for development |
| `--with-deps` | `apt-get install` the helper packages the extension uses |
| `--check` | Pre-flight checks only |
| `--uninstall` / `./uninstall.sh <name>` | Remove it (`--purge` also removes anything it added under `/etc`) |
| `--all` | Act on every extension in the repo |

Requirements: Cockpit &ge; 250 on Debian 13 / Ubuntu 24.04 (other apt-based distributions probably work).
Each extension's README lists anything extra.

## Download a release instead of cloning

Tagged releases attach `<name>-<version>.tar.gz` (runtime files + installer only):

```bash
tar xzf samba-adc-1.0.1.tar.gz && cd samba-adc-1.0.1 && sudo ./install.sh
```

## Repository layout

```
cockpit-samba-ad-dc/
  install.sh  uninstall.sh      # install any extension by name
  samba-adc/                    # one extension
    manifest.json index.html *.js *.py vendor/     # runtime files (what gets installed)
    install.sh uninstall.sh VERSION CHANGELOG.md   # per-extension packaging
    tests/ tools/ package.json                     # development only, never installed
  scripts/check_package.py      # CI: installer file list vs. what the page loads, version consistency
  .github/workflows/            # CI and release automation
  Makefile                      # make lint | test | check | dist
```

## Development

```bash
make lint check                          # shellcheck, syntax, package consistency
cd samba-adc && npm ci && npm test       # unit tests
make dist EXT=samba-adc                  # build dist/samba-adc-<version>.tar.gz
./install.sh samba-adc --dev --user      # live-edit install into your own Cockpit
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for adding a new extension and the release process.

## License

[MIT](LICENSE). Bundled and derived third-party material is listed in [`NOTICE.md`](NOTICE.md).

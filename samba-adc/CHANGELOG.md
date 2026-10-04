# Changelog

All notable changes to the Samba AD DC Cockpit module. Format: [Keep a Changelog](https://keepachangelog.com/),
versioning: [SemVer](https://semver.org/).

## [1.0.0] - 2026-10-04

First public release as a standalone extension.

### Added
- **Group Policy Management Console look-alike**: domain/OU/site tree, link order, enforced, link enabled,
  block inheritance, inheritance view, GPO details/status, Settings report, create/rename/delete.
- **Group Policy Editor look-alike** for Computer and User Configuration:
  - Administrative Templates driven by ADMX/ADML, with a built-in set and a one-click download of
    Microsoft's Windows 11 templates into the domain Central Store (also: file/folder upload, Samba's own templates).
  - Security Settings: password/lockout, legacy Audit Policy, User Rights Assignment (45 rights),
    Security Options (98, generated from `sceregvl.inf`), Windows Defender Firewall with Advanced Security
    (profiles, logging, inbound/outbound rules), Advanced Audit Policy Configuration (52 subcategories).
  - Scripts (startup/shutdown/logon/logoff, PowerShell) and Preferences (Registry, Drive Maps).
  - Honest placeholder pages for nodes that cannot be edited here, with the RSAT route.
- **Group Policy health check and repair**: per-GPO integrity (SYSVOL folder, GPT.INI, version, NT ACLs,
  unregistered client-side extensions, dangling links) and domain delivery (SYSVOL ACLs, DNS SRV, time, SPN).
- **File sharing & domain diagnostics** with one-click fixes, and a sign-in test (per share and for `\\server`)
  that names the failing layer.
  - Firewall check covers the full Active Directory port set (incl. dynamic RPC 49152-65535) for ufw,
    firewalld and nftables.
  - `wsdd2` support for Debian 13 (systemd drop-in binding it to `samba-ad-dc.service`).
- `install.sh` / `uninstall.sh` (system, `--user`, `--prefix`, `--dev`, `--check`, `--with-deps`).

### Changed
- GPO create/delete/edit no longer use `samba-tool gpo` over SMB (the DC's machine account cannot write to
  SYSVOL); they use the local AD database and SYSVOL directly and need no credentials.
- Rebuilt the README (the previous one contained duplicated sections).

### Fixed
- Link edits are read-modify-write against the directory, so rapid edits cannot overwrite each other.
- INF files are written in the exact format Windows uses (no spaces in `[Registry Values]`).

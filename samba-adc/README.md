# Samba AD DC &mdash; Cockpit module

A [Cockpit](https://cockpit-project.org) page for administering a **Samba Active
Directory Domain Controller** on Debian 13 (Ubuntu works too). It is a thin UI over
`samba-tool`, `testparm`, `systemctl` and the local AD database: no separate daemon,
no database of its own, no build step.

Highlights:

- Everyday AD administration: users, groups, computers, OUs, DNS, FSMO, sites, SPNs, delegation, ACLs.
- A **Group Policy Management Console + Editor** look-alike, with the full Windows 11 / Server
  policy catalog (Microsoft's ADMX templates, installed with one click).
- **Diagnostics** for the two classic Samba-on-Windows complaints: *"the server shows up in Explorer but
  I can't open it"* and *`gpupdate`: "lack of network connectivity to a domain controller"*.

> Version: see [`VERSION`](VERSION) and [`CHANGELOG.md`](CHANGELOG.md).

## Requirements

- Debian 13 (or Ubuntu 24.04) with **Cockpit &ge; 250** and a working **Samba AD DC**
  (`samba-ad-dc`, so `samba-tool` and `python3-samba` are present).
- `python3`, `smbclient` (for the sign-in test), `ldb-tools` (for fast user lists).
  `sudo ./install.sh --with-deps` installs these (not Samba itself).
- The Cockpit user can gain administrative access (in `sudo`, or root). Every privileged call uses
  Cockpit's normal *Administrative access* escalation.
- Internet access on the DC only for the optional **Microsoft ADMX download** (or copy the `.msi` over).

## Install

```bash
git clone https://github.com/YOUR-USER/Cockpit-extensions.git
cd Cockpit-extensions
sudo ./install.sh samba-adc            # system-wide, to /usr/share/cockpit/samba-adc
```

Other modes (run `./install.sh samba-adc --help` for all):

```bash
./install.sh samba-adc --check          # pre-flight checks only, changes nothing
sudo ./install.sh samba-adc --with-deps # also apt-install cockpit, python3, smbclient, ldb-tools, acl, attr
./install.sh samba-adc --user           # current user only (~/.local/share/cockpit), no root
./install.sh samba-adc --dev            # symlink the checkout (edits are live, reload the tab)
sudo ./uninstall.sh samba-adc           # remove (add --purge to also remove the wsdd2 drop-in)
```

"Samba AD DC" then appears in the Cockpit menu. No Cockpit restart is needed; hard-refresh the
browser (Ctrl+Shift+R) if it does not show up. Upgrading is the same command again (the old copy is
swapped out atomically). Uninstalling never touches your GPOs, SYSVOL, `smb.conf` or shares.

<details><summary>Manual install</summary>

```bash
sudo mkdir -p /usr/share/cockpit/samba-adc
sudo cp -r manifest.json index.html style.css *.js *.py vendor /usr/share/cockpit/samba-adc/
sudo chmod -R a+rX /usr/share/cockpit/samba-adc
```
(Copy only the runtime files; `install.sh` has the exact list.)
</details>

## Coverage

Each of these is its own tab:

| Tab | Backed by | Covers |
|---|---|---|
| Overview | `domain info`, `drs showrepl` | Quick health snapshot |
| Domain | `domain info/level/passwordsettings` | Functional level, password & lockout policy |
| Forest | `forest directory_service` | dsHeuristics |
| FSMO | `fsmo show/transfer/seize` | All FSMO roles |
| Sites | `sites …`, `sites subnet …` | Sites and subnets |
| DNS | `dns zonecreate/zonelist/add/delete/query` | Zones and records |
| Users | `user …` | Create/delete/enable/disable/reset password/move/groups, bulk actions, first/last name columns, spreadsheet import |
| Groups | `group …` | Create/delete/members/move, bulk actions |
| Computers | `computer …` | Create/delete/show/list/move, bulk actions |
| Contacts | `contact …` | Create/delete/show/move, bulk actions |
| Organizational Units | `ou …` | Create/delete/rename/move, bulk actions |
| Group Policy | GPMC-style manager + GPME-style editor ([below](#group-policy)) | Links, enforce, block inheritance, ADMX templates (full Windows 11 set), Security Settings, Advanced Audit, Firewall, Scripts, Preferences, health check & repair |
| SPNs | `spn …` | List/add/delete per account |
| Delegation | `delegation …` | Show, unconstrained/protocol-transition toggles, constrained service delegation |
| ACLs | `dsacl …`, `ntacl …` | Directory-object ACLs by DN, filesystem ACLs by path, sysvol check/reset |
| Server Time | `time` | Query a server's time |
| File Shares | `smb.conf` sections | Add/edit/delete Samba shares, create backing directories, sets real filesystem permissions |
| Configuration | `smb.conf`, `testparm`, diagnostics | Full raw editor, validated before every save; file-sharing & domain-delivery diagnostics |

Passwords (user creation, password reset) are always sent over the
process's stdin, never as a command-line argument, so they never show up in
`ps`. Every `smb.conf` write (Configuration tab and File Shares tab) is
checked with `testparm -s` against a scratch copy before it's allowed to
overwrite the real file, so a bad edit can't take Samba down; a successful
save triggers `systemctl reload` on the selected service.

### Moving objects between OUs

Every "Move" action (Users, Groups, Computers, Contacts, Organizational
Units) opens a visual picker of the actual OU/container tree &mdash; built
from `samba-tool ou list` plus the well-known default containers
(`CN=Users`, `CN=Computers`, `CN=Builtin`) &mdash; so picking a destination
is click-to-select rather than typing an LDAP DN by hand. A "Type a DN
instead" link is still there as a fallback for containers the tree doesn't
know about.

### Bulk actions

Users, Groups, Computers, Contacts, and Organizational Units all have a
checkbox column and a "select all" header checkbox. Selecting one or more
rows reveals a bulk-action bar (Delete, Move&hellip;, and for Users,
Enable/Disable) that runs the action against every selected item, sequentially,
and reports back which ones succeeded and which failed rather than stopping
at the first error.

### First/last name on the Users list

The Users table shows First name and Last name columns (blank/&mdash; when
not set on that account), fetched efficiently with one bulk `ldbsearch`
query against the local database rather than one `samba-tool user show`
call per user. If `ldbsearch` (from the `ldb-tools` package) isn't
available, it automatically falls back to `samba-tool user show` per user,
run with limited concurrency so a large directory doesn't spawn dozens of
escalated processes at once.

### Importing users from a spreadsheet

"Import from spreadsheet&hellip;" on the Users tab accepts .csv, .xlsx,
.xls, or .ods &mdash; parsed entirely in the browser (via a locally-vendored
copy of [SheetJS](https://sheetjs.com), `vendor/xlsx.core.min.js`, Apache-2.0
licensed &mdash; no file ever needs to touch the server just to be read, and
no external network request is made to parse it). After picking a file you
get:

- **A preview** of the first few rows, so you can confirm it parsed correctly.
- **Column mapping**: each target field (Username, First name, Last name,
  Email, Password, Groups) gets a dropdown of the file's actual column
  headers, pre-guessed from common header names (`username`/`sAMAccountName`,
  `first name`/`givenName`, etc.) but fully overridable. Username is the only
  required mapping.
- **Import settings applied to every row**: which OU/container to create the
  accounts in (the same visual tree picker used for Move), a password
  strategy (generate a random password per user, or fall back to one shared
  password for rows without their own), "must change password at next
  logon", and a set of groups to add every imported user to (merged with
  whatever's in each row's own Groups column, if mapped).
- Usernames that already exist are always skipped, never overwritten.

After the import runs, a results dialog lists every row's outcome
(created/skipped/failed, with the reason for skips and failures), and shows
any auto-generated passwords **once** &mdash; there's a "Download results
(CSV)" button to capture them, since they aren't retrievable afterward.
There's also a "Download a CSV template" link on the file-picker step to get
the expected column layout right from the start.


### File share permissions (why Windows said "access denied")

Two things have to line up for a Windows client to get into a share on an
AD DC, and this module now sets up both:

1. **`valid users` must name groups as groups.** In `smb.conf`,
   `valid users = Sales` means a *user* called Sales. A group must be written
   `@"DOMAIN\Sales"`. The share form now writes the correct form
   automatically (it knows which names are users and which are groups), and
   reads existing `@"DOMAIN\Group"` entries back into the picker.
2. **The share needs a Windows (NT) ACL, not just POSIX permissions.**
   Windows clients are gated by the NT ACL that `vfs_acl_xattr` keeps on the
   directory. "Create/fix directory & permissions" now looks up each named
   user/group's SID from the directory (no NSS/winbind name resolution
   needed), writes an NT ACL granting them Modify (or Read for read-only
   shares) with `samba-tool ntacl set`, opens the POSIX mode to `3777` so the
   NT ACL is the real gate, and shows the ACL now on disk so you can verify
   it. Saved shares get `vfs objects = acl_xattr`, `map acl inherit = yes`,
   `store dos attributes = yes` and `acl_xattr:ignore system acls = yes`.
   Any other parameters you added to a share by hand are preserved when the
   share is edited.

The ACL is applied to the share's root directory and inherited by new
content. Existing subfolders keep their old ACLs; use Windows' Security tab
("Replace all child object permissions") to push it down.

After changing access, Windows caches sessions and group tokens: disconnect
the mapped drive (`net use * /delete`), and log off/on if the user was only
just added to the group.

### Windows network discovery and "I can see it but can't open it"

Windows 10/11 find servers through **WS-Discovery** and then open `\\<announced name>`. Discovery
working only proves the *announcement* reached the client; opening the server needs more.
**Configuration &rarr; File sharing &amp; network discovery &rarr; Run diagnostics** checks each layer:

| Check | What goes wrong without it |
|---|---|
| Discovery daemon | Not installed, stopped, or (wsdd2 on an AD DC) refused by systemd, see below |
| TCP 445 listening on the real interface | `bind interfaces only` / `interfaces` mistakes |
| Announced name == NetBIOS/DNS name | Explorer shows the OS hostname; if Samba/DNS know the server by another name, the click goes nowhere |
| Hostname does not resolve to `127.0.1.1` | Debian's default `/etc/hosts` makes Samba hand out an unreachable address |
| A record in AD DNS matches this host | Windows resolves `\\name` through DNS; no record = "network path not found" |
| **Firewall (ufw / firewalld / nftables)** | Needs the **Active Directory ports** (DNS 53, Kerberos 88, RPC 135, LDAP 389, SMB 445, 464, 636, 3268/9, **dynamic RPC 49152-65535**) plus the discovery ports. Opening only SMB + discovery makes the computer *appear* in Explorer while opening it and `gpupdate` fail |
| Each share | Missing path, no Windows ACL yet, unresolvable `valid users` groups, `guest ok` (blocked by Windows 11 24H2) |
| SYSVOL / NETLOGON, `samba-tool ntacl sysvolcheck` | Wrong SYSVOL ACLs give "access denied" reading `GPT.INI` |
| DNS SRV records, multiple/stale A records | The DC cannot be located; intermittent failures |
| Time sync, SPNs, NTLM/signing settings | Kerberos failures (5 minute skew), "access denied" |

Each failing check has a one-click fix where that is safe (install/bind the daemon, open firewall
ports, refresh DNS records, reset SYSVOL permissions). **Test access** (Shares tab) and **Test sign-in**
(diagnostics card) sign in from the server itself and report which layer fails: network, name,
authentication, or permission.

**Package note (Debian 13):** the Python `wsdd` package is no longer in Debian stable; Debian 13 ships
**`wsdd2`**, which also answers LLMNR (a name-resolution fallback for clients that do not use this DC
for DNS). Debian's `wsdd2.service` is bound to `smbd.service`, which is disabled on an AD DC, so the
module writes a drop-in (`/etc/systemd/system/wsdd2.service.d/samba-ad-dc.conf`) tying it to
`samba-ad-dc.service` instead. Ports: `wsdd2` needs UDP 3702, TCP 3702 and UDP/TCP 5355; Python
`wsdd`/`wsdd-server` needs UDP 3702 and TCP 5357.

**Client side** (cannot be checked from the server): domain-joined PCs must use **this DC as their DNS
server**, have a correct clock, and be signed in with a domain account. The Group Policy *Health check*
lists the exact commands to run on the PC.

### Group Policy

The **Group Policy** tab has two parts that mirror the Windows tools.

**Management (like GPMC):** a tree of the domain, OUs, sites and all GPOs. Select a domain/OU to see its
linked GPOs: change link order, toggle *Enforced* and *Link enabled*, set *Block inheritance*, unlink,
link an existing GPO or create-and-link a new one. *Group Policy Inheritance* computes effective
precedence. Selecting a GPO shows *Scope*, *Details* (versions, status, registered extensions) and
*Settings* (a report of everything configured). GPOs can be created, renamed, enabled/disabled per
computer/user side, and deleted (links are cleaned up).

**Health check (toolbar):** verifies every GPO (SYSVOL folder, `GPT.INI`, AD/SYSVOL version, NT ACLs,
client-side extensions registered) plus SYSVOL permissions, DNS SRV records, time sync and SPNs, with a
one-click **Repair**.

**Editor (like GPME):** *Edit* opens Computer Configuration / User Configuration:

- **Administrative Templates**: browse categories, filter, *Not configured / Enabled / Disabled* with the
  real option controls. Driven by ADMX/ADML, so any vendor's templates work.
  **Templates&hellip; &rarr; Download &amp; install** fetches Microsoft's official *Administrative Templates
  (.admx) for Windows 11* onto the DC and installs them in the domain **Central Store**
  (`SYSVOL\<domain>\Policies\PolicyDefinitions`), as you would by hand on Windows. They also cover Windows
  Server of the same generation. The tree then has the same top-level categories as `gpedit.msc`
  (Control Panel, Desktop, Network, Printers, Server, Start Menu and Taskbar, System, Windows Components,
  All Settings) with ~4,500 policies. A small built-in set is used until then. Needs `msitools` (installed on
  demand) and internet access on the DC, or copy the `.msi` over and use *An .msi file already on this
  server*. Other vendors' files can be uploaded; Samba's own templates install with one button.
- **Security Settings**: password and lockout policy; **Audit Policy** (legacy); **User Rights Assignment**
  (all 45 rights, with user/group lookup); **Security Options** (98 settings generated from Windows' own
  `sceregvl.inf` definitions, plus UAC/NTLM entries newer than that file); **Windows Defender Firewall
  with Advanced Security** (profile settings, logging, inbound and outbound rules); **Advanced Audit Policy
  Configuration** (all 52 subcategories, `audit.csv`).
- **Scripts**: startup/shutdown (computer), logon/logoff (user), including PowerShell.
- **Preferences**: Registry items (computer and user) and Drive Maps (user).

Nodes this tool cannot edit (Software Settings, Name Resolution Policy, Deployed Printers, Public Key
Policies, AppLocker, Software Restriction, IPsec, Network List Manager, Folder Redirection, Restricted
Groups, System Services, Registry/File System ACLs, wired/wireless, Kerberos, Event Log, QoS) are shown
with an explanation. Edit those from a Windows PC with RSAT (`gpmc.msc`); both use the standard SYSVOL
layout, so changes coexist.

Every change is written immediately (like GPME), bumps the GPO version and registers the client-side
extension so clients actually pick it up.

**How it works.** AD objects are written through the local `sam.ldb`; GPO files are written straight into
SYSVOL as root (case-insensitively, because Samba creates `MACHINE`/`USER` in upper case), and each new
file gets the GPO's NT ACL, which is what `samba-tool ntacl sysvolreset` does. This needs **no domain
credentials**. (Deliberate: the DC's machine account is *not* allowed to write into SYSVOL over SMB, so
`samba-tool gpo create/load -P` fails.)

Also not included: security filtering and delegation editing, WMI filters, GPO backup/restore, and
Preference types other than Registry and Drive Maps. Samba's AD DC enforces the *domain* password policy
from the directory (`samba-tool domain passwordsettings`), not from a GPO; GPO account policy only affects
local accounts of computers in the linked OU.

**Tested vs. not tested.** The AD/SYSVOL layer, Registry.pol (byte-identical to Samba's own serialiser),
GptTmpl.inf, audit.csv, scripts and the UI were tested against a real Samba 4.19 DC. **Not tested** on a
real Windows client: that the firewall-rule string format, the audit CSE GUID and the Preferences XML are
accepted (they follow Microsoft's documented formats), Samba 4.22 (Debian 13), and the live Microsoft
download. Verify with `gpresult /h report.html` on a client.


## Notes on specific tabs

- **Theme**: synced with Cockpit's own light/dark choice on a best-effort basis; override with the
  **Theme** button in the header (Auto &rarr; Light &rarr; Dark).
- **Credentials**: most of the module (user/group/computer/contact/OU list, show, create, delete, move,
  **all Group Policy and file-sharing diagnostics**) talks straight to the local AD database as root and
  needs no credentials. A smaller set of commands are genuine network/RPC operations (DRS replication
  status, FSMO transfer/seize, Sites, DNS management, delegation). For these the module first tries this
  DC's machine account (`-P`); if you set domain-administrator credentials via the **Credentials** button
  those are used instead. `--use-kerberos=off` is added so `samba-tool` authenticates with the password
  directly via NTLM instead of looking for a Kerberos ticket cache that does not exist in Cockpit's
  one-shot escalated shell. Credentials are kept in memory only.
- **DC targeting (`-H`)**: Sites and FSMO transfer/seize need to locate a DC via LDAP; the module passes this
  machine's own hostname as `-H` to bypass the DNS-SRV lookup ("Could not find DC for domain").
  `drs showrepl` does not accept `-H` and is excluded. Override via the `-H` field in the header.
- **Service selector** (top right) probes for `samba-ad-dc.service`, `samba.service` and `smbd.service`.
- **FSMO**: Transfer moves a role to *this* DC gracefully; Seize forces it and is for permanently lost holders only.
- **Domain functional level**: raising it is one-directional; the UI warns first.
- **DS ACLs / NT ACLs**: thin forms around `samba-tool dsacl` / `ntacl` taking raw SDDL.

## Development

There is no build step. Layout:

| File | Purpose |
|---|---|
| `manifest.json`, `index.html`, `style.css` | Cockpit registration, layout, styling |
| `samba-adc.js` | Core panels and shared helpers (`run()`, `openModal()`, `showAlert()` ...) |
| `gpo-core.js` | Pure logic: ADMX/ADML engine, GptTmpl.inf, scripts, audit.csv, firewall rules, GPP XML (browser + Node) |
| `gpo-builtin.js`, `gpo-catalogs.js` | Built-in templates; **generated** Security Options / rights / audit catalogs |
| `gpo-ui.js` | GPMC/GPME UI |
| `gpo_backend.py` | Root helper for AD + SYSVOL (JSON in, JSON out), also health check/repair and ADMX import |
| `sharing-ui.js`, `sharing_diag.py` | Diagnostics UI and backend; sign-in test |
| `vendor/` | SheetJS (Apache-2.0), vendored so spreadsheet import needs no network |
| `tools/gen_catalogs.py` | Regenerates `gpo-catalogs.js` from Windows' `sceregvl.inf` |
| `tests/` | Unit tests |

The Python helpers are run as root with `python3 -c <source>` and a JSON request on stdin; they are fetched
by the page, so they must be installed next to `index.html` (the installer does this).

```bash
cd samba-adc
npm ci            # test tooling only (jsdom); the module has no runtime dependencies
npm test          # 30 JS unit tests (ADMX engine, inf/csv/xml, firewall rules, built-in catalog)
python3 -m unittest discover -s tests -p 'test_*.py'   # parser tests; Registry.pol tests auto-skip without Samba
python3 ../scripts/check_package.py .                  # installer list vs. what the page loads, versions, changelog
```

Integration-tested (not in CI, needs a lab DC): the full UI driven through jsdom against a live Samba
AD DC, including a 4,500-policy ADMX store. If you change the GPO helpers, test on a throwaway domain.

Each panel follows the same shape: a `load*()`/`init*()` function registered in `PANEL_LOADERS`, a table/form
renderer, and modals built with `openModal()`. Adding another `samba-tool` subcommand means adding one panel
in that shape.

## License

MIT, see [`../LICENSE`](../LICENSE). Third-party notices: [`../NOTICE.md`](../NOTICE.md).

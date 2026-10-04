#!/usr/bin/env python3
"""
Generates gpo-catalogs.js (Security Options, User Rights, Advanced Audit subcategories).

Security Options come from Windows' own definition file, sceregvl.inf (registry path,
type, display type, choices, localisable names), so they are correct by construction.
Usage:  python3 tools/gen_catalogs.py /path/to/sceregvl.inf > gpo-catalogs.js
Source used: https://raw.githubusercontent.com/vanhauser-thc/audit_scripts/master/sceregvl.inf
Audit GUIDs: https://learn.microsoft.com/windows/win32/secauthz/auditing-constants
"""
import json, re, sys

raw = open(sys.argv[1], "rb").read()
txt = raw.decode("utf-16" if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8", "replace")
lines = txt.splitlines()
i_reg = next(i for i, l in enumerate(lines) if l.strip().lower() == "[register registry values]")
i_str = next(i for i, l in enumerate(lines) if l.strip().lower() == "[strings]")

strings = {}
for l in lines[i_str + 1:]:
    if l.lstrip().startswith(";") or "=" not in l:
        continue
    k, v = l.split("=", 1)
    strings[k.strip()] = v.strip().strip('"').strip()

def S(ref):
    m = re.fullmatch(r"%([^%]+)%", ref.strip())
    return strings.get(m.group(1), m.group(1)) if m else ref.strip()

KIND = {0: "bool", 1: "num", 2: "text", 3: "enum", 4: "multi", 5: "bitmask"}
opts = []
for l in lines[i_reg + 1:i_str]:
    l = l.strip()
    if not l or l.startswith(";") or "," not in l:
        continue
    parts = l.split(",", 3)
    if len(parts) < 4:
        continue
    path, typ, name, rest = parts[0].strip(), parts[1].strip(), parts[2].strip(), parts[3]
    if not typ.isdigit():
        continue
    m = re.match(r"(\d)(?:,(.*))?$", rest.strip())
    if not m:
        continue
    dt = int(m.group(1)); extra = m.group(2)
    o = {"path": path, "type": int(typ), "label": S(name), "kind": KIND[dt]}
    if dt in (3, 5) and extra:
        o["options"] = []
        # "0|%A%,1|%B%" -> value|label pairs separated by commas
        for pair in re.split(r",(?=\s*-?\d+\|)", extra):
            v, _, lab = pair.partition("|")
            o["options"].append([int(v.strip()), S(lab)])
    elif dt == 1 and extra:
        o["unit"] = S(extra).lower()
    opts.append(o)


# Display names for settings whose sceregvl.inf [Strings] are DLL resource references (@wsecedit.dll,-NNNN).
# Registry path, type and the numeric choice values still come from the INF; only the text is supplied here
# (names as published in Microsoft's "Security policy settings reference").
LSA_ = "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\"
SVC = "MACHINE\\System\\CurrentControlSet\\Services\\"
SYS_ = "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\"
WL = "MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\"
NAMES = {
 LSA_+"AuditBaseObjects": ("Audit: Audit the access of global system objects",),
 LSA_+"CrashOnAuditFail": ("Audit: Shut down system immediately if unable to log security audits",),
 LSA_+"DisableDomainCreds": ("Network access: Do not allow storage of passwords and credentials for network authentication",),
 LSA_+"EveryoneIncludesAnonymous": ("Network access: Let Everyone permissions apply to anonymous users",),
 LSA_+"ForceGuest": ("Network access: Sharing and security model for local accounts", {0: "Classic - local users authenticate as themselves", 1: "Guest only - local users authenticate as Guest"}),
 LSA_+"FullPrivilegeAuditing": ("Audit: Audit the use of Backup and Restore privilege",),
 LSA_+"LimitBlankPasswordUse": ("Accounts: Limit local account use of blank passwords to console logon only",),
 LSA_+"LmCompatibilityLevel": ("Network security: LAN Manager authentication level", {0: "Send LM & NTLM responses", 1: "Send LM & NTLM - use NTLMv2 session security if negotiated", 2: "Send NTLM response only", 3: "Send NTLMv2 response only", 4: "Send NTLMv2 response only. Refuse LM", 5: "Send NTLMv2 response only. Refuse LM & NTLM"}),
 LSA_+"MSV1_0\\NTLMMinClientSec": ("Network security: Minimum session security for NTLM SSP based (including secure RPC) clients", {524288: "Require NTLMv2 session security", 536870912: "Require 128-bit encryption"}),
 LSA_+"MSV1_0\\NTLMMinServerSec": ("Network security: Minimum session security for NTLM SSP based (including secure RPC) servers", {524288: "Require NTLMv2 session security", 536870912: "Require 128-bit encryption"}),
 LSA_+"NoLMHash": ("Network security: Do not store LAN Manager hash value on next password change",),
 LSA_+"RestrictAnonymous": ("Network access: Do not allow anonymous enumeration of SAM accounts and shares",),
 LSA_+"RestrictAnonymousSAM": ("Network access: Do not allow anonymous enumeration of SAM accounts",),
 LSA_+"SubmitControl": ("Domain controller: Allow server operators to schedule tasks",),
 LSA_+"SCENoApplyLegacyAuditPolicy": ("Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings",),
 "MACHINE\\System\\CurrentControlSet\\Control\\Print\\Providers\\LanMan Print Services\\Servers\\AddPrinterDrivers": ("Devices: Prevent users from installing printer drivers",),
 "MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths\\Machine": ("Network access: Remotely accessible registry paths and sub-paths",),
 "MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedExactPaths\\Machine": ("Network access: Remotely accessible registry paths",),
 "MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\Kernel\\ObCaseInsensitive": ("System objects: Require case insensitivity for non-Windows subsystems",),
 "MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\ClearPageFileAtShutdown": ("Shutdown: Clear virtual memory pagefile",),
 "MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\ProtectionMode": ("System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)",),
 "MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\SubSystems\\optional": ("System settings: Optional subsystems",),
 SVC+"LanManServer\\Parameters\\EnableSecuritySignature": ("Microsoft network server: Digitally sign communications (if client agrees)",),
 SVC+"LanManServer\\Parameters\\RequireSecuritySignature": ("Microsoft network server: Digitally sign communications (always)",),
 SVC+"LanManServer\\Parameters\\EnableForcedLogOff": ("Microsoft network server: Disconnect clients when logon hours expire",),
 SVC+"LanManServer\\Parameters\\AutoDisconnect": ("Microsoft network server: Amount of idle time required before suspending session", None, "minutes"),
 SVC+"LanManServer\\Parameters\\RestrictNullSessAccess": ("Network access: Restrict anonymous access to Named Pipes and Shares",),
 SVC+"LanManServer\\Parameters\\NullSessionPipes": ("Network access: Named Pipes that can be accessed anonymously",),
 SVC+"LanManServer\\Parameters\\NullSessionShares": ("Network access: Shares that can be accessed anonymously",),
 SVC+"LanmanWorkstation\\Parameters\\EnableSecuritySignature": ("Microsoft network client: Digitally sign communications (if server agrees)",),
 SVC+"LanmanWorkstation\\Parameters\\RequireSecuritySignature": ("Microsoft network client: Digitally sign communications (always)",),
 SVC+"LanmanWorkstation\\Parameters\\EnablePlainTextPassword": ("Microsoft network client: Send unencrypted password to third-party SMB servers",),
 SVC+"LDAP\\LDAPClientIntegrity": ("Network security: LDAP client signing requirements", {0: "None", 1: "Negotiate signing", 2: "Require signing"}),
 SVC+"Netlogon\\Parameters\\DisablePasswordChange": ("Domain member: Disable machine account password changes",),
 SVC+"Netlogon\\Parameters\\MaximumPasswordAge": ("Domain member: Maximum machine account password age", None, "days"),
 SVC+"Netlogon\\Parameters\\RefusePasswordChange": ("Domain controller: Refuse machine account password changes",),
 SVC+"Netlogon\\Parameters\\SignSecureChannel": ("Domain member: Digitally sign secure channel data (when possible)",),
 SVC+"Netlogon\\Parameters\\SealSecureChannel": ("Domain member: Digitally encrypt secure channel data (when possible)",),
 SVC+"Netlogon\\Parameters\\RequireSignOrSeal": ("Domain member: Digitally encrypt or sign secure channel data (always)",),
 SVC+"Netlogon\\Parameters\\RequireStrongKey": ("Domain member: Require strong (Windows 2000 or later) session key",),
 SVC+"NTDS\\Parameters\\LDAPServerIntegrity": ("Domain controller: LDAP server signing requirements", {1: "None", 2: "Require signing"}),
 SYS_+"DisableCAD": ("Interactive logon: Do not require CTRL+ALT+DEL",),
 SYS_+"DontDisplayLastUserName": ("Interactive logon: Do not display last user name",),
 SYS_+"DontDisplayLockedUserId": ("Interactive logon: Display user information when the session is locked", {1: "User display name, domain and user names", 2: "User display name only", 3: "Do not display user information"}),
 SYS_+"LegalNoticeCaption": ("Interactive logon: Message title for users attempting to log on",),
 SYS_+"LegalNoticeText": ("Interactive logon: Message text for users attempting to log on",),
 SYS_+"ScForceOption": ("Interactive logon: Require smart card",),
 SYS_+"ShutdownWithoutLogon": ("Shutdown: Allow system to be shut down without having to log on",),
 SYS_+"UndockWithoutLogon": ("Devices: Allow undock without having to log on",),
 "MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Setup\\RecoveryConsole\\SecurityLevel": ("Recovery console: Allow automatic administrative logon",),
 "MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Setup\\RecoveryConsole\\SetCommand": ("Recovery console: Allow floppy copy and access to all drives and all folders",),
 WL+"CachedLogonsCount": ("Interactive logon: Number of previous logons to cache (in case domain controller is not available)", None, "logons"),
 WL+"ForceUnlockLogon": ("Interactive logon: Require Domain Controller authentication to unlock workstation",),
 WL+"PasswordExpiryWarning": ("Interactive logon: Prompt user to change password before expiration", None, "days"),
 WL+"ScRemoveOption": ("Interactive logon: Smart card removal behavior", {0: "No Action", 1: "Lock Workstation", 2: "Force Logoff", 3: "Disconnect if a Remote Desktop Services session"}),
 "MACHINE\\Software\\Policies\\Microsoft\\Cryptography\\ForceKeyProtection": ("System cryptography: Force strong key protection for user keys stored on the computer", {0: "User input is not required when new keys are stored and used", 1: "User is prompted when the key is first used", 2: "User must enter a password every time they use a key"}),
 "MACHINE\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\AuthenticodeEnabled": ("System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies",),
 "MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\DCOM\\MachineLaunchRestriction": ("DCOM: Machine Launch Restrictions in Security Descriptor Definition Language (SDDL) syntax",),
 "MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\DCOM\\MachineAccessRestriction": ("DCOM: Machine Access Restrictions in Security Descriptor Definition Language (SDDL) syntax",),
}
NAMES = {k.lower(): v for k, v in NAMES.items()}
unresolved = []
fixed = []
for o in opts:
    if not o["label"].startswith("@"):
        fixed.append(o); continue
    n = NAMES.get(o["path"].lower())
    if not n:
        unresolved.append(o["path"]); continue
    o["label"] = n[0]
    if len(n) > 1 and n[1] and "options" in o:
        o["options"] = [[v, n[1].get(v, l)] for v, l in o["options"]]
    if len(n) > 2:
        o["unit"] = n[2]
    fixed.append(o)
for o in fixed:
    for pair in o.get("options", []):
        if str(pair[1]).startswith("@"):
            unresolved.append(o["path"] + " option " + str(pair[0]))
    if str(o.get("unit", "")).startswith("@"):
        o["unit"] = "units"
opts = fixed
if unresolved:
    sys.stderr.write("UNRESOLVED NAMES (refusing to emit):\n  " + "\n  ".join(unresolved) + "\n"); sys.exit(2)

def sup(path, typ, label, kind, **kw):
    d = {"path": path, "type": typ, "label": label, "kind": kind}; d.update(kw); return d
SYS = "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\"
LSA = "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\"
supplement = [
    sup(SYS + "EnableLUA", 4, "User Account Control: Run all administrators in Admin Approval Mode", "bool"),
    sup(SYS + "FilterAdministratorToken", 4, "User Account Control: Admin Approval Mode for the Built-in Administrator account", "bool"),
    sup(SYS + "ConsentPromptBehaviorAdmin", 4, "User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode", "enum",
        options=[[0, "Elevate without prompting"], [1, "Prompt for credentials on the secure desktop"], [2, "Prompt for consent on the secure desktop"], [3, "Prompt for credentials"], [4, "Prompt for consent"], [5, "Prompt for consent for non-Windows binaries"]]),
    sup(SYS + "ConsentPromptBehaviorUser", 4, "User Account Control: Behavior of the elevation prompt for standard users", "enum",
        options=[[0, "Automatically deny elevation requests"], [1, "Prompt for credentials on the secure desktop"], [3, "Prompt for credentials"]]),
    sup(SYS + "EnableInstallerDetection", 4, "User Account Control: Detect application installations and prompt for elevation", "bool"),
    sup(SYS + "EnableSecureUIAPaths", 4, "User Account Control: Only elevate UIAccess applications that are installed in secure locations", "bool"),
    sup(SYS + "PromptOnSecureDesktop", 4, "User Account Control: Switch to the secure desktop when prompting for elevation", "bool"),
    sup(SYS + "EnableVirtualization", 4, "User Account Control: Virtualize file and registry write failures to per-user locations", "bool"),
    sup(SYS + "ValidateAdminCodeSignatures", 4, "User Account Control: Only elevate executables that are signed and validated", "bool"),
    sup(SYS + "EnableUIADesktopToggle", 4, "User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop", "bool"),
    sup(SYS + "InactivityTimeoutSecs", 4, "Interactive logon: Machine inactivity limit", "num", unit="seconds", min=0, max=599940),
    sup(LSA + "FIPSAlgorithmPolicy\\Enabled", 4, "System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing", "bool"),
    sup(LSA + "RestrictRemoteSAM", 1, "Network access: Restrict clients allowed to make remote calls to SAM", "text"),
    sup(LSA + "MSV1_0\\RestrictSendingNTLMTraffic", 4, "Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers", "enum",
        options=[[0, "Allow all"], [1, "Audit all"], [2, "Deny all"]]),
    sup(LSA + "MSV1_0\\RestrictReceivingNTLMTraffic", 4, "Network security: Restrict NTLM: Incoming NTLM traffic", "enum",
        options=[[0, "Allow all"], [1, "Deny all domain accounts"], [2, "Deny all accounts"]]),
    sup(LSA + "MSV1_0\\AuditReceivingNTLMTraffic", 4, "Network security: Restrict NTLM: Audit Incoming NTLM Traffic", "enum",
        options=[[0, "Disable"], [1, "Enable auditing for domain accounts"], [2, "Enable auditing for all accounts"]]),
    sup("MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\SmbServerNameHardeningLevel", 4, "Microsoft network server: Server SPN target name validation level", "enum",
        options=[[0, "Off"], [1, "Accept if provided by client"], [2, "Required from client"]]),
]
have = {o["path"].lower() for o in opts}
for o in supplement:
    if o["path"].lower() not in have:
        opts.append(o); have.add(o["path"].lower())
for o in opts:
    lab = o["label"]
    o["group"] = lab.split(":", 1)[0].strip() if ":" in lab else "Other"
    if o["group"].startswith("MSS"): o["group"] = "MSS (Legacy)"
opts.sort(key=lambda o: (o["group"], o["label"].lower()))

PRIVS = [
 ("SeNetworkLogonRight","Access this computer from the network"),("SeTrustedCredManAccessPrivilege","Access Credential Manager as a trusted caller"),
 ("SeTcbPrivilege","Act as part of the operating system"),("SeMachineAccountPrivilege","Add workstations to domain"),
 ("SeIncreaseQuotaPrivilege","Adjust memory quotas for a process"),("SeInteractiveLogonRight","Allow log on locally"),
 ("SeRemoteInteractiveLogonRight","Allow log on through Remote Desktop Services"),("SeBackupPrivilege","Back up files and directories"),
 ("SeChangeNotifyPrivilege","Bypass traverse checking"),("SeSystemtimePrivilege","Change the system time"),("SeTimeZonePrivilege","Change the time zone"),
 ("SeCreatePagefilePrivilege","Create a pagefile"),("SeCreateTokenPrivilege","Create a token object"),("SeCreateGlobalPrivilege","Create global objects"),
 ("SeCreatePermanentPrivilege","Create permanent shared objects"),("SeCreateSymbolicLinkPrivilege","Create symbolic links"),("SeDebugPrivilege","Debug programs"),
 ("SeDenyNetworkLogonRight","Deny access to this computer from the network"),("SeDenyBatchLogonRight","Deny log on as a batch job"),
 ("SeDenyServiceLogonRight","Deny log on as a service"),("SeDenyInteractiveLogonRight","Deny log on locally"),
 ("SeDenyRemoteInteractiveLogonRight","Deny log on through Remote Desktop Services"),
 ("SeEnableDelegationPrivilege","Enable computer and user accounts to be trusted for delegation"),("SeRemoteShutdownPrivilege","Force shutdown from a remote system"),
 ("SeAuditPrivilege","Generate security audits"),("SeImpersonatePrivilege","Impersonate a client after authentication"),
 ("SeIncreaseWorkingSetPrivilege","Increase a process working set"),("SeIncreaseBasePriorityPrivilege","Increase scheduling priority"),
 ("SeLoadDriverPrivilege","Load and unload device drivers"),("SeLockMemoryPrivilege","Lock pages in memory"),("SeBatchLogonRight","Log on as a batch job"),
 ("SeServiceLogonRight","Log on as a service"),("SeSecurityPrivilege","Manage auditing and security log"),("SeRelabelPrivilege","Modify an object label"),
 ("SeSystemEnvironmentPrivilege","Modify firmware environment values"),("SeDelegateSessionUserImpersonatePrivilege","Obtain an impersonation token for another user in the same session"),
 ("SeManageVolumePrivilege","Perform volume maintenance tasks"),("SeProfileSingleProcessPrivilege","Profile single process"),("SeSystemProfilePrivilege","Profile system performance"),
 ("SeUndockPrivilege","Remove computer from docking station"),("SeAssignPrimaryTokenPrivilege","Replace a process level token"),("SeRestorePrivilege","Restore files and directories"),
 ("SeShutdownPrivilege","Shut down the system"),("SeSyncAgentPrivilege","Synchronize directory service data"),("SeTakeOwnershipPrivilege","Take ownership of files or other objects")]

AU = lambda n: "{0CCE%04X-69AE-11D9-BED3-505054503030}" % n
AUDIT = [
 ("System", [(0x9210,"Security State Change"),(0x9211,"Security System Extension"),(0x9212,"System Integrity"),(0x9213,"IPsec Driver"),(0x9214,"Other System Events")]),
 ("Logon/Logoff", [(0x9215,"Logon"),(0x9216,"Logoff"),(0x9217,"Account Lockout"),(0x9218,"IPsec Main Mode"),(0x9219,"IPsec Quick Mode"),(0x921a,"IPsec Extended Mode"),(0x921b,"Special Logon"),(0x921c,"Other Logon/Logoff Events"),(0x9243,"Network Policy Server")]),
 ("Object Access", [(0x921d,"File System"),(0x921e,"Registry"),(0x921f,"Kernel Object"),(0x9220,"SAM"),(0x9221,"Certification Services"),(0x9222,"Application Generated"),(0x9223,"Handle Manipulation"),(0x9224,"File Share"),(0x9225,"Filtering Platform Packet Drop"),(0x9226,"Filtering Platform Connection"),(0x9227,"Other Object Access Events")]),
 ("Privilege Use", [(0x9228,"Sensitive Privilege Use"),(0x9229,"Non Sensitive Privilege Use"),(0x922a,"Other Privilege Use Events")]),
 ("Detailed Tracking", [(0x922b,"Process Creation"),(0x922c,"Process Termination"),(0x922d,"DPAPI Activity"),(0x922e,"RPC Events")]),
 ("Policy Change", [(0x922f,"Audit Policy Change"),(0x9230,"Authentication Policy Change"),(0x9231,"Authorization Policy Change"),(0x9232,"MPSSVC Rule-Level Policy Change"),(0x9233,"Filtering Platform Policy Change"),(0x9234,"Other Policy Change Events")]),
 ("Account Management", [(0x9235,"User Account Management"),(0x9236,"Computer Account Management"),(0x9237,"Security Group Management"),(0x9238,"Distribution Group Management"),(0x9239,"Application Group Management"),(0x923a,"Other Account Management Events")]),
 ("DS Access", [(0x923b,"Directory Service Access"),(0x923c,"Directory Service Changes"),(0x923d,"Directory Service Replication"),(0x923e,"Detailed Directory Service Replication")]),
 ("Account Logon", [(0x923f,"Credential Validation"),(0x9240,"Kerberos Service Ticket Operations"),(0x9241,"Other Account Logon Events"),(0x9242,"Kerberos Authentication Service")]),
]
audit = [{"name": c, "subs": [{"name": n, "guid": AU(g)} for g, n in subs]} for c, subs in AUDIT]
out = "/* GENERATED by tools/gen_catalogs.py - do not edit by hand. */\n(function (root, factory) {\n  if (typeof module === 'object' && module.exports) module.exports = factory(); else root.GpoCatalogs = factory();\n})(typeof self !== 'undefined' ? self : this, function () {\n  return " + json.dumps({"secOptions": opts, "privileges": [[k, v] for k, v in PRIVS], "audit": audit}, indent=1, ensure_ascii=False) + ";\n});\n"
sys.stdout.write(out)
sys.stderr.write("security options: %d (%d from sceregvl.inf, %d supplemental) | privileges: %d | audit subcategories: %d\n" % (len(opts), len(opts) - len([o for o in supplement if True]), len(supplement), len(PRIVS), sum(len(c["subs"]) for c in audit)))

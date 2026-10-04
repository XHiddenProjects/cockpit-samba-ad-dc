"use strict";
/* ---------------------------------------------------------------------
 * Built-in Administrative Templates: a small set of widely used Windows
 * policies so the editor is useful before any ADMX files are imported.
 * Same model shape as GpoCore.parseAdmx() produces. For the full set,
 * use "Import ADMX templates" (copies Microsoft's .admx/.adml into the
 * domain Central Store, exactly like the Windows GPMC workflow).
 * ------------------------------------------------------------------- */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.GpoBuiltin = factory();
})(typeof self !== "undefined" ? self : this, function () {
  const NS = "SambaAdc.Builtin";
  const dec = (v) => ({ t: "decimal", v });
  const str = (v) => ({ t: "string", v });
  const cat = (id, name, parent) => ({ id: NS + ":" + id, name, parent: parent ? NS + ":" + parent : null });
  const P = (name, cls, category, displayName, explain, key, valueName, extra) => Object.assign({
    id: NS + ":" + name, name, cls, category: NS + ":" + category, displayName, explain, key, valueName: valueName || null,
    supportedOn: "Windows 10 / Windows Server 2016 or later", enabledValue: null, disabledValue: null, enabledList: null, disabledList: null, elements: []
  }, extra || {});
  const enumEl = (id, label, valueName, items, defaultItem, asString) => ({
    type: "enum", id, label, valueName, required: true, defaultItem: defaultItem || 0,
    items: items.map(([name, v]) => ({ name, value: asString ? str(String(v)) : dec(v), list: null }))
  });
  const decEl = (id, label, valueName, min, max, def, storeAsText) => ({ type: "decimal", id, label, valueName, required: true, min, max, defaultValue: def, storeAsText: !!storeAsText });
  const textEl = (id, label, valueName, def) => ({ type: "text", id, label, valueName, required: false, maxLength: 1023, expandable: false, defaultValue: def || "" });

  const WU = "Software\\Policies\\Microsoft\\Windows\\WindowsUpdate";
  const EXPL = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer";
  const SYS = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
  const SS = "Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop";
  const FW = "Software\\Policies\\Microsoft\\WindowsFirewall\\";
  const days = [["0 - Every day", 0], ["1 - Sunday", 1], ["2 - Monday", 2], ["3 - Tuesday", 3], ["4 - Wednesday", 4], ["5 - Thursday", 5], ["6 - Friday", 6], ["7 - Saturday", 7]];

  const categories = [
    cat("WinComp", "Windows Components"),
    cat("WU", "Windows Update", "WinComp"), cat("RDS", "Remote Desktop Services", "WinComp"),
    cat("Defender", "Microsoft Defender Antivirus", "WinComp"), cat("Firewall", "Windows Defender Firewall", "WinComp"),
    cat("AutoPlay", "AutoPlay Policies", "WinComp"), cat("DataColl", "Data Collection and Preview Builds", "WinComp"),
    cat("WER", "Windows Error Reporting", "WinComp"), cat("Explorer", "File Explorer", "WinComp"),
    cat("System", "System"), cat("Logon", "Logon", "System"), cat("CAD", "Ctrl+Alt+Del Options", "System"),
    cat("Network", "Network"), cat("DNSClient", "DNS Client", "Network"),
    cat("ControlPanel", "Control Panel"), cat("Personalization", "Personalization", "ControlPanel"),
    cat("Desktop", "Desktop"), cat("StartMenu", "Start Menu and Taskbar")
  ];

  const policies = [
    // ---- Computer ----
    P("AutoUpdateCfg", "Machine", "WU", "Configure Automatic Updates", "Specifies whether this computer receives security updates and other important downloads through the Windows automatic updating service.\n\nDisabled turns automatic updating off (NoAutoUpdate = 1).", WU + "\\AU", "NoAutoUpdate", {
      enabledValue: dec(0), disabledValue: dec(1), elements: [
        enumEl("AUOptions", "Configure automatic updating:", "AUOptions", [["2 - Notify for download and notify for install", 2], ["3 - Auto download and notify for install", 3], ["4 - Auto download and schedule the install", 4], ["5 - Allow local admin to choose setting", 5]], 2),
        enumEl("ScheduledInstallDay", "Scheduled install day:", "ScheduledInstallDay", days, 0),
        decEl("ScheduledInstallTime", "Scheduled install time (hour, 0-23):", "ScheduledInstallTime", 0, 23, 3)]
    }),
    P("CorpWuURL", "Machine", "WU", "Specify intranet Microsoft update service location", "Specifies an intranet server (for example WSUS) to host updates.", WU, null, {
      enabledList: [{ key: WU + "\\AU", valueName: "UseWUServer", value: dec(1) }], disabledList: [{ key: WU + "\\AU", valueName: "UseWUServer", value: dec(0) }],
      elements: [textEl("WUServer", "Set the intranet update service for detecting updates:", "WUServer"), textEl("WUStatusServer", "Set the intranet statistics server:", "WUStatusServer")]
    }),
    P("NoAutoReboot", "Machine", "WU", "No auto-restart with logged on users for scheduled automatic updates installations", "If enabled, Automatic Updates does not restart a computer automatically while users are logged on.", WU + "\\AU", "NoAutoRebootWithLoggedOnUsers"),
    P("TS_DenyConnections", "Machine", "RDS", "Allow users to connect remotely by using Remote Desktop Services", "Enabled allows remote connections; Disabled blocks them (fDenyTSConnections).", "Software\\Policies\\Microsoft\\Windows NT\\Terminal Services", "fDenyTSConnections", { enabledValue: dec(0), disabledValue: dec(1) }),
    P("TS_UserAuth", "Machine", "RDS", "Require user authentication for remote connections by using Network Level Authentication", "Requires Network Level Authentication (NLA) for Remote Desktop connections.", "Software\\Policies\\Microsoft\\Windows NT\\Terminal Services", "UserAuthentication"),
    P("DisableAntiSpyware", "Machine", "Defender", "Turn off Microsoft Defender Antivirus", "Enabled turns Microsoft Defender Antivirus off. Leave Not Configured unless another antivirus product manages protection.", "Software\\Policies\\Microsoft\\Windows Defender", "DisableAntiSpyware"),
    P("FW_Domain", "Machine", "Firewall", "Windows Defender Firewall: Protect all network connections (Domain profile)", "Turns the firewall on or off for the Domain profile.", FW + "DomainProfile", "EnableFirewall"),
    P("FW_Private", "Machine", "Firewall", "Windows Defender Firewall: Protect all network connections (Private profile)", "Turns the firewall on or off for the Private profile.", FW + "StandardProfile", "EnableFirewall"),
    P("FW_Public", "Machine", "Firewall", "Windows Defender Firewall: Protect all network connections (Public profile)", "Turns the firewall on or off for the Public profile.", FW + "PublicProfile", "EnableFirewall"),
    P("AllowTelemetry", "Machine", "DataColl", "Allow Diagnostic Data (Telemetry)", "Sets the amount of diagnostic data devices send to Microsoft.", "Software\\Policies\\Microsoft\\Windows\\DataCollection", null, {
      elements: [enumEl("AllowTelemetry", "Diagnostic data level:", "AllowTelemetry", [["0 - Security [Enterprise only]", 0], ["1 - Basic", 1], ["2 - Enhanced", 2], ["3 - Full", 3]], 1)]
    }),
    P("WER_Disable", "Machine", "WER", "Disable Windows Error Reporting", "Enabled stops Windows Error Reporting from sending reports.", "Software\\Policies\\Microsoft\\Windows\\Windows Error Reporting", "Disabled"),
    P("NoLockScreen", "Machine", "Personalization", "Do not display the lock screen", "Prevents the lock screen from appearing; sign-in goes straight to the logon screen.", "Software\\Policies\\Microsoft\\Windows\\Personalization", "NoLockScreen"),
    P("HideFastUserSwitching", "Machine", "Logon", "Hide entry points for Fast User Switching", "Hides the Switch User interface in the Logon UI, Start menu and Task Manager.", SYS, "HideFastUserSwitching"),
    P("DisableLLMNR", "Machine", "DNSClient", "Turn off multicast name resolution", "Enabled turns off LLMNR (Link-Local Multicast Name Resolution) on clients, a common hardening step.", "Software\\Policies\\Microsoft\\Windows NT\\DNSClient", "EnableMulticast", { enabledValue: dec(0), disabledValue: dec(1) }),
    // ---- Both ----
    P("NoDriveTypeAutoRun", "Both", "AutoPlay", "Turn off Autoplay", "Turns off Autoplay for the chosen drive types.", EXPL, null, {
      elements: [enumEl("NoDriveTypeAutoRun", "Turn off Autoplay on:", "NoDriveTypeAutoRun", [["CD-ROM and removable media drives", 145], ["All drives", 255]], 1)]
    }),
    // ---- User ----
    P("NoControlPanel", "User", "ControlPanel", "Prohibit access to Control Panel and PC settings", "Disables Control Panel and the Settings app.", EXPL, "NoControlPanel"),
    P("NoRun", "User", "StartMenu", "Remove Run menu from Start Menu", "Removes the Run command from the Start menu.", EXPL, "NoRun"),
    P("NoClose", "User", "StartMenu", "Remove and prevent access to the Shut Down, Restart, Sleep, and Hibernate commands", "Removes the power commands from the Start menu and Alt+F4 dialog.", EXPL, "NoClose"),
    P("NoWinKeys", "User", "Explorer", "Turn off Windows Key hotkeys", "Disables shortcuts that use the Windows logo key.", EXPL, "NoWinKeys"),
    P("NoDrives", "User", "Explorer", "Hide these specified drives in My Computer", "Hides the chosen drives in File Explorer. Users can still reach them by typing the path.", EXPL, null, {
      elements: [enumEl("NoDrives", "Pick one of the following combinations:", "NoDrives", [["Restrict A and B drives only", 3], ["Restrict C drive only", 4], ["Restrict D drive only", 8], ["Restrict A, B and C drives only", 7], ["Restrict A, B, C and D drives only", 15], ["Restrict all drives", 67108863], ["Do not restrict drives", 0]], 5)]
    }),
    P("DisableTaskMgr", "User", "CAD", "Remove Task Manager", "Prevents users from starting Task Manager.", SYS, "DisableTaskMgr"),
    P("DisableChangePassword", "User", "CAD", "Remove Change Password", "Removes the Change a password option from the Ctrl+Alt+Del screen.", SYS, "DisableChangePassword"),
    P("DisableLockWorkstation", "User", "CAD", "Remove Lock Computer", "Prevents users from locking the computer.", SYS, "DisableLockWorkstation"),
    P("DisableRegistryTools", "User", "System", "Prevent access to registry editing tools", "Blocks Regedit for the user.", SYS, "DisableRegistryTools"),
    P("ScreenSaveActive", "User", "Personalization", "Enable screen saver", "Enables or disables the screen saver.", SS, "ScreenSaveActive", { enabledValue: str("1"), disabledValue: str("0") }),
    P("ScreenSaverIsSecure", "User", "Personalization", "Password protect the screen saver", "Requires a password to unlock after the screen saver.", SS, "ScreenSaverIsSecure", { enabledValue: str("1"), disabledValue: str("0") }),
    P("ScreenSaveTimeOut", "User", "Personalization", "Screen saver timeout", "Seconds of inactivity before the screen saver starts.", SS, null, { elements: [decEl("ScreenSaveTimeOut", "Seconds:", "ScreenSaveTimeOut", 1, 86400, 900, true)] }),
    P("Wallpaper", "User", "Desktop", "Desktop Wallpaper", "Specifies the desktop background for all users. Use a local path or a UNC path readable by everyone.", SYS, null, {
      elements: [textEl("Wallpaper", "Wallpaper Name:", "Wallpaper"), enumEl("WallpaperStyle", "Wallpaper Style:", "WallpaperStyle", [["Center", 0], ["Tile", 1], ["Stretch", 2], ["Fit", 3], ["Fill", 4], ["Span", 5]], 4, true)]
    })
  ];

  return { model: { namespace: NS, categories, policies } };
});

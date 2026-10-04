const { JSDOM } = require("jsdom");
global.DOMParser = new JSDOM("").window.DOMParser;
const C = require("../gpo-core.js");
const assert = require("assert");
let n = 0; const t = (name, fn) => { fn(); n++; console.log("  ok  " + name); };

const ADMX = `<?xml version="1.0" encoding="utf-8"?>
<policyDefinitions revision="1.0" schemaVersion="1.0" xmlns="http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions">
  <policyNamespaces><target prefix="t" namespace="Test.Policies"/><using prefix="windows" namespace="Microsoft.Policies.Windows"/></policyNamespaces>
  <categories>
    <category name="Top" displayName="$(string.TopCat)"><parentCategory ref="windows:WindowsComponents"/></category>
    <category name="Sub" displayName="$(string.SubCat)"><parentCategory ref="Top"/></category>
  </categories>
  <policies>
    <policy name="AutoUpdate" class="Machine" displayName="$(string.AU)" explainText="$(string.AU_Explain)" presentation="$(presentation.AU)" key="Software\\Policies\\Test\\AU" valueName="NoAutoUpdate">
      <parentCategory ref="Sub"/><supportedOn ref="windows:SUPPORTED_Any"/>
      <enabledValue><decimal value="0"/></enabledValue><disabledValue><decimal value="1"/></disabledValue>
      <elements>
        <enum id="AUOptions" valueName="AUOptions" required="true"><item displayName="$(string.Opt2)"><value><decimal value="2"/></value></item><item displayName="$(string.Opt3)"><value><decimal value="3"/></value></item><item displayName="$(string.Opt4)"><value><decimal value="4"/></value></item></enum>
        <decimal id="Hour" valueName="Hour" minValue="0" maxValue="23"/>
        <text id="Server" valueName="Server" maxLength="200"/>
        <boolean id="Chk" valueName="Chk"/>
        <multiText id="MT" valueName="MT"/>
      </elements>
    </policy>
    <policy name="Intranet" class="Machine" displayName="$(string.Intra)" key="Software\\Policies\\Test\\WU">
      <parentCategory ref="Sub"/>
      <enabledList><item key="Software\\Policies\\Test\\WU\\AU" valueName="UseWUServer"><value><decimal value="1"/></value></item></enabledList>
      <disabledList><item key="Software\\Policies\\Test\\WU\\AU" valueName="UseWUServer"><value><decimal value="0"/></value></item></disabledList>
      <elements><text id="WUServer" valueName="WUServer"/></elements>
    </policy>
    <policy name="Simple" class="Both" displayName="$(string.Simple)" key="Software\\Policies\\Test\\S" valueName="Flag"><parentCategory ref="Top"/></policy>
    <policy name="StrVals" class="User" displayName="Screen saver" key="Software\\Policies\\Test\\Desk" valueName="Active"><parentCategory ref="Top"/>
      <enabledValue><string>1</string></enabledValue><disabledValue><string>0</string></disabledValue></policy>
    <policy name="DelOnEnable" class="User" displayName="Del" key="Software\\Policies\\Test\\D" valueName="X"><parentCategory ref="Top"/>
      <enabledValue><delete/></enabledValue><disabledValue><decimal value="1"/></disabledValue></policy>
    <policy name="Allow" class="Machine" displayName="List" key="Software\\Policies\\Test\\L"><parentCategory ref="Top"/>
      <elements><list id="Names" key="Software\\Policies\\Test\\L\\Names"/><list id="Pairs" key="Software\\Policies\\Test\\L\\Pairs" explicitValue="true" additive="true"/></elements></policy>
  </policies>
</policyDefinitions>`;
const ADML = `<?xml version="1.0" encoding="utf-8"?><policyDefinitionResources revision="1.0" schemaVersion="1.0"><displayName/><description/><resources>
<stringTable><string id="TopCat">Top Category</string><string id="SubCat">Sub Category</string><string id="AU">Configure Automatic Updates</string><string id="AU_Explain">Explains stuff.</string>
<string id="Opt2">2 - Notify</string><string id="Opt3">3 - Auto download</string><string id="Opt4">4 - Schedule</string><string id="Intra">Intranet server</string><string id="Simple">Simple flag</string></stringTable>
<presentationTable><presentation id="AU"><dropdownList refId="AUOptions" defaultItem="1">Configure automatic updating:</dropdownList><text>Install hour</text><decimalTextBox refId="Hour" defaultValue="3">Hour:</decimalTextBox><textBox refId="Server"><label>Server URL:</label><defaultValue>http://x</defaultValue></textBox><checkBox refId="Chk" defaultChecked="true">Enable chk</checkBox></presentation></presentationTable></resources></policyDefinitionResources>`;

const model = C.parseAdmx(ADMX, C.parseAdml(ADML));
const P = (n) => model.policies.find((p) => p.name === n);
console.log("ADMX parsing");
t("namespace + counts", () => { assert.equal(model.namespace, "Test.Policies"); assert.equal(model.policies.length, 6); assert.equal(model.categories.length, 2); });
t("string resolution", () => { assert.equal(P("AutoUpdate").displayName, "Configure Automatic Updates"); assert.equal(P("AutoUpdate").explain, "Explains stuff."); assert.equal(model.categories[0].name, "Top Category"); });
t("cross-namespace parent resolved", () => assert.equal(model.categories[0].parent, "Microsoft.Policies.Windows:WindowsComponents"));
t("presentation labels/defaults", () => { const e = P("AutoUpdate").elements; assert.equal(e[0].label, "Configure automatic updating:"); assert.equal(e[0].defaultItem, 1); assert.equal(e[1].defaultValue, 3); assert.equal(e[2].defaultValue, "http://x"); assert.equal(e[3].defaultChecked, true); assert.equal(e[2].label, "Server URL:"); });
t("enum items", () => assert.deepEqual(P("AutoUpdate").elements[0].items.map((i) => i.name), ["2 - Notify", "3 - Auto download", "4 - Schedule"]));

console.log("category tree");
t("tree (Machine) nests and orphan parent gets a placeholder", () => {
  const tree = C.buildTree([model], "Machine");
  assert.equal(tree.length, 1); assert.equal(tree[0].name, "WindowsComponents");
  const top = tree[0].children[0]; assert.equal(top.name, "Top Category");
  assert.deepEqual(top.policies.map((p) => p.name), ["Allow", "Simple"]);
  assert.equal(top.children[0].name, "Sub Category"); assert.equal(top.children[0].policies.length, 2);
});
t("class filter: User tree excludes Machine-only", () => {
  const top = C.buildTree([model], "User")[0].children[0];
  assert.deepEqual(top.policies.map((p) => p.name).sort(), ["DelOnEnable", "Simple", "StrVals"]); assert.equal(top.children.length, 0);
});

console.log("engine: enable / disable / not configured");
t("Enabled writes enabledValue(0) + elements, default item/value used", () => {
  const e = C.applyPolicy([], P("AutoUpdate"), "enabled", { AUOptions: 2, Hour: 5, Server: "srv", Chk: false, MT: ["a", "b"] });
  const g = (n) => e.find((x) => x.name === n);
  assert.deepEqual([g("NoAutoUpdate").type, g("NoAutoUpdate").data], [4, 0]);
  assert.equal(g("AUOptions").data, 4); assert.equal(g("Hour").data, 5); assert.equal(g("Server").data, "srv");
  assert.equal(g("Chk").data, 0); assert.deepEqual(g("MT").data, ["a", "b"]); assert.equal(g("MT").type, 7);
});
t("Enabled with no values uses presentation defaults", () => {
  const e = C.applyPolicy([], P("AutoUpdate"), "enabled", {});
  assert.equal(e.find((x) => x.name === "AUOptions").data, 3); assert.equal(e.find((x) => x.name === "Hour").data, 3); assert.equal(e.find((x) => x.name === "Chk").data, 1);
});
t("Disabled writes disabledValue(1) and **del. for elements", () => {
  const e = C.applyPolicy([], P("AutoUpdate"), "disabled");
  assert.equal(e.find((x) => x.name === "NoAutoUpdate").data, 1);
  for (const n of ["AUOptions", "Hour", "Server", "Chk", "MT"]) assert.ok(e.find((x) => x.name === "**del." + n), n);
});
t("Not configured removes everything incl. **del. variants, leaves others", () => {
  const other = { key: "Software\\Other", name: "Keep", type: 4, data: 9 };
  let e = C.applyPolicy([other], P("AutoUpdate"), "enabled", {});
  e = C.applyPolicy(e, P("AutoUpdate"), "disabled");
  e = C.applyPolicy(e, P("AutoUpdate"), "notconfigured");
  assert.deepEqual(e, [other]);
});
t("state round-trip: enabled", () => {
  const vals = { AUOptions: 2, Hour: 17, Server: "http://wsus", Chk: true, MT: ["x"] };
  const e = C.applyPolicy([], P("AutoUpdate"), "enabled", vals);
  const s = C.getPolicyState(e, P("AutoUpdate"));
  assert.equal(s.state, "enabled"); assert.deepEqual(s.values, vals);
});
t("state round-trip: disabled / notconfigured", () => {
  assert.equal(C.getPolicyState(C.applyPolicy([], P("AutoUpdate"), "disabled"), P("AutoUpdate")).state, "disabled");
  assert.equal(C.getPolicyState([], P("AutoUpdate")).state, "notconfigured");
});
t("default enabled=1 / disabled=0 when ADMX gives no values", () => {
  assert.equal(C.applyPolicy([], P("Simple"), "enabled")[0].data, 1);
  assert.equal(C.applyPolicy([], P("Simple"), "disabled")[0].data, 0);
  assert.equal(C.getPolicyState(C.applyPolicy([], P("Simple"), "disabled"), P("Simple")).state, "disabled");
});
t("enabledList / disabledList (policy without valueName)", () => {
  const en = C.applyPolicy([], P("Intranet"), "enabled", { WUServer: "http://wsus" });
  const use = en.find((x) => x.name === "UseWUServer"); assert.equal(use.data, 1); assert.equal(use.key, "Software\\Policies\\Test\\WU\\AU");
  assert.equal(C.getPolicyState(en, P("Intranet")).state, "enabled");
  const di = C.applyPolicy([], P("Intranet"), "disabled");
  assert.equal(di.find((x) => x.name === "UseWUServer").data, 0); assert.equal(C.getPolicyState(di, P("Intranet")).state, "disabled");
});
t("string-typed enabled/disabled values (screen saver style)", () => {
  const e = C.applyPolicy([], P("StrVals"), "enabled"); assert.deepEqual([e[0].type, e[0].data], [1, "1"]);
  assert.equal(C.getPolicyState(e, P("StrVals")).state, "enabled");
  assert.equal(C.getPolicyState(C.applyPolicy([], P("StrVals"), "disabled"), P("StrVals")).state, "disabled");
});
t("<delete/> enabledValue -> **del. and detected as enabled", () => {
  const e = C.applyPolicy([], P("DelOnEnable"), "enabled"); assert.equal(e[0].name, "**del.X");
  assert.equal(C.getPolicyState(e, P("DelOnEnable")).state, "enabled");
  assert.equal(C.getPolicyState(C.applyPolicy([], P("DelOnEnable"), "disabled"), P("DelOnEnable")).state, "disabled");
});
t("list element: clears first (non-additive), numbers items, round-trips", () => {
  const e = C.applyPolicy([], P("Allow"), "enabled", { Names: ["a.exe", "b.exe"], Pairs: [{ name: "k1", value: "v1" }] });
  assert.equal(e[0].name, "**delvals."); assert.deepEqual(e.filter((x) => x.key.endsWith("Names") && !x.name.startsWith("**")).map((x) => [x.name, x.data]), [["1", "a.exe"], ["2", "b.exe"]]);
  assert.ok(!e.some((x) => x.key.endsWith("Pairs") && x.name === "**delvals."));
  const s = C.getPolicyState(e, P("Allow")); assert.equal(s.state, "enabled"); assert.deepEqual(s.values, { Names: ["a.exe", "b.exe"], Pairs: [{ name: "k1", value: "v1" }] });
  assert.deepEqual(C.applyPolicy(e, P("Allow"), "notconfigured"), []);
});
t("applyPolicy does not mutate its input", () => { const src = []; C.applyPolicy(src, P("Simple"), "enabled"); assert.equal(src.length, 0); });

console.log("GptTmpl.inf");
const INF = "\uFEFF[Unicode]\r\nUnicode=yes\r\n[System Access]\r\nMinimumPasswordAge = 1\r\nMaximumPasswordAge = 42\r\nPasswordComplexity = 1\r\n[Registry Values]\r\nMACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DontDisplayLastUserName=4,1\r\nMACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LegalNoticeText=7,Line one,Line two\r\n[Privilege Rights]\r\nSeShutdownPrivilege = *S-1-5-32-544,*S-1-5-32-551\r\n[Version]\r\nsignature=\"$CHICAGO$\"\r\nRevision=1\r\n";
t("parse + get", () => {
  const m = C.parseInf(INF);
  assert.equal(C.infGet(m, "System Access", "MaximumPasswordAge"), "42");
  assert.deepEqual(C.infGetRegValue(m, "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DontDisplayLastUserName"), { type: 4, value: "1" });
  assert.equal(C.infGetRegValue(m, "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LegalNoticeText").value, "Line one,Line two");
  assert.deepEqual(C.infGetPrivilege(m, "SeShutdownPrivilege"), ["*S-1-5-32-544", "*S-1-5-32-551"]);
});
t("set/remove + serialize keeps Unicode first / Version last, drops empty sections", () => {
  const m = C.parseInf(INF);
  C.infSet(m, "System Access", "MinimumPasswordLength", 12); C.infSet(m, "System Access", "MaximumPasswordAge", null);
  C.infSetPrivilege(m, "SeShutdownPrivilege", undefined); C.infSet(m, "Kerberos Policy", "MaxClockSkew", 5);
  const out = C.serializeInf(m);
  assert.ok(out.startsWith("[Unicode]")); assert.ok(out.trimEnd().endsWith("Revision=1")); assert.ok(!out.includes("Privilege Rights")); assert.ok(out.includes("MinimumPasswordLength = 12")); assert.ok(!out.includes("MaximumPasswordAge"));
  assert.equal(C.infGet(C.parseInf(out), "Kerberos Policy", "MaxClockSkew"), "5");
});
t("empty file serializes to a valid minimal inf", () => { const o = C.serializeInf({ sections: [] }); assert.ok(o.startsWith("[Unicode]\r\nUnicode=yes")); assert.ok(o.includes("$CHICAGO$")); });
t("UTF-16LE BOM round trip", () => { const b = C.encodeUtf16le("[Unicode]\r\nUnicode=yes\r\nÄ"); assert.equal(b[0], 0xFF); assert.equal(C.decodeText(b), "[Unicode]\r\nUnicode=yes\r\nÄ"); assert.equal(C.decodeText(C.encodeUtf8("héllo")), "héllo"); });

console.log("scripts.ini");
t("parse/serialize", () => {
  const d = C.parseScriptsIni("[Startup]\r\n0CmdLine=a.bat\r\n0Parameters=-x\r\n1CmdLine=b.bat\r\n1Parameters=\r\n[Shutdown]\r\n0CmdLine=c.bat\r\n0Parameters=\r\n");
  assert.deepEqual(d.Startup, [{ cmd: "a.bat", params: "-x" }, { cmd: "b.bat", params: "" }]);
  d.Startup.splice(0, 1); assert.equal(C.parseScriptsIni(C.serializeScriptsIni(d)).Startup[0].cmd, "b.bat");
});

console.log("GPP");
t("Drive Maps XML round-trip + well-formed", () => {
  const xml = C.buildDrivesXml([{ action: "U", letter: "S", path: "\\\\dc1\\sales & co", label: "Sales", persistent: true }]);
  assert.ok(xml.includes("{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}")); assert.ok(xml.includes("&amp;"));
  const back = C.parseDrivesXml(xml); assert.equal(back[0].path, "\\\\dc1\\sales & co"); assert.equal(back[0].letter, "S"); assert.equal(back[0].persistent, true); assert.match(back[0].uid, /^\{[0-9A-F-]{36}\}$/);
});
t("Registry preference XML round-trip (DWORD hex)", () => {
  const xml = C.buildRegistryXml([{ action: "U", hive: "HKEY_LOCAL_MACHINE", key: "SOFTWARE\\X", name: "V", type: "REG_DWORD", value: 255 }, { action: "D", hive: "HKEY_CURRENT_USER", key: "Software\\Y", name: "", type: "REG_SZ", value: "" }]);
  assert.ok(xml.includes('value="000000FF"')); const b = C.parseRegistryXml(xml); assert.equal(b[0].value, 255); assert.equal(b[1].action, "D");
});
t("extNames", () => assert.deepEqual(C.extNames("[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]"), ["Administrative Templates (registry)", "Security Settings"]));
console.log("\n" + n + " tests passed");

console.log("audit.csv / firewall / prefilter");
t("audit.csv round trip (real-world sample incl. empty Machine Name)", () => {
  const csv = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value\r\n,System,Audit Security State Change,{0CCE9210-69AE-11D9-BED3-505054503030},Success,,1\r\n,System,Audit Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,,3\r\n";
  const rows = C.parseAuditCsv(csv); assert.equal(rows.length, 2); assert.equal(rows[1].value, 3); assert.equal(rows[0].guid, "{0CCE9210-69AE-11D9-BED3-505054503030}");
  assert.equal(C.buildAuditCsv(rows), csv);
  rows[0].value = 0; assert.ok(C.buildAuditCsv(rows).includes("No Auditing,,0"));
});
t("firewall rule parse/build round-trip with repeated keys and unknown tokens", () => {
  const s = "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=80|LPort=443|Profile=Domain|Profile=Private|RA4=10.0.0.0/255.0.0.0|App=C:\\x\\a.exe|Name=Web|Desc=d|EmbedCtxt=Grp|Edge=TRUE|";
  const r = C.parseFwRule(s); assert.deepEqual(r.lport, ["80", "443"]); assert.deepEqual(r.profiles, ["Domain", "Private"]); assert.equal(r.group, "Grp"); assert.deepEqual(r.extra, ["Edge=TRUE"]);
  assert.equal(C.buildFwRule(r), s.replace("Profile=Domain|Profile=Private|RA4=10.0.0.0/255.0.0.0|App=C:\\x\\a.exe", "Profile=Domain|Profile=Private|RA4=10.0.0.0/255.0.0.0|App=C:\\x\\a.exe"));
  const r2 = C.parseFwRule("v2.31|Action=Block|Active=FALSE|Dir=Out|Name=x|"); assert.equal(r2.active, false); assert.equal(C.buildFwRule(r2), "v2.31|Action=Block|Active=FALSE|Dir=Out|Name=x|");
  const r3 = C.parseFwRule("v2.31|Action=Allow|Active=TRUE|Dir=In|LPort=1,2,5000-5010|Name=a|b|"); assert.deepEqual(r3.lport, ["1", "2", "5000-5010"]);
  r.name = "a|b"; assert.ok(!C.buildFwRule(r).includes("a|b"));
});
t("policyMayBeConfigured pre-filter agrees with full state on every built-in policy", () => {
  const B = require("../gpo-builtin.js"); let entries = [];
  for (const p of B.model.policies.slice(0, 12)) entries = C.applyPolicy(entries, p, "enabled", {});
  const keys = C.keySet(entries);
  for (const p of B.model.policies) { const st = C.getPolicyState(entries, p).state; if (st !== "notconfigured") assert.ok(C.policyMayBeConfigured(p, keys), p.name); }
});
console.log("\n" + n + " tests passed (total)");

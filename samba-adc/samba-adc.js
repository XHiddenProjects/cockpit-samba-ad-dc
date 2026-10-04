"use strict";

/* ---------------------------------------------------------------------
 * Samba AD DC Cockpit module
 * Wraps samba-tool / testparm / systemctl / smb.conf editing.
 * ------------------------------------------------------------------- */

const SMB_CONF_PATH = "/etc/samba/smb.conf";
const SERVICE_CANDIDATES = ["samba-ad-dc.service", "samba.service", "smbd.service"];

const STATE = {
  service: null,           // chosen systemd unit name
  smbConfText: null,       // last-read smb.conf content
  smbConfFile: null,       // cockpit.file() handle
  baseDN: null,            // derived from "realm" in smb.conf
  realm: null,
  workgroup: null,
  creds: null,              // { user, pass } - kept in memory only, applied to any samba-tool call needing real auth
  dbUrl: null,              // optional "-H" override for samba-tool, e.g. "ldap://127.0.0.1" (user-set, applies to every call)
  selfFqdn: null,           // this machine's own hostname, auto-detected, used as a default -H for DC-discovery-dependent subcommands
  accountNamesCache: null,  // cached combined list of user+group names, for autocomplete
  userNamesCache: null,     // cached list of user names only, for ACL type resolution
  groupNamesCache: null,    // cached list of group names only, for ACL type resolution
  containerTree: null       // cached OU/container tree, for the move-object picker
};

/* ---------------- generic helpers ---------------- */

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function el(html) {
  const div = document.createElement("div");
  div.innerHTML = html.trim();
  return div.firstElementChild;
}

function showAlert(type, message, opts) {
  opts = opts || {};
  const area = document.getElementById("sadc-alert-area");
  const box = el(`<div class="alert ${type}"><span class="alert-close">&times;</span><div class="alert-msg"></div></div>`);
  box.querySelector(".alert-msg").textContent = message;
  box.querySelector(".alert-close").addEventListener("click", () => box.remove());
  area.prepend(box);
  if (type === "success" && !opts.sticky) {
    setTimeout(() => box.remove(), 4500);
  }
  return box;
}

function errText(err) {
  if (!err) return "Unknown error";
  let msg = typeof err === "string" ? err : (err.message || err.problem || JSON.stringify(err));
  const hint = hintForError(msg);
  return hint ? msg + "\n\n" + hint : msg;
}

/* GPO and Sites (and FSMO transfer/seize) subcommands need a DC located via
   "-H", bypassing samba-tool's own DNS-SRV discovery. "drs" does NOT accept
   "-H" at all (samba-tool rejects it with "no such option: -H") - its
   target, when needed, is a plain positional argument, and "showrepl" with
   no argument already defaults to this DC. */
function sambaSubcommandNeedsDcTarget(args) {
  const sub = args[1];
  if (sub === "gpo" || sub === "sites") return true;
  if (sub === "fsmo" && (args[2] === "transfer" || args[2] === "seize")) return true;
  return false;
}

/* GPO, DRS, Sites, and FSMO transfer/seize are genuine network/RPC
   operations and need real authentication one way or another. Everything
   else (user/group/computer/contact/ou/...) works fine as local root with
   no flags at all and must be left untouched. */
function sambaSubcommandNeedsRealAuth(args) {
  const sub = args[1];
  if (sub === "gpo" || sub === "drs" || sub === "sites") return true;
  if (sub === "fsmo" && (args[2] === "transfer" || args[2] === "seize")) return true;
  return false;
}

/* Run a command with superuser privileges. Returns a Promise<string stdout>.
   For samba-tool invocations:
   - if the person has set an explicit "-H" override in the header, it's
     applied to every samba-tool call EXCEPT "drs" (which doesn't accept
     "-H" at all).
   - otherwise, for the specific subcommands that always need to locate a
     DC via DNS (see sambaSubcommandNeedsDcTarget), this machine's own
     auto-detected FQDN (or 127.0.0.1 as a last resort) is used as "-H" so
     that DNS-SRV discovery is bypassed automatically.
   - appends "-U user%pass" when the person has saved credentials via the
     header's "Credentials" button; otherwise, for the specific subcommands
     that need real network authentication (see sambaSubcommandNeedsRealAuth)
     - GPO, DRS, Sites, FSMO transfer/seize - falls back to "-P"
     (--machine-pass) so they authenticate as this DC's own machine account
     instead of needing an interactive Kerberos ticket cache that doesn't
     exist in a one-shot escalated shell. Either way, "--use-kerberos=off"
     is added alongside so samba-tool authenticates with the supplied
     password directly via NTLM instead of first checking for an existing
     Kerberos ticket cache, which is what actually throws
     "krb5_cc_get_principal: no such file or directory" when none exists
     (the older "-k no" spelling of this flag is deprecated since Samba
     4.15 and now prints a warning, so this module uses the current one). Plain local commands
     (user/group/computer/contact/ou list/show/create/delete/move) are left
     completely untouched either way, since they work fine as local root
     with no flags at all. */
function run(args, opts) {
  opts = Object.assign({ superuser: "require", err: "message" }, opts || {});
  if (args[0] === "samba-tool") {
    const sub = args[1];
    const hasUrlFlag = args.some((a) => a === "-H" || a === "--URL" || /^--URL=/.test(a));
    if (!hasUrlFlag && sub !== "drs") {
      if (STATE.dbUrl) {
        args = [...args, "-H", STATE.dbUrl];
      } else if (sambaSubcommandNeedsDcTarget(args)) {
        args = [...args, "-H", `ldap://${STATE.selfFqdn || "127.0.0.1"}`];
      }
    }
    const hasUserCreds = args.some((a) => a === "-U" || /^-U./.test(a) || /^--username=/.test(a) || a === "-P" || a === "--machine-pass");
    if (!hasUserCreds) {
      if (STATE.creds) args = [...args, "-U", `${STATE.creds.user}%${STATE.creds.pass}`];
      else if (sambaSubcommandNeedsRealAuth(args)) args = [...args, "-P"];
      // Whenever we've supplied auth ourselves (either branch above), also
      // force NTLM instead of Kerberos with "-k no". Without this,
      // samba-tool's credential handling still tries to check for an
      // existing Kerberos ticket cache first even when a password/machine
      // password was supplied, and fails with
      // "krb5_cc_get_principal: no such file or directory" in Cockpit's
      // one-shot escalated shell, which has no ccache at all. "-k no"
      // skips that check and authenticates directly with the password.
      const justAddedCreds = args.some((a) => a === "-U" || /^-U./.test(a) || a === "-P");
      const hasKerbFlag = args.some((a) => a === "-k" || /^--kerberos/.test(a) || /^--use-kerberos/.test(a));
      if (justAddedCreds && !hasKerbFlag) args = [...args, "--use-kerberos=off"];
    }
  }
  return cockpit.spawn(args, opts);
}

async function detectSelfFqdn() {
  try {
    const out = await cockpit.spawn(["hostname", "-f"], { err: "message" });
    STATE.selfFqdn = out.trim();
  } catch (e) {
    try {
      const out2 = await cockpit.spawn(["hostname"], { err: "message" });
      STATE.selfFqdn = out2.trim();
    } catch (e2) { STATE.selfFqdn = null; }
  }
  const dbUrlInput = document.getElementById("sadc-db-url");
  if (dbUrlInput && STATE.selfFqdn) {
    dbUrlInput.placeholder = `auto (ldap://${STATE.selfFqdn} for GPO/DRS/Sites/FSMO)`;
  }
}
function hintForError(msg) {
  if (/cannot find dc for domain/i.test(msg)) {
    return "Hint: this is DNS-based DC discovery failing before any authentication happens, so credentials won't " +
      "fix it \u2014 only \"-H\" does. This module already tries this DC's own hostname automatically for GPO/DRS/" +
      "Sites/FSMO commands; if it's still failing, set the \"-H\" field in the header explicitly to ldap://127.0.0.1 " +
      "or this DC's real IP address, and separately check that this server's own DNS resolution (resolv.conf / " +
      "systemd-resolved) actually works.";
  }
  if (/failed to bind|bind.*uuid|NT_STATUS_(RPC|CONNECTION|OBJECT_NAME_NOT_FOUND)/i.test(msg)) {
    return "Hint: this is usually an RPC/DRS connectivity issue between this DC and the target \u2014 check the " +
      "service is actually running (top-right service badge), that DNS resolves the DC correctly, and try setting " +
      "domain administrator credentials via the \"Credentials\" button in the header.";
  }
  if (/NT_STATUS_LOGON_FAILURE|NT_STATUS_ACCESS_DENIED|invalid credentials|error 49/i.test(msg)) {
    return "Hint: this is an authentication failure. Set real domain administrator credentials via the " +
      "\"Credentials\" button in the header \u2014 this command needs an actual account, not just local root access.";
  }
  if (/krb5_cc_get_principal|failed_kerberos_login/i.test(msg)) {
    return "Hint: this command tried to check for an existing Kerberos ticket cache that doesn't exist in this " +
      "one-shot escalated shell. This module already adds \"--use-kerberos=off\" to force NTLM instead whenever it " +
      "supplies authentication itself \u2014 if you're still seeing this, you likely passed credentials some other " +
      "way (a manual \"-H\" with embedded auth, etc.); try clearing that and using the \"Credentials\" button instead.";
  }
  if (/no such option/i.test(msg)) {
    return "Hint: this samba-tool subcommand doesn't accept one of the flags this module tried to add automatically " +
      "(most likely \"-H\"). Please report this so it can be excluded for that subcommand.";
  }
  return null;
}

/* ---------------- autocomplete ---------------- */

async function getAccountNames(force) {
  await getTypedAccountNames(force);
  return STATE.accountNamesCache;
}

/* Fetches and caches user and group names SEPARATELY (not just merged),
   because knowing which is which matters for building correct ACLs
   ("u:name:rwx" vs "g:name:rwx" are not interchangeable). */
async function getTypedAccountNames(force) {
  if (STATE.userNamesCache && STATE.groupNamesCache && !force) {
    return { users: STATE.userNamesCache, groups: STATE.groupNamesCache };
  }
  try {
    const [usersOut, groupsOut] = await Promise.all([
      run(["samba-tool", "user", "list"]),
      run(["samba-tool", "group", "list"])
    ]);
    STATE.userNamesCache = Array.from(new Set(usersOut.split("\n").map((s) => s.trim()).filter(Boolean))).sort((a, b) => a.localeCompare(b));
    STATE.groupNamesCache = Array.from(new Set(groupsOut.split("\n").map((s) => s.trim()).filter(Boolean))).sort((a, b) => a.localeCompare(b));
  } catch (e) {
    STATE.userNamesCache = STATE.userNamesCache || [];
    STATE.groupNamesCache = STATE.groupNamesCache || [];
  }
  STATE.accountNamesCache = Array.from(new Set([...STATE.userNamesCache, ...STATE.groupNamesCache])).sort((a, b) => a.localeCompare(b));
  return { users: STATE.userNamesCache, groups: STATE.groupNamesCache };
}

/* Single-value autocomplete: turns a plain text input into a filtered
   suggestion dropdown. Selecting a suggestion fills the input. */
function attachSimpleAutocomplete(inputEl, getOptionsFn) {
  const wrap = document.createElement("div");
  wrap.className = "ac-wrap";
  inputEl.parentNode.insertBefore(wrap, inputEl);
  wrap.appendChild(inputEl);
  const suggestEl = document.createElement("div");
  suggestEl.className = "ac-suggestions";
  wrap.appendChild(suggestEl);

  let options = [];
  getOptionsFn().then((o) => { options = o; });

  function render(query) {
    const q = query.trim().toLowerCase();
    const matches = q ? options.filter((o) => o.toLowerCase().includes(q)).slice(0, 8) : options.slice(0, 8);
    if (matches.length === 0) { suggestEl.classList.remove("open"); suggestEl.innerHTML = ""; return; }
    suggestEl.innerHTML = matches.map((m) => `<div class="ac-suggestion" data-val="${escapeHtml(m)}">${escapeHtml(m)}</div>`).join("");
    suggestEl.classList.add("open");
    suggestEl.querySelectorAll(".ac-suggestion").forEach((row) => {
      row.addEventListener("mousedown", (ev) => {
        ev.preventDefault();
        inputEl.value = row.dataset.val;
        suggestEl.classList.remove("open");
      });
    });
  }
  inputEl.addEventListener("input", () => render(inputEl.value));
  inputEl.addEventListener("focus", () => render(inputEl.value));
  inputEl.addEventListener("blur", () => setTimeout(() => suggestEl.classList.remove("open"), 120));
}

/* Multi-value "tag picker" autocomplete: type to filter, click/Enter to add
   a chip, keep typing to add more. Returns { getValues(), reset() }. */
function createMultiTagPicker(mountEl, getOptionsFn, placeholder, initialValues) {
  mountEl.innerHTML = `
    <div class="ac-wrap">
      <div class="autocomplete-multi" id="${mountEl.id}-box">
        <div class="ac-tags" id="${mountEl.id}-tags"></div>
        <input type="text" id="${mountEl.id}-input" placeholder="${escapeHtml(placeholder || "Type a name\u2026")}" autocomplete="off">
      </div>
      <div class="ac-suggestions" id="${mountEl.id}-suggestions"></div>
    </div>
  `;
  const input = document.getElementById(`${mountEl.id}-input`);
  const tagsEl = document.getElementById(`${mountEl.id}-tags`);
  const suggestEl = document.getElementById(`${mountEl.id}-suggestions`);
  const selected = (initialValues || []).filter(Boolean).slice();
  let options = [];
  getOptionsFn().then((o) => { options = o; });

  function renderTags() {
    tagsEl.innerHTML = selected.map((v) => `<span class="tag">${escapeHtml(v)}<button type="button" data-val="${escapeHtml(v)}">&times;</button></span>`).join("");
    tagsEl.querySelectorAll("button").forEach((b) => {
      b.addEventListener("click", () => {
        const idx = selected.indexOf(b.dataset.val);
        if (idx !== -1) selected.splice(idx, 1);
        renderTags();
      });
    });
  }
  function renderSuggestions() {
    const q = input.value.trim().toLowerCase();
    const matches = (q ? options.filter((o) => o.toLowerCase().includes(q)) : options)
      .filter((o) => !selected.includes(o)).slice(0, 8);
    if (matches.length === 0) { suggestEl.classList.remove("open"); suggestEl.innerHTML = ""; return; }
    suggestEl.innerHTML = matches.map((m) => `<div class="ac-suggestion" data-val="${escapeHtml(m)}">${escapeHtml(m)}</div>`).join("");
    suggestEl.classList.add("open");
    suggestEl.querySelectorAll(".ac-suggestion").forEach((row) => {
      row.addEventListener("mousedown", (ev) => {
        ev.preventDefault();
        addValue(row.dataset.val);
      });
    });
  }
  function addValue(v) {
    v = v.trim();
    if (!v || selected.includes(v)) return;
    selected.push(v);
    input.value = "";
    renderTags();
    renderSuggestions();
    input.focus();
  }
  input.addEventListener("input", renderSuggestions);
  input.addEventListener("focus", renderSuggestions);
  input.addEventListener("blur", () => setTimeout(() => suggestEl.classList.remove("open"), 120));
  input.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" || ev.key === ",") {
      ev.preventDefault();
      if (input.value.trim()) addValue(input.value);
    } else if (ev.key === "Backspace" && !input.value && selected.length) {
      selected.pop();
      renderTags();
    }
  });
  renderTags();

  return { getValues: () => selected.slice(), reset: () => { selected.length = 0; renderTags(); } };
}

/* ---------------- bulk selection ---------------- */

/* Wires up a "select all" checkbox plus per-row ".row-check" checkboxes
   (each carrying the row's identifier in data-name) inside wrapEl, showing
   barEl (a .bulk-bar element) with a live count and one button per action
   whenever at least one row is checked. actions: [{ label, className, run(selectedNames) }] */
function wireBulkActions(wrapEl, barEl, actions) {
  function checks() { return Array.from(wrapEl.querySelectorAll(".row-check")); }
  const selectAll = wrapEl.querySelector(".select-all");
  function selected() { return checks().filter((c) => c.checked).map((c) => c.dataset.name); }
  function updateBar() {
    const sel = selected();
    if (sel.length === 0) { barEl.classList.remove("visible"); return; }
    barEl.classList.add("visible");
    const countEl = barEl.querySelector(".bulk-count");
    if (countEl) countEl.textContent = `${sel.length} selected`;
  }
  checks().forEach((c) => c.addEventListener("change", () => {
    updateBar();
    if (selectAll) selectAll.checked = checks().length > 0 && checks().every((x) => x.checked);
  }));
  if (selectAll) {
    selectAll.checked = false;
    selectAll.addEventListener("change", () => {
      checks().forEach((c) => { c.checked = selectAll.checked; });
      updateBar();
    });
  }
  barEl.innerHTML = `<span class="bulk-count"></span>` +
    actions.map((a, i) => `<button type="button" class="small ${a.className || ""}" data-idx="${i}">${escapeHtml(a.label)}</button>`).join("");
  barEl.querySelectorAll("button[data-idx]").forEach((btn) => {
    btn.addEventListener("click", () => actions[Number(btn.dataset.idx)].run(selected()));
  });
  updateBar();
}

function openModal(title, bodyHtml, opts) {
  opts = opts || {};
  const host = document.getElementById("modal-host");
  const backdrop = el(`
    <div class="modal-backdrop">
      <div class="modal ${opts.wide ? "wide" : ""}">
        <div class="modal-header">
          <h3></h3>
          <button class="modal-close">&times;</button>
        </div>
        <div class="modal-body"></div>
        <div class="modal-footer"></div>
      </div>
    </div>`);
  backdrop.querySelector("h3").textContent = title;
  backdrop.querySelector(".modal-body").innerHTML = bodyHtml;
  const footer = backdrop.querySelector(".modal-footer");

  function close() { backdrop.remove(); }
  backdrop.querySelector(".modal-close").addEventListener("click", close);
  backdrop.addEventListener("click", (e) => { if (e.target === backdrop) close(); });

  (opts.buttons || []).forEach((btn) => {
    const b = document.createElement("button");
    b.textContent = btn.label;
    b.className = btn.className || "";
    b.addEventListener("click", () => btn.onClick(close, backdrop));
    footer.appendChild(b);
  });

  host.appendChild(backdrop);
  return { close, node: backdrop };
}

function confirmModal(message, onConfirm) {
  openModal("Confirm", `<p>${escapeHtml(message)}</p>`, {
    buttons: [
      { label: "Cancel", onClick: (close) => close() },
      { label: "Confirm", className: "danger", onClick: (close) => { close(); onConfirm(); } }
    ]
  });
}

/* ---------------- tabs ---------------- */

function initTabs() {
  const tabs = document.querySelectorAll(".sadc-tab");
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      tabs.forEach((t) => t.classList.remove("active"));
      document.querySelectorAll(".sadc-panel").forEach((p) => p.classList.remove("active"));
      tab.classList.add("active");
      const panel = document.getElementById("panel-" + tab.dataset.panel);
      panel.classList.add("active");
      loadPanel(tab.dataset.panel);
    });
  });
}

const PANEL_LOADERS = {
  overview: loadOverview,
  domain: loadDomain,
  forest: loadForest,
  fsmo: loadFsmo,
  sites: loadSites,
  dns: loadDns,
  users: loadUsers,
  groups: loadGroups,
  computers: loadComputers,
  contacts: loadContacts,
  ous: loadOUs,
  gpo: () => GpoUI.load(),
  spn: initSpn,
  delegation: initDelegation,
  acls: initAcls,
  time: initTime,
  shares: loadShares,
  config: loadConfig
};
const LOADED_ONCE = {};

function loadPanel(name, force) {
  if (LOADED_ONCE[name] && !force) return;
  LOADED_ONCE[name] = true;
  PANEL_LOADERS[name] && PANEL_LOADERS[name]();
}

/* ---------------- service detection ---------------- */

async function detectService() {
  const select = document.getElementById("sadc-service-select");
  select.innerHTML = "";
  const found = [];
  for (const unit of SERVICE_CANDIDATES) {
    try {
      const out = await run(["systemctl", "show", "-p", "LoadState,ActiveState,SubState", "--value", unit]);
      const [loadState, activeState, subState] = out.trim().split("\n");
      if (loadState && loadState !== "not-found") {
        found.push({ unit, loadState, activeState, subState });
      }
    } catch (e) { /* ignore missing unit */ }
  }
  if (found.length === 0) {
    document.getElementById("sadc-service-badge").textContent = "no samba service unit found";
    document.getElementById("sadc-service-badge").className = "badge err";
    return;
  }
  found.forEach((f) => {
    const opt = document.createElement("option");
    opt.value = f.unit;
    opt.textContent = f.unit;
    select.appendChild(opt);
  });
  // prefer an active one, else the first candidate present
  const active = found.find((f) => f.activeState === "active") || found[0];
  select.value = active.unit;
  STATE.service = active.unit;
  updateServiceBadge(active);

  select.onchange = async () => {
    STATE.service = select.value;
    const f = found.find((x) => x.unit === select.value);
    updateServiceBadge(f);
  };
}

function updateServiceBadge(f) {
  const badge = document.getElementById("sadc-service-badge");
  if (!f) { badge.textContent = "unknown"; badge.className = "badge neutral"; return; }
  badge.textContent = `${f.unit}: ${f.activeState}/${f.subState}`;
  badge.className = "badge " + (f.activeState === "active" ? "ok" : (f.activeState === "failed" ? "err" : "warn"));
}

async function restartService() {
  if (!STATE.service) return;
  const btn = document.getElementById("sadc-service-restart");
  btn.disabled = true;
  try {
    await run(["systemctl", "restart", STATE.service]);
    showAlert("success", `${STATE.service} restarted.`);
    await detectService();
  } catch (e) {
    showAlert("error", `Failed to restart ${STATE.service}: ${errText(e)}`);
  } finally {
    btn.disabled = false;
  }
}

/* ---------------- OVERVIEW ---------------- */

async function loadOverview() {
  const domainBox = document.getElementById("ov-domain-info");
  const drsBox = document.getElementById("ov-drs");

  domainBox.innerHTML = `<span class="spinner"></span> Loading&hellip;`;
  try {
    const out = await run(["samba-tool", "domain", "info", "127.0.0.1"]);
    domainBox.innerHTML = `<pre class="ldif">${escapeHtml(out.trim())}</pre>`;
    document.getElementById("sadc-domain-line").textContent = out.split("\n")[0] || "";
  } catch (e) {
    domainBox.innerHTML = `<div class="alert error">${escapeHtml(errText(e))}</div>`;
  }

  drsBox.innerHTML = `<span class="spinner"></span> Loading&hellip;`;
  try {
    const out = await run(["samba-tool", "drs", "showrepl"]);
    drsBox.innerHTML = `<pre class="ldif">${escapeHtml(out.trim())}</pre>`;
  } catch (e) {
    drsBox.innerHTML = `<div class="alert error">${escapeHtml(errText(e))}</div>`;
  }
}

/* ---------------- generic "move object" modal ---------------- */

/* Sequentially runs actionFn(item) for every item, collecting per-item
   success/failure rather than stopping at the first error - used by both
   the move picker and bulk row actions, so one bad item in a multi-select
   doesn't hide what happened to the rest. */
async function bulkRun(items, actionFn) {
  const results = [];
  for (const item of items) {
    try { await actionFn(item); results.push({ item, ok: true }); }
    catch (e) { results.push({ item, ok: false, error: errText(e) }); }
  }
  return results;
}

function summarizeBulk(results, verb) {
  const failed = results.filter((r) => !r.ok);
  const n = results.length;
  if (failed.length === 0) {
    showAlert("success", `${verb} ${n} item${n === 1 ? "" : "s"}.`);
  } else if (failed.length === n) {
    showAlert("error", `${verb} failed for all ${n} item(s). ${failed.map((f) => `${f.item}: ${f.error}`).join("; ")}`, { sticky: true });
  } else {
    showAlert("error", `${verb} succeeded for ${n - failed.length}/${n}. Failed: ${failed.map((f) => `${f.item} (${f.error})`).join("; ")}`, { sticky: true });
  }
}

/* ---------------- OU/container tree (for the move picker) ---------------- */

async function getContainerTree(force) {
  if (STATE.containerTree && !force) return STATE.containerTree;
  if (!STATE.baseDN) { try { await readSmbConf(); } catch (e) { /* ignore */ } }
  let dns = [];
  try {
    const out = await run(["samba-tool", "ou", "list"]);
    dns = out.split("\n").map((s) => s.trim()).filter(Boolean);
  } catch (e) { /* still show the well-known default containers below */ }
  if (STATE.baseDN) {
    dns.push(`CN=Users,${STATE.baseDN}`);
    dns.push(`CN=Computers,${STATE.baseDN}`);
    dns.push(`CN=Builtin,${STATE.baseDN}`);
  }
  STATE.containerTree = buildContainerTree(dns, STATE.baseDN || "");
  return STATE.containerTree;
}

function buildContainerTree(dns, rootDn) {
  const nodes = new Map();
  function ensureNode(dn) {
    if (!nodes.has(dn)) {
      const firstRdn = dn.split(",")[0] || dn;
      const label = firstRdn.includes("=") ? firstRdn.split("=").slice(1).join("=") : firstRdn;
      nodes.set(dn, { dn, label, children: [] });
    }
    return nodes.get(dn);
  }
  const root = ensureNode(rootDn);
  root.label = "Domain root";
  Array.from(new Set(dns)).sort((a, b) => a.length - b.length).forEach((dn) => {
    if (!dn || dn === rootDn) return;
    const node = ensureNode(dn);
    const commaIdx = dn.indexOf(",");
    const parentDn = (commaIdx === -1 ? rootDn : dn.slice(commaIdx + 1)) || rootDn;
    const parentNode = ensureNode(parentDn);
    if (!parentNode.children.includes(node)) parentNode.children.push(node);
  });
  (function sortChildren(node) {
    node.children.sort((a, b) => a.label.localeCompare(b.label));
    node.children.forEach(sortChildren);
  })(root);
  return root;
}

function renderTreeNodeHtml(node, expanded) {
  const hasChildren = node.children.length > 0;
  return `
    <li class="tree-node">
      <div class="tree-row" data-dn="${escapeHtml(node.dn)}">
        <span class="tree-toggle ${hasChildren ? "" : "tree-toggle-empty"}">${hasChildren ? (expanded ? "\u25be" : "\u25b8") : ""}</span>
        <span class="tree-label">${escapeHtml(node.label)}</span>
      </div>
      ${hasChildren ? `<ul class="tree-children${expanded ? "" : " collapsed"}">${node.children.map((c) => renderTreeNodeHtml(c, false)).join("")}</ul>` : ""}
    </li>`;
}

/* A visual OU/container picker for moving one or more directory objects,
   so picking a destination doesn't require typing (or even knowing) an LDAP
   DN. Falls back to a manual DN field for anything the tree doesn't cover
   (e.g. a custom container that isn't an OU). names is always an array -
   pass a single-item array for a single move; buildArgs(name, targetDn)
   returns the full samba-tool argv for moving that one item. */
function openMoveModal({ kind, names, buildArgs, onDone }) {
  const isBulk = names.length > 1;
  const title = isBulk ? `Move ${names.length} ${kind}s` : `Move ${kind}: ${names[0]}`;
  const modal = openModal(title, `
    <div class="form-row">
      <label>Destination</label>
      <div class="tree-picker" id="mv-tree"><span class="spinner"></span> Loading directory&hellip;</div>
    </div>
    <p class="muted" id="mv-selected-hint">No destination selected yet &mdash; click an item in the tree above.</p>
    <div class="form-row">
      <button type="button" id="mv-manual-toggle" class="link small">Type a DN instead</button>
      <div id="mv-manual-wrap" style="display:none;margin-top:8px">
        <input type="text" id="mv-target-manual" placeholder="OU=Sales,DC=example,DC=com">
      </div>
    </div>
  `, {
    wide: true,
    buttons: [
      { label: "Cancel", onClick: (close) => close() },
      {
        label: isBulk ? `Move ${names.length} items` : "Move", className: "primary", onClick: async (close, node) => {
          const manualWrap = node.querySelector("#mv-manual-wrap");
          const manualVisible = manualWrap && manualWrap.style.display !== "none";
          const manualValue = node.querySelector("#mv-target-manual").value.trim();
          const target = (manualVisible && manualValue) ? manualValue : (node.dataset.selectedDn || "");
          if (!target) { showAlert("error", "Pick a destination in the tree, or type a DN, first."); return; }
          close();
          const results = await bulkRun(names, (n) => run(buildArgs(n, target)));
          summarizeBulk(results, "Move");
          if (onDone) onDone();
        }
      }
    ]
  });

  const treeMount = modal.node.querySelector("#mv-tree");
  const hint = modal.node.querySelector("#mv-selected-hint");
  getContainerTree().then((tree) => {
    treeMount.innerHTML = `<ul class="tree-root">${renderTreeNodeHtml(tree, true)}</ul>`;
    treeMount.addEventListener("click", (e) => {
      const toggle = e.target.closest(".tree-toggle:not(.tree-toggle-empty)");
      if (toggle) {
        const li = toggle.closest("li");
        const childUl = li.querySelector(":scope > ul.tree-children");
        if (childUl) {
          const collapsed = childUl.classList.toggle("collapsed");
          toggle.textContent = collapsed ? "\u25b8" : "\u25be";
        }
        return;
      }
      const row = e.target.closest(".tree-row");
      if (row) {
        treeMount.querySelectorAll(".tree-row.selected").forEach((r) => r.classList.remove("selected"));
        row.classList.add("selected");
        modal.node.dataset.selectedDn = row.dataset.dn;
        hint.textContent = `Selected: ${row.dataset.dn}`;
      }
    });
  }).catch((e) => {
    treeMount.innerHTML = `<div class="alert error">Could not load the directory tree: ${escapeHtml(errText(e))}</div>`;
  });

  modal.node.querySelector("#mv-manual-toggle").addEventListener("click", () => {
    const wrap = modal.node.querySelector("#mv-manual-wrap");
    wrap.style.display = wrap.style.display === "none" ? "block" : "none";
  });
}

/* ---------------- DOMAIN ---------------- */

async function loadDomain() {
  document.getElementById("domain-info-refresh").onclick = loadDomainInfo;
  document.getElementById("domain-level-refresh").onclick = loadDomainLevel;
  document.getElementById("domain-pwd-refresh").onclick = loadDomainPasswordSettings;
  document.getElementById("domain-level-raise-domain").onclick = () => raiseDomainLevel("domain");
  document.getElementById("domain-level-raise-forest").onclick = () => raiseDomainLevel("forest");
  document.getElementById("domain-pwd-form").addEventListener("submit", onDomainPasswordSubmit);
  loadDomainInfo();
  loadDomainLevel();
  loadDomainPasswordSettings();
}

async function loadDomainInfo() {
  const box = document.getElementById("domain-info-box");
  box.innerHTML = `<span class="spinner"></span> Loading&hellip;`;
  try {
    const out = await run(["samba-tool", "domain", "info", "127.0.0.1"]);
    box.innerHTML = `<pre class="ldif">${escapeHtml(out.trim())}</pre>`;
  } catch (e) { box.innerHTML = `<div class="alert error">${escapeHtml(errText(e))}</div>`; }
}

async function loadDomainLevel() {
  const box = document.getElementById("domain-level-box");
  box.innerHTML = `<span class="spinner"></span> Loading&hellip;`;
  try {
    const out = await run(["samba-tool", "domain", "level", "show"]);
    box.innerHTML = `<pre class="ldif">${escapeHtml(out.trim())}</pre>`;
  } catch (e) { box.innerHTML = `<div class="alert error">${escapeHtml(errText(e))}</div>`; }
}

async function raiseDomainLevel(scope) {
  const level = document.getElementById("domain-level-target").value;
  confirmModal(`Raise the ${scope} functional level to ${level}? This cannot be undone.`, async () => {
    try {
      const flag = scope === "domain" ? "--domain-level=" + level : "--forest-level=" + level;
      await run(["samba-tool", "domain", "level", "raise", flag]);
      showAlert("success", `${scope} functional level raised to ${level}.`);
      loadDomainLevel();
    } catch (e) { showAlert("error", errText(e), { sticky: true }); }
  });
}

async function loadDomainPasswordSettings() {
  const box = document.getElementById("domain-pwd-box");
  box.innerHTML = `<span class="spinner"></span> Loading&hellip;`;
  try {
    const out = await run(["samba-tool", "domain", "passwordsettings", "show"]);
    box.innerHTML = `<pre class="ldif">${escapeHtml(out.trim())}</pre>`;
    prefillPasswordForm(out);
  } catch (e) { box.innerHTML = `<div class="alert error">${escapeHtml(errText(e))}</div>`; }
}

/* Fill the password-settings form with the domain's current values, parsed
   loosely from "domain passwordsettings show" output, so editing one field
   doesn't require re-typing the others from scratch. */
function prefillPasswordForm(text) {
  // Line-based extraction: test each line for the keyword pattern, then
  // take everything after that line's first colon as the value. Much more
  // robust than one combined regex against real samba-tool output, where
  // extra words/units commonly sit between the keyword and the colon
  // (e.g. "Reset account lockout after (mins): 30").
  function grab(keywordTestRegex) {
    const re = new RegExp(keywordTestRegex, "i");
    for (const line of text.split("\n")) {
      const idx = line.indexOf(":");
      if (idx !== -1 && re.test(line.slice(0, idx))) {
        return line.slice(idx + 1).trim();
      }
    }
    return "";
  }
  function grabNumber(keywordRegex) {
    const v = grab(keywordRegex);
    const m = v.match(/-?\d+/);
    return m ? m[0] : "";
  }
  const complexityRaw = grab("complexity").toLowerCase();
  const complexitySel = document.getElementById("pw-complexity");
  if (/on|enabled|required/.test(complexityRaw)) complexitySel.value = "on";
  else if (/off|disabled/.test(complexityRaw)) complexitySel.value = "off";

  const setIfEmpty = (id, val) => {
    const el2 = document.getElementById(id);
    if (val !== "" && !el2.dataset.userEdited) el2.value = val;
  };
  setIfEmpty("pw-minlen", grabNumber("minimum password length"));
  setIfEmpty("pw-history", grabNumber("history"));
  setIfEmpty("pw-minage", grabNumber("minimum password age"));
  setIfEmpty("pw-maxage", grabNumber("maximum password age"));
  setIfEmpty("pw-lockthresh", grabNumber("lockout threshold"));
  setIfEmpty("pw-lockdur", grabNumber("lockout duration"));
  setIfEmpty("pw-lockreset", grabNumber("reset.*lockout|lockout.*reset"));

  // Track manual edits so a later refresh doesn't clobber unsaved changes.
  ["pw-minlen", "pw-history", "pw-minage", "pw-maxage", "pw-lockthresh", "pw-lockdur", "pw-lockreset"].forEach((id) => {
    const el2 = document.getElementById(id);
    if (!el2.dataset.bound) {
      el2.dataset.bound = "1";
      el2.addEventListener("input", () => { el2.dataset.userEdited = "1"; });
    }
  });
}

async function onDomainPasswordSubmit(ev) {
  ev.preventDefault();
  const args = ["samba-tool", "domain", "passwordsettings", "set"];
  const map = [
    ["pw-complexity", "--complexity"],
    ["pw-minlen", "--min-pwd-length"],
    ["pw-history", "--history-length"],
    ["pw-minage", "--min-pwd-age"],
    ["pw-maxage", "--max-pwd-age"],
    ["pw-lockthresh", "--account-lockout-threshold"],
    ["pw-lockdur", "--account-lockout-duration"],
    ["pw-lockreset", "--reset-account-lockout-after"]
  ];
  let any = false;
  for (const [id, flag] of map) {
    const el2 = document.getElementById(id);
    const v = el2.value;
    if (v !== "" && v !== null) { args.push(flag + "=" + v); any = true; }
  }
  if (!any) { showAlert("error", "Set at least one field before applying."); return; }
  try {
    await run(args);
    showAlert("success", "Password settings updated.");
    loadDomainPasswordSettings();
  } catch (e) { showAlert("error", errText(e), { sticky: true }); }
}

/* ---------------- FOREST ---------------- */

async function loadForest() {
  document.getElementById("forest-ds-refresh").onclick = loadForestDs;
  document.getElementById("forest-ds-set").onclick = async () => {
    const v = document.getElementById("forest-ds-value").value.trim();
    try {
      await run(["samba-tool", "forest", "directory_service", "dsheuristics", v]);
      showAlert("success", "dsHeuristics updated.");
      loadForestDs();
    } catch (e) { showAlert("error", errText(e), { sticky: true }); }
  };
  loadForestDs();
}

async function loadForestDs() {
  const box = document.getElementById("forest-ds-box");
  box.innerHTML = `<span class="spinner"></span> Loading&hellip;`;
  try {
    const out = await run(["samba-tool", "forest", "directory_service", "show"]);
    box.innerHTML = `<pre class="ldif">${escapeHtml(out.trim())}</pre>`;
  } catch (e) { box.innerHTML = `<div class="alert error">${escapeHtml(errText(e))}</div>`; }
}

/* ---------------- FSMO ---------------- */

async function loadFsmo() {
  document.getElementById("fsmo-refresh").onclick = loadFsmoShow;
  document.getElementById("fsmo-transfer").onclick = async () => {
    const role = document.getElementById("fsmo-role").value;
    const target = document.getElementById("fsmo-target").value.trim();
    const args = ["samba-tool", "fsmo", "transfer", "--role=" + role];
    if (target) args.push("-H", `ldap://${target}`);
    try {
      await run(args);
      showAlert("success", `Transferred ${role} role.`);
      loadFsmoShow();
    } catch (e) { showAlert("error", errText(e), { sticky: true }); }
  };
  document.getElementById("fsmo-seize").onclick = () => {
    const role = document.getElementById("fsmo-role").value;
    confirmModal(`Seize the "${role}" FSMO role onto this DC? Only do this if the current holder is permanently gone.`, async () => {
      try {
        await run(["samba-tool", "fsmo", "seize", "--role=" + role, "--force"]);
        showAlert("success", `Seized ${role} role.`);
        loadFsmoShow();
      } catch (e) { showAlert("error", errText(e), { sticky: true }); }
    });
  };
  loadFsmoShow();
}

async function loadFsmoShow() {
  const box = document.getElementById("fsmo-box");
  box.innerHTML = `<span class="spinner"></span> Loading&hellip;`;
  try {
    const out = await run(["samba-tool", "fsmo", "show"]);
    box.innerHTML = `<pre class="ldif">${escapeHtml(out.trim())}</pre>`;
  } catch (e) { box.innerHTML = `<div class="alert error">${escapeHtml(errText(e))}</div>`; }
}

/* ---------------- SITES ---------------- */

async function loadSites() {
  document.getElementById("sites-refresh").onclick = () => { loadSitesList(); loadSubnetsList(); };
  document.getElementById("sites-add").onclick = openAddSite;
  document.getElementById("subnets-refresh").onclick = loadSubnetsList;
  document.getElementById("subnets-add").onclick = openAddSubnet;
  loadSitesList();
  loadSubnetsList();
}

async function loadSitesList() {
  const wrap = document.getElementById("sites-table-wrap");
  wrap.innerHTML = `<span class="spinner"></span> Loading&hellip;`;
  try {
    const out = await run(["samba-tool", "sites", "list"]);
    const names = out.split("\n").map((s) => s.trim()).filter(Boolean).sort();
    if (names.length === 0) { wrap.innerHTML = `<div class="empty-state">No sites found.</div>`; return; }
    const rows = names.map((n) => `
      <tr data-name="${escapeHtml(n)}"><td>${escapeHtml(n)}</td>
      <td class="row-actions"><button class="small btn-view">View</button><button class="small danger btn-delete">Delete</button></td></tr>`).join("");
    wrap.innerHTML = `<table class="data-table"><thead><tr><th>Site</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
    wrap.querySelectorAll("tr[data-name]").forEach((tr) => {
      const name = tr.dataset.name;
      tr.querySelector(".btn-view").addEventListener("click", async () => {
        const modal = openModal(`Site: ${name}`, `<span class="spinner"></span>`);
        try {
          const out2 = await run(["samba-tool", "sites", "view", name]);
          modal.node.querySelector(".modal-body").innerHTML = `<pre class="ldif">${escapeHtml(out2.trim())}</pre>`;
        } catch (e) { modal.node.querySelector(".modal-body").innerHTML = `<div class="alert error">${escapeHtml(errText(e))}</div>`; }
      });
      tr.querySelector(".btn-delete").addEventListener("click", () => {
        confirmModal(`Delete site "${name}"?`, async () => {
          try { await run(["samba-tool", "sites", "remove", name]); showAlert("success", "Site deleted."); loadSitesList(); }
          catch (e) { showAlert("error", errText(e)); }
        });
      });
    });
  } catch (e) { wrap.innerHTML = `<div class="alert error">${escapeHtml(errText(e))}</div>`; }
}

function openAddSite() {
  openModal("Add site", `<div class="form-row"><label>Site name</label><input type="text" id="site-name"></div>`, {
    buttons: [
      { label: "Cancel", onClick: (close) => close() },
      {
        label: "Create", className: "primary", onClick: async (close, node) => {
          const name = node.querySelector("#site-name").value.trim();
          if (!name) { showAlert("error", "Site name required."); return; }
          try { await run(["samba-tool", "sites", "create", name]); showAlert("success", `Site "${name}" created.`); close(); loadSitesList(); }
          catch (e) { showAlert("error", errText(e)); }
        }
      }
    ]
  });
}

async function loadSubnetsList() {
  const wrap = document.getElementById("subnets-table-wrap");
  wrap.innerHTML = `<span class="muted">Select a site to list its subnets, or use "Add subnet" below.</span>`;
  try {
    const sitesOut = await run(["samba-tool", "sites", "list"]);
    const sites = sitesOut.split("\n").map((s) => s.trim()).filter(Boolean);
    let allRows = "";
    for (const site of sites) {
      try {
        const out = await run(["samba-tool", "sites", "subnet", "list", site]);
        const subnets = out.split("\n").map((s) => s.trim()).filter(Boolean);
        subnets.forEach((sn) => {
          allRows += `<tr data-subnet="${escapeHtml(sn)}"><td>${escapeHtml(sn)}</td><td>${escapeHtml(site)}</td>
            <td class="row-actions"><button class="small danger btn-delete-subnet">Delete</button></td></tr>`;
        });
      } catch (e) { /* site may have no subnets */ }
    }
    if (!allRows) { wrap.innerHTML = `<div class="empty-state">No subnets found.</div>`; return; }
    wrap.innerHTML = `<table class="data-table"><thead><tr><th>Subnet</th><th>Site</th><th></th></tr></thead><tbody>${allRows}</tbody></table>`;
    wrap.querySelectorAll(".btn-delete-subnet").forEach((btn) => {
      const tr = btn.closest("tr");
      btn.addEventListener("click", () => {
        confirmModal(`Delete subnet "${tr.dataset.subnet}"?`, async () => {
          try { await run(["samba-tool", "sites", "subnet", "remove", tr.dataset.subnet]); showAlert("success", "Subnet deleted."); loadSubnetsList(); }
          catch (e) { showAlert("error", errText(e)); }
        });
      });
    });
  } catch (e) { wrap.innerHTML = `<div class="alert error">${escapeHtml(errText(e))}</div>`; }
}

function openAddSubnet() {
  openModal("Add subnet", `
    <div class="form-row"><label>Subnet (CIDR)</label><input type="text" id="subnet-cidr" placeholder="10.0.1.0/24"></div>
    <div class="form-row"><label>Site</label><input type="text" id="subnet-site"></div>
  `, {
    buttons: [
      { label: "Cancel", onClick: (close) => close() },
      {
        label: "Create", className: "primary", onClick: async (close, node) => {
          const cidr = node.querySelector("#subnet-cidr").value.trim();
          const site = node.querySelector("#subnet-site").value.trim();
          if (!cidr || !site) { showAlert("error", "Subnet and site are required."); return; }
          try { await run(["samba-tool", "sites", "subnet", "create", cidr, site]); showAlert("success", "Subnet created."); close(); loadSubnetsList(); }
          catch (e) { showAlert("error", errText(e)); }
        }
      }
    ]
  });
}

/* ---------------- DNS ---------------- */

function requireCreds() {
  if (!STATE.creds) { showAlert("error", "Set domain administrator credentials via the \"Credentials\" button in the header first."); return false; }
  return true;
}

async function loadDns() {
  document.getElementById("dns-zones-refresh").onclick = loadDnsZones;
  document.getElementById("dns-zone-add").onclick = openAddZone;
  document.getElementById("dns-rec-query").onclick = () => dnsRecordAction("query");
  document.getElementById("dns-rec-add").onclick = () => dnsRecordAction("add");
  document.getElementById("dns-rec-delete").onclick = () => dnsRecordAction("delete");
  document.getElementById("dns-open-creds").onclick = () => openCredentialsModal(updateDnsCredsNote);
  updateDnsCredsNote();
}

function updateDnsCredsNote() {
  const note = document.getElementById("dns-creds-note");
  if (!note) return;
  note.textContent = STATE.creds
    ? `Using saved credentials for "${STATE.creds.user}".`
    : "No credentials saved yet \u2014 use the \"Credentials\" button in the header.";
}

async function loadDnsZones() {
  const wrap = document.getElementById("dns-zones-table-wrap");
  if (!requireCreds()) return;
  wrap.innerHTML = `<span class="spinner"></span> Loading&hellip;`;
  try {
    const out = await run(["samba-tool", "dns", "zonelist", "localhost"]);
    wrap.innerHTML = `<pre class="ldif">${escapeHtml(out.trim())}</pre>`;
  } catch (e) { wrap.innerHTML = `<div class="alert error">${escapeHtml(errText(e))}</div>`; }
}

function openAddZone() {
  if (!requireCreds()) return;
  openModal("Create DNS zone", `<div class="form-row"><label>Zone name</label><input type="text" id="zone-name" placeholder="sub.example.com"></div>`, {
    buttons: [
      { label: "Cancel", onClick: (close) => close() },
      {
        label: "Create", className: "primary", onClick: async (close, node) => {
          const zone = node.querySelector("#zone-name").value.trim();
          if (!zone) { showAlert("error", "Zone name required."); return; }
          try { await run(["samba-tool", "dns", "zonecreate", "localhost", zone]); showAlert("success", `Zone "${zone}" created.`); close(); loadDnsZones(); }
          catch (e) { showAlert("error", errText(e), { sticky: true }); }
        }
      }
    ]
  });
}

async function dnsRecordAction(action) {
  if (!requireCreds()) return;
  const zone = document.getElementById("dns-rec-zone").value.trim();
  const name = document.getElementById("dns-rec-name").value.trim();
  const type = document.getElementById("dns-rec-type").value;
  const data = document.getElementById("dns-rec-data").value.trim();
  const out = document.getElementById("dns-rec-result");
  if (!zone || !name) { showAlert("error", "Zone and name are required."); return; }
  if (action !== "query" && !data) { showAlert("error", "Data is required to add or delete a record."); return; }
  const args = ["samba-tool", "dns", action, "localhost", zone, name, type];
  if (action !== "query") args.push(data);
  out.textContent = "Running\u2026";
  try {
    const res = await run(args);
    out.textContent = res;
  } catch (e) { out.textContent = errText(e); }
}

/* ---------------- CONTACTS ---------------- */

async function loadContacts() {
  const wrap = document.getElementById("contacts-table-wrap");
  wrap.innerHTML = `<span class="spinner"></span> Loading&hellip;`;
  try {
    const out = await run(["samba-tool", "contact", "list"]);
    const names = out.split("\n").map((s) => s.trim()).filter(Boolean).sort();
    renderContactsTable(names);
  } catch (e) { wrap.innerHTML = `<div class="alert error">${escapeHtml(errText(e))}</div>`; }
}

function renderContactsTable(names) {
  const wrap = document.getElementById("contacts-table-wrap");
  if (names.length === 0) { wrap.innerHTML = `<div class="empty-state">No contacts found.</div>`; return; }
  const rows = names.map((n) => `
    <tr data-name="${escapeHtml(n)}">
      <td class="col-check"><input type="checkbox" class="row-check" data-name="${escapeHtml(n)}"></td>
      <td>${escapeHtml(n)}</td>
      <td class="row-actions">
        <button class="small btn-details">Details</button>
        <button class="small btn-move">Move</button>
        <button class="small danger btn-delete">Delete</button>
      </td></tr>`).join("");
  wrap.innerHTML = `<table class="data-table"><thead><tr><th class="col-check"><input type="checkbox" class="select-all" title="Select all"></th><th>Contact</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
  wrap.querySelectorAll("tr[data-name]").forEach((tr) => {
    const name = tr.dataset.name;
    tr.querySelector(".btn-details").addEventListener("click", async () => {
      const modal = openModal(`Contact: ${name}`, `<span class="spinner"></span>`, { wide: true });
      try {
        const out = await run(["samba-tool", "contact", "show", name]);
        modal.node.querySelector(".modal-body").innerHTML = `<pre class="ldif">${escapeHtml(out.trim())}</pre>`;
      } catch (e) { modal.node.querySelector(".modal-body").innerHTML = `<div class="alert error">${escapeHtml(errText(e))}</div>`; }
    });
    tr.querySelector(".btn-move").addEventListener("click", () => {
      openMoveModal({ kind: "contact", names: [name], buildArgs: (n, target) => ["samba-tool", "contact", "move", n, target], onDone: () => loadPanel("contacts", true) });
    });
    tr.querySelector(".btn-delete").addEventListener("click", () => {
      confirmModal(`Delete contact "${name}"?`, async () => {
        try { await run(["samba-tool", "contact", "delete", name]); showAlert("success", "Contact deleted."); loadPanel("contacts", true); }
        catch (e) { showAlert("error", errText(e)); }
      });
    });
  });
  document.getElementById("contacts-search").oninput = (e) => {
    const q = e.target.value.toLowerCase();
    wrap.querySelectorAll("tr[data-name]").forEach((tr) => { tr.style.display = tr.dataset.name.toLowerCase().includes(q) ? "" : "none"; });
  };

  wireBulkActions(wrap, document.getElementById("contacts-bulk-bar"), [
    {
      label: "Move\u2026", run: (sel) => openMoveModal({
        kind: "contact", names: sel,
        buildArgs: (n, target) => ["samba-tool", "contact", "move", n, target],
        onDone: () => loadPanel("contacts", true)
      })
    },
    {
      label: "Delete", className: "danger", run: (sel) => confirmModal(`Delete ${sel.length} selected contact(s)?`, async () => {
        summarizeBulk(await bulkRun(sel, (n) => run(["samba-tool", "contact", "delete", n])), "Delete");
        loadPanel("contacts", true);
      })
    }
  ]);
}

function openAddContact() {
  openModal("Add contact", `
    <div class="form-grid">
      <div class="form-row"><label>Given name</label><input type="text" id="ct-given"></div>
      <div class="form-row"><label>Surname</label><input type="text" id="ct-surname"></div>
      <div class="form-row"><label>Email</label><input type="text" id="ct-mail"></div>
      <div class="form-row"><label>Job title</label><input type="text" id="ct-job"></div>
      <div class="form-row"><label>Company</label><input type="text" id="ct-company"></div>
      <div class="form-row"><label>Telephone</label><input type="text" id="ct-phone"></div>
    </div>
  `, {
    buttons: [
      { label: "Cancel", onClick: (close) => close() },
      {
        label: "Create contact", className: "primary", onClick: async (close, node) => {
          const given = node.querySelector("#ct-given").value.trim();
          const surname = node.querySelector("#ct-surname").value.trim();
          if (!given && !surname) { showAlert("error", "Enter at least a given name or surname."); return; }
          const args = ["samba-tool", "contact", "add"];
          if (given) args.push("--given-name=" + given);
          if (surname) args.push("--surname=" + surname);
          const mail = node.querySelector("#ct-mail").value.trim();
          const job = node.querySelector("#ct-job").value.trim();
          const company = node.querySelector("#ct-company").value.trim();
          const phone = node.querySelector("#ct-phone").value.trim();
          if (mail) args.push("--mail-address=" + mail);
          if (job) args.push("--job-title=" + job);
          if (company) args.push("--company=" + company);
          if (phone) args.push("--telephone-number=" + phone);
          try { await run(args); showAlert("success", "Contact created."); close(); loadPanel("contacts", true); }
          catch (e) { showAlert("error", errText(e), { sticky: true }); }
        }
      }
    ]
  });
}

/* ---------------- SPN ---------------- */

function initSpn() {
  document.getElementById("spn-list").onclick = async () => {
    const account = document.getElementById("spn-account").value.trim();
    const out = document.getElementById("spn-result");
    if (!account) { showAlert("error", "Account is required."); return; }
    out.textContent = "Loading\u2026";
    try { out.textContent = await run(["samba-tool", "spn", "list", account]); }
    catch (e) { out.textContent = errText(e); }
  };
  document.getElementById("spn-add").onclick = async () => {
    const account = document.getElementById("spn-account").value.trim();
    const spn = document.getElementById("spn-name").value.trim();
    const out = document.getElementById("spn-result");
    if (!account || !spn) { showAlert("error", "Account and SPN are required."); return; }
    try { out.textContent = await run(["samba-tool", "spn", "add", spn, account]); showAlert("success", "SPN added."); }
    catch (e) { out.textContent = errText(e); }
  };
  document.getElementById("spn-delete").onclick = async () => {
    const account = document.getElementById("spn-account").value.trim();
    const spn = document.getElementById("spn-name").value.trim();
    const out = document.getElementById("spn-result");
    if (!spn) { showAlert("error", "SPN is required."); return; }
    try { out.textContent = await run(["samba-tool", "spn", "delete", spn].concat(account ? [account] : [])); showAlert("success", "SPN deleted."); }
    catch (e) { out.textContent = errText(e); }
  };
}

/* ---------------- DELEGATION ---------------- */

function initDelegation() {
  const out = () => document.getElementById("deleg-result");
  const account = () => document.getElementById("deleg-account").value.trim();
  document.getElementById("deleg-show").onclick = async () => {
    if (!account()) { showAlert("error", "Account is required."); return; }
    out().textContent = "Loading\u2026";
    try { out().textContent = await run(["samba-tool", "delegation", "show", account()]); }
    catch (e) { out().textContent = errText(e); }
  };
  document.getElementById("deleg-anyservice-on").onclick = () => delegToggle("for-any-service", "on");
  document.getElementById("deleg-anyservice-off").onclick = () => delegToggle("for-any-service", "off");
  document.getElementById("deleg-anyprotocol-on").onclick = () => delegToggle("for-any-protocol", "on");
  document.getElementById("deleg-anyprotocol-off").onclick = () => delegToggle("for-any-protocol", "off");
  document.getElementById("deleg-service-add").onclick = () => delegService("add-service");
  document.getElementById("deleg-service-del").onclick = () => delegService("del-service");

  async function delegToggle(sub, onoff) {
    if (!account()) { showAlert("error", "Account is required."); return; }
    try { out().textContent = await run(["samba-tool", "delegation", sub, account(), onoff]); showAlert("success", "Updated."); }
    catch (e) { out().textContent = errText(e); }
  }
  async function delegService(sub) {
    const principal = document.getElementById("deleg-service-principal").value.trim();
    if (!account() || !principal) { showAlert("error", "Account and service principal are required."); return; }
    try { out().textContent = await run(["samba-tool", "delegation", sub, account(), principal]); showAlert("success", "Updated."); }
    catch (e) { out().textContent = errText(e); }
  }
}

/* ---------------- ACLs (DS + NT) ---------------- */

function initAcls() {
  document.getElementById("dsacl-get").onclick = async () => {
    const dn = document.getElementById("dsacl-dn").value.trim();
    const out = document.getElementById("dsacl-result");
    if (!dn) { showAlert("error", "Object DN is required."); return; }
    out.textContent = "Loading\u2026";
    try { out.textContent = await run(["samba-tool", "dsacl", "get", "--objectdn=" + dn]); }
    catch (e) { out.textContent = errText(e); }
  };
  document.getElementById("dsacl-set").onclick = async () => {
    const dn = document.getElementById("dsacl-dn").value.trim();
    const sddl = document.getElementById("dsacl-sddl").value.trim();
    const out = document.getElementById("dsacl-result");
    if (!dn || !sddl) { showAlert("error", "Object DN and SDDL are required."); return; }
    try { out.textContent = await run(["samba-tool", "dsacl", "set", "--objectdn=" + dn, "--sddl=" + sddl]); showAlert("success", "ACE applied."); }
    catch (e) { out.textContent = errText(e); }
  };
  document.getElementById("dsacl-delete").onclick = async () => {
    const dn = document.getElementById("dsacl-dn").value.trim();
    const sddl = document.getElementById("dsacl-sddl").value.trim();
    const out = document.getElementById("dsacl-result");
    if (!dn || !sddl) { showAlert("error", "Object DN and SDDL are required."); return; }
    try { out.textContent = await run(["samba-tool", "dsacl", "delete", "--objectdn=" + dn, "--sddl=" + sddl]); showAlert("success", "ACE removed."); }
    catch (e) { out.textContent = errText(e); }
  };

  document.getElementById("ntacl-get").onclick = async () => {
    const path = document.getElementById("ntacl-path").value.trim();
    const out = document.getElementById("ntacl-result");
    if (!path) { showAlert("error", "Path is required."); return; }
    out.textContent = "Loading\u2026";
    try { out.textContent = await run(["samba-tool", "ntacl", "get", path]); }
    catch (e) { out.textContent = errText(e); }
  };
  document.getElementById("ntacl-set").onclick = async () => {
    const path = document.getElementById("ntacl-path").value.trim();
    const sddl = document.getElementById("ntacl-sddl").value.trim();
    const out = document.getElementById("ntacl-result");
    if (!path || !sddl) { showAlert("error", "Path and SDDL are required."); return; }
    try { out.textContent = await run(["samba-tool", "ntacl", "set", sddl, path]); showAlert("success", "ACL applied."); }
    catch (e) { out.textContent = errText(e); }
  };
  document.getElementById("ntacl-sysvolcheck").onclick = async () => {
    const out = document.getElementById("ntacl-result");
    out.textContent = "Running\u2026";
    try { out.textContent = await run(["samba-tool", "ntacl", "sysvolcheck"]); }
    catch (e) { out.textContent = errText(e); }
  };
  document.getElementById("ntacl-sysvolreset").onclick = async () => {
    const out = document.getElementById("ntacl-result");
    confirmModal("Reset sysvol ACLs to Samba's defaults?", async () => {
      out.textContent = "Running\u2026";
      try { out.textContent = await run(["samba-tool", "ntacl", "sysvolreset"]); showAlert("success", "sysvol ACLs reset."); }
      catch (e) { out.textContent = errText(e); }
    });
  };
}

/* ---------------- SERVER TIME ---------------- */

function initTime() {
  document.getElementById("time-query").onclick = async () => {
    const server = document.getElementById("time-server").value.trim() || "localhost";
    const out = document.getElementById("time-result");
    out.textContent = "Querying\u2026";
    try { out.textContent = await run(["samba-tool", "time", server]); }
    catch (e) { out.textContent = errText(e); }
  };
}



/* ---------------- USERS ---------------- */

async function loadUsers() {
  const wrap = document.getElementById("users-table-wrap");
  wrap.innerHTML = `<span class="spinner"></span> Loading&hellip;`;
  try {
    const out = await run(["samba-tool", "user", "list"]);
    const names = out.split("\n").map((s) => s.trim()).filter(Boolean).sort();
    const nameDetails = await fetchUserFullNames(names);
    renderUsersTable(names, nameDetails);
  } catch (e) {
    wrap.innerHTML = `<div class="alert error">${escapeHtml(errText(e))}</div>`;
  }
}

/* Runs fn(item) over items with at most `limit` calls in flight at once,
   instead of either fully serial (slow) or fully parallel (can spawn
   dozens of escalated processes at once for a large directory). */
async function mapWithConcurrency(items, limit, fn) {
  let i = 0;
  async function worker() {
    while (i < items.length) {
      const idx = i++;
      await fn(items[idx], idx);
    }
  }
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker));
}

/* Given first: attempts one bulk "ldbsearch" query (querying givenName/sn
   for every user object in a single call to the local database) since it's
   far cheaper than one "samba-tool user show" per user. Falls back to
   concurrency-limited "samba-tool user show" calls if ldbsearch isn't
   available or returns nothing usable, so this still works even without
   the ldb-tools package installed. Returns { username: { given, sn } },
   with "" for either name when it isn't set on that account. */
async function fetchUserFullNames(names) {
  try {
    const out = await run(
      ["ldbsearch", "-H", "/var/lib/samba/private/sam.ldb", "(&(objectClass=user)(objectCategory=person))", "sAMAccountName", "givenName", "sn"]
    );
    const map = parseLdbUserRecords(out);
    if (Object.keys(map).length > 0) return map;
  } catch (e) { /* fall through to the per-user fallback below */ }

  const map = {};
  await mapWithConcurrency(names, 6, async (name) => {
    try {
      const out = await run(["samba-tool", "user", "show", name]);
      map[name] = parseGivenSnFromLdif(out);
    } catch (e) {
      map[name] = { given: "", sn: "" };
    }
  });
  return map;
}

function parseLdbUserRecords(out) {
  const map = {};
  out.split(/\n\s*\n/).forEach((block) => {
    let sam = "", given = "", sn = "";
    block.split("\n").forEach((line) => {
      if (!line || line.startsWith("#")) return;
      const m = line.match(/^(\w+):\s?(.*)$/);
      if (!m) return;
      const key = m[1].toLowerCase();
      if (key === "samaccountname") sam = m[2].trim();
      else if (key === "givenname") given = m[2].trim();
      else if (key === "sn") sn = m[2].trim();
    });
    if (sam) map[sam] = { given, sn };
  });
  return map;
}

function parseGivenSnFromLdif(out) {
  const given = (out.match(/^givenName:\s?(.*)$/mi) || [])[1] || "";
  const sn = (out.match(/^sn:\s?(.*)$/mi) || [])[1] || "";
  return { given: given.trim(), sn: sn.trim() };
}

function renderUsersTable(names, nameDetails) {
  const wrap = document.getElementById("users-table-wrap");
  if (names.length === 0) {
    wrap.innerHTML = `<div class="empty-state">No users found.</div>`;
    return;
  }
  const rows = names.map((n) => {
    const d = (nameDetails && nameDetails[n]) || { given: "", sn: "" };
    const given = d.given ? escapeHtml(d.given) : '<span class="muted">&mdash;</span>';
    const sn = d.sn ? escapeHtml(d.sn) : '<span class="muted">&mdash;</span>';
    const searchText = [n, d.given, d.sn].join(" ").toLowerCase();
    return `
    <tr data-name="${escapeHtml(n)}" data-search="${escapeHtml(searchText)}">
      <td class="col-check"><input type="checkbox" class="row-check" data-name="${escapeHtml(n)}"></td>
      <td>${escapeHtml(n)}</td>
      <td>${given}</td>
      <td>${sn}</td>
      <td class="row-actions">
        <button class="small btn-details">Details</button>
        <button class="small btn-reset">Reset password</button>
        <button class="small btn-move">Move</button>
        <button class="small danger btn-delete">Delete</button>
      </td>
    </tr>`;
  }).join("");
  wrap.innerHTML = `<table class="data-table"><thead><tr><th class="col-check"><input type="checkbox" class="select-all" title="Select all"></th><th>Username</th><th>First name</th><th>Last name</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;

  wrap.querySelectorAll("tr[data-name]").forEach((tr) => {
    const name = tr.dataset.name;
    tr.querySelector(".btn-details").addEventListener("click", () => openUserDetails(name));
    tr.querySelector(".btn-reset").addEventListener("click", () => openResetPassword(name));
    tr.querySelector(".btn-move").addEventListener("click", () => {
      openMoveModal({ kind: "user", names: [name], buildArgs: (n, target) => ["samba-tool", "user", "move", n, target], onDone: () => loadPanel("users", true) });
    });
    tr.querySelector(".btn-delete").addEventListener("click", () => {
      confirmModal(`Delete user "${name}"? This cannot be undone.`, async () => {
        try {
          await run(["samba-tool", "user", "delete", name]);
          showAlert("success", `User "${name}" deleted.`);
          loadPanel("users", true);
        } catch (e) {
          showAlert("error", `Failed to delete "${name}": ${errText(e)}`);
        }
      });
    });
  });

  document.getElementById("users-search").oninput = (e) => {
    const q = e.target.value.trim().toLowerCase();
    wrap.querySelectorAll("tr[data-name]").forEach((tr) => {
      tr.style.display = tr.dataset.search.includes(q) ? "" : "none";
    });
  };

  wireBulkActions(wrap, document.getElementById("users-bulk-bar"), [
    {
      label: "Enable", run: (sel) => confirmModal(`Enable ${sel.length} selected user(s)?`, async () => {
        summarizeBulk(await bulkRun(sel, (n) => run(["samba-tool", "user", "enable", n])), "Enable");
        loadPanel("users", true);
      })
    },
    {
      label: "Disable", run: (sel) => confirmModal(`Disable ${sel.length} selected user(s)?`, async () => {
        summarizeBulk(await bulkRun(sel, (n) => run(["samba-tool", "user", "disable", n])), "Disable");
        loadPanel("users", true);
      })
    },
    {
      label: "Move\u2026", run: (sel) => openMoveModal({
        kind: "user", names: sel,
        buildArgs: (n, target) => ["samba-tool", "user", "move", n, target],
        onDone: () => loadPanel("users", true)
      })
    },
    {
      label: "Delete", className: "danger", run: (sel) => confirmModal(`Delete ${sel.length} selected user(s)? This cannot be undone.`, async () => {
        summarizeBulk(await bulkRun(sel, (n) => run(["samba-tool", "user", "delete", n])), "Delete");
        loadPanel("users", true);
      })
    }
  ]);
}

async function openUserDetails(name) {
  const modal = openModal(`User: ${name}`, `<span class="spinner"></span> Loading&hellip;`, { wide: true });
  try {
    const [ldif, groupsOut] = await Promise.all([
      run(["samba-tool", "user", "show", name]),
      run(["samba-tool", "user", "getgroups", name]).catch(() => "")
    ]);
    const enabled = !/userAccountControl:\s*\d*(514|546|66082|66050)\b/.test(ldif); // rough disabled-flag check
    const groups = groupsOut.split("\n").map((s) => s.trim()).filter(Boolean);

    const body = modal.node.querySelector(".modal-body");
    body.innerHTML = `
      <div class="form-row">
        <span class="badge ${enabled ? "ok" : "err"}">${enabled ? "Enabled" : "Disabled"}</span>
      </div>
      <div class="form-row">
        <label>Group membership</label>
        <div class="tag-list" id="user-groups-list">
          ${groups.map((g) => `<span class="tag">${escapeHtml(g)} <button data-group="${escapeHtml(g)}" class="tag-remove">&times;</button></span>`).join("") || '<span class="muted">none</span>'}
        </div>
      </div>
      <div class="form-row">
        <label>Add to group</label>
        <div style="display:flex;gap:8px">
          <input type="text" id="user-add-group" placeholder="group name" style="flex:1">
          <button id="user-add-group-btn" class="small">Add</button>
        </div>
      </div>
      <div class="form-row">
        <label>Raw account attributes</label>
        <pre class="ldif">${escapeHtml(ldif.trim())}</pre>
      </div>
    `;

    body.querySelectorAll(".tag-remove").forEach((b) => {
      b.addEventListener("click", async () => {
        try {
          await run(["samba-tool", "group", "removemembers", b.dataset.group, name]);
          showAlert("success", `Removed "${name}" from "${b.dataset.group}".`);
          modal.close();
          openUserDetails(name);
        } catch (e) {
          showAlert("error", errText(e));
        }
      });
    });
    body.querySelector("#user-add-group-btn").addEventListener("click", async () => {
      const g = body.querySelector("#user-add-group").value.trim();
      if (!g) return;
      try {
        await run(["samba-tool", "group", "addmembers", g, name]);
        showAlert("success", `Added "${name}" to "${g}".`);
        modal.close();
        openUserDetails(name);
      } catch (e) {
        showAlert("error", errText(e));
      }
    });
    attachSimpleAutocomplete(body.querySelector("#user-add-group"), () => getAccountNames());

    const footer = modal.node.querySelector(".modal-footer");
    const toggleBtn = document.createElement("button");
    toggleBtn.textContent = enabled ? "Disable account" : "Enable account";
    toggleBtn.className = "small";
    toggleBtn.addEventListener("click", async () => {
      try {
        await run(["samba-tool", "user", enabled ? "disable" : "enable", name]);
        showAlert("success", `Account "${name}" ${enabled ? "disabled" : "enabled"}.`);
        modal.close();
      } catch (e) {
        showAlert("error", errText(e));
      }
    });
    footer.appendChild(toggleBtn);
    const closeBtn = document.createElement("button");
    closeBtn.textContent = "Close";
    closeBtn.className = "primary";
    closeBtn.addEventListener("click", () => modal.close());
    footer.appendChild(closeBtn);
  } catch (e) {
    modal.node.querySelector(".modal-body").innerHTML = `<div class="alert error">${escapeHtml(errText(e))}</div>`;
  }
}

function openResetPassword(name) {
  const modal = openModal(`Reset password: ${name}`, `
    <div class="form-row"><label>New password</label><input type="password" id="rp-pw1"></div>
    <div class="form-row"><label>Confirm password</label><input type="password" id="rp-pw2"></div>
    <div class="checkbox-row"><input type="checkbox" id="rp-mustchange"><label for="rp-mustchange">User must change password at next logon</label></div>
  `, {
    buttons: [
      { label: "Cancel", onClick: (close) => close() },
      {
        label: "Reset password", className: "primary", onClick: async (close, node) => {
          const pw1 = node.querySelector("#rp-pw1").value;
          const pw2 = node.querySelector("#rp-pw2").value;
          if (!pw1 || pw1 !== pw2) { showAlert("error", "Passwords do not match."); return; }
          try {
            await run(["samba-tool", "user", "setpassword", name], { input: pw1 + "\n" + pw1 + "\n" });
            if (node.querySelector("#rp-mustchange").checked) {
              await run(["samba-tool", "user", "setexpiry", name, "--days=0"]);
            }
            showAlert("success", `Password reset for "${name}".`);
            close();
          } catch (e) {
            showAlert("error", errText(e));
          }
        }
      }
    ]
  });
}

function openAddUser() {
  openModal("Add user", `
    <div class="form-grid">
      <div class="form-row"><label>Username</label><input type="text" id="au-username"></div>
      <div class="form-row"><label>Email</label><input type="text" id="au-mail"></div>
      <div class="form-row"><label>First name</label><input type="text" id="au-given"></div>
      <div class="form-row"><label>Surname</label><input type="text" id="au-surname"></div>
      <div class="form-row"><label>Password</label><input type="password" id="au-pw1"></div>
      <div class="form-row"><label>Confirm password</label><input type="password" id="au-pw2"></div>
    </div>
    <div class="checkbox-row"><input type="checkbox" id="au-mustchange" checked><label for="au-mustchange">Must change password at next logon</label></div>
    <div class="checkbox-row"><input type="checkbox" id="au-disabled"><label for="au-disabled">Account is disabled</label></div>
  `, {
    buttons: [
      { label: "Cancel", onClick: (close) => close() },
      {
        label: "Create user", className: "primary", onClick: async (close, node) => {
          const username = node.querySelector("#au-username").value.trim();
          const pw1 = node.querySelector("#au-pw1").value;
          const pw2 = node.querySelector("#au-pw2").value;
          if (!username) { showAlert("error", "Username is required."); return; }
          if (!pw1 || pw1 !== pw2) { showAlert("error", "Passwords do not match."); return; }
          const given = node.querySelector("#au-given").value.trim();
          const surname = node.querySelector("#au-surname").value.trim();
          const mail = node.querySelector("#au-mail").value.trim();
          const args = ["samba-tool", "user", "create", username];
          if (given) args.push("--given-name=" + given);
          if (surname) args.push("--surname=" + surname);
          if (mail) args.push("--mail-address=" + mail);
          if (node.querySelector("#au-mustchange").checked) args.push("--must-change-at-next-login");
          try {
            await run(args, { input: pw1 + "\n" + pw1 + "\n" });
            if (node.querySelector("#au-disabled").checked) {
              await run(["samba-tool", "user", "disable", username]);
            }
            showAlert("success", `User "${username}" created.`);
            close();
            loadPanel("users", true);
          } catch (e) {
            showAlert("error", errText(e));
          }
        }
      }
    ]
  });
}

/* ---------------- bulk user import from spreadsheet ---------------- */

const IMPORT_FIELDS = [
  { key: "username", label: "Username", required: true, candidates: ["username", "samaccountname", "user", "login", "account", "sam"] },
  { key: "given", label: "First name", required: false, candidates: ["given name", "givenname", "first name", "firstname", "given"] },
  { key: "sn", label: "Last name", required: false, candidates: ["surname", "last name", "lastname", "sn", "family name"] },
  { key: "mail", label: "Email", required: false, candidates: ["email", "e-mail", "mail"] },
  { key: "password", label: "Password", required: false, candidates: ["password", "pass", "pwd"] },
  { key: "groups", label: "Groups (comma/semicolon separated)", required: false, candidates: ["groups", "group", "memberof"] }
];

function guessColumnMapping(headers) {
  const mapping = {};
  const normalized = headers.map((h) => ({ h, norm: h.trim().toLowerCase() }));
  IMPORT_FIELDS.forEach((f) => {
    let match = normalized.find((n) => f.candidates.includes(n.norm));
    if (!match) match = normalized.find((n) => f.candidates.some((c) => n.norm.includes(c)));
    mapping[f.key] = match ? match.h : "";
  });
  return mapping;
}

/* Reads a CSV/XLSX/XLS/ODS file (anything SheetJS's core build understands)
   entirely client-side and returns { headers, rows } where rows are plain
   objects keyed by header text - no server round-trip needed just to parse. */
function parseSpreadsheetFile(file) {
  return new Promise((resolve, reject) => {
    if (typeof XLSX === "undefined") { reject(new Error("Spreadsheet library failed to load.")); return; }
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("Could not read the file."));
    reader.onload = (e) => {
      try {
        const data = new Uint8Array(e.target.result);
        const wb = XLSX.read(data, { type: "array" });
        const sheet = wb.Sheets[wb.SheetNames[0]];
        const rows = XLSX.utils.sheet_to_json(sheet, { defval: "", raw: false });
        let headers = rows.length ? Object.keys(rows[0]) : [];
        if (headers.length === 0) {
          const raw = XLSX.utils.sheet_to_json(sheet, { header: 1 });
          headers = (raw[0] || []).map(String);
        }
        resolve({ headers, rows });
      } catch (err) { reject(err); }
    };
    reader.readAsArrayBuffer(file);
  });
}

function generatePassword(len) {
  len = len || 16;
  const sets = ["ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnopqrstuvwxyz", "23456789", "!@#$%^&*-_=+"];
  const all = sets.join("");
  function randInt(max) { const a = new Uint32Array(1); crypto.getRandomValues(a); return a[0] % max; }
  let pw = sets.map((set) => set[randInt(set.length)]);
  while (pw.length < len) pw.push(all[randInt(all.length)]);
  for (let i = pw.length - 1; i > 0; i--) { const j = randInt(i + 1);[pw[i], pw[j]] = [pw[j], pw[i]]; }
  return pw.join("");
}

function csvEscape(v) {
  v = v === null || v === undefined ? "" : String(v);
  return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
}
function toCsv(headers, rows) {
  const lines = [headers.map(csvEscape).join(",")];
  rows.forEach((r) => lines.push(headers.map((h) => csvEscape(r[h])).join(",")));
  return lines.join("\r\n");
}
function downloadTextFile(filename, mime, content) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}

function openImportUsersModal() {
  const importState = {
    file: null,
    headers: [],
    rows: [],
    mapping: {},
    targetDn: "",
    passwordMode: "generate", // "generate" | "fixed"
    fixedPassword: "",
    mustChange: true,
    defaultGroups: []
  };

  const modal = openModal("Import users from spreadsheet", `<div id="imp-body"></div>`, {
    wide: true,
    buttons: [
      { label: "Cancel", onClick: (close) => close() },
      { label: "Start import", className: "primary", onClick: (close, node) => startImport(node, close) }
    ]
  });
  const body = modal.node.querySelector("#imp-body");

  function renderStep1() {
    body.innerHTML = `
      <p class="form-hint">
        Accepts .csv, .xlsx, .xls, or .ods. The first row must be column headers &mdash; columns can be in any
        order and named however you like, since you'll map them to fields next.
      </p>
      <div class="form-row">
        <input type="file" id="imp-file" accept=".csv,.tsv,.xlsx,.xls,.ods">
      </div>
      <button type="button" id="imp-template" class="small link">Download a CSV template</button>
      <div id="imp-file-status"></div>
    `;
    body.querySelector("#imp-template").addEventListener("click", () => {
      const headers = ["username", "given_name", "surname", "email", "password", "groups"];
      const example = { username: "jdoe", given_name: "Jane", surname: "Doe", email: "jane.doe@example.com", password: "", groups: "Sales;Staff" };
      downloadTextFile("users-template.csv", "text/csv", toCsv(headers, [example]));
    });
    body.querySelector("#imp-file").addEventListener("change", async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      const statusEl = body.querySelector("#imp-file-status");
      statusEl.innerHTML = `<span class="spinner"></span> Reading&hellip;`;
      try {
        const { headers, rows } = await parseSpreadsheetFile(file);
        if (rows.length === 0) { statusEl.innerHTML = `<div class="alert error">No data rows found in that file.</div>`; return; }
        importState.file = file;
        importState.headers = headers;
        importState.rows = rows;
        importState.mapping = guessColumnMapping(headers);
        renderStep2();
      } catch (err) {
        statusEl.innerHTML = `<div class="alert error">Could not read that file: ${escapeHtml(errText(err))}</div>`;
      }
    });
  }

  function renderStep2() {
    const mappingRowsHtml = IMPORT_FIELDS.map((f) => `
      <div class="form-row">
        <label>${escapeHtml(f.label)}${f.required ? " (required)" : ""}</label>
        <select class="imp-map" data-field="${f.key}">
          <option value="">(none)</option>
          ${importState.headers.map((h) => `<option value="${escapeHtml(h)}" ${importState.mapping[f.key] === h ? "selected" : ""}>${escapeHtml(h)}</option>`).join("")}
        </select>
      </div>`).join("");

    const previewRows = importState.rows.slice(0, 5);
    const previewHtml = `
      <div class="tree-picker" style="max-height:180px">
        <table class="data-table"><thead><tr>${importState.headers.map((h) => `<th>${escapeHtml(h)}</th>`).join("")}</tr></thead>
        <tbody>${previewRows.map((r) => `<tr>${importState.headers.map((h) => `<td>${escapeHtml(r[h])}</td>`).join("")}</tr>`).join("")}</tbody></table>
      </div>
      <p class="form-hint">${importState.rows.length} row(s) detected. Showing the first ${previewRows.length}.</p>
    `;

    body.innerHTML = `
      <p class="muted">${escapeHtml(importState.file.name)} &mdash; <button type="button" id="imp-change-file" class="link small" style="display:inline">choose a different file</button></p>
      <div class="card"><div class="card-header">Preview</div><div class="card-body">${previewHtml}</div></div>
      <div class="card"><div class="card-header">Column mapping</div><div class="card-body">${mappingRowsHtml}</div></div>
      <div class="card">
        <div class="card-header">Import settings (applied to every row)</div>
        <div class="card-body">
          <div class="form-row">
            <label>Create accounts in</label>
            <div class="tree-picker" id="imp-tree"><span class="spinner"></span> Loading directory&hellip;</div>
            <p class="muted" id="imp-ou-hint">Default location (no OU selected).</p>
          </div>
          <div class="form-row">
            <label>Password</label>
            <div class="checkbox-row"><input type="radio" name="imp-pwmode" id="imp-pw-generate" checked><label for="imp-pw-generate">Generate a random password for each new user (recommended)</label></div>
            <div class="checkbox-row"><input type="radio" name="imp-pwmode" id="imp-pw-fixed"><label for="imp-pw-fixed">Use this password for any row without one:</label></div>
            <input type="password" id="imp-pw-fixed-value" placeholder="Fallback password" style="margin-top:6px" disabled>
            <p class="form-hint">A row's own Password column value, if mapped and non-empty, always wins over either option.</p>
          </div>
          <div class="checkbox-row"><input type="checkbox" id="imp-mustchange" checked><label for="imp-mustchange">Must change password at next logon</label></div>
          <div class="form-row">
            <label>Also add every imported user to these groups</label>
            <div id="imp-groups-mount"></div>
            <p class="form-hint">Combined with anything in each row's own Groups column, if mapped.</p>
          </div>
          <p class="form-hint">Usernames that already exist are skipped automatically, never overwritten.</p>
        </div>
      </div>
    `;

    body.querySelector("#imp-change-file").addEventListener("click", renderStep1);
    body.querySelectorAll(".imp-map").forEach((sel) => {
      sel.addEventListener("change", () => { importState.mapping[sel.dataset.field] = sel.value; });
    });

    const pwGenerate = body.querySelector("#imp-pw-generate");
    const pwFixed = body.querySelector("#imp-pw-fixed");
    const pwFixedValue = body.querySelector("#imp-pw-fixed-value");
    pwGenerate.addEventListener("change", () => { pwFixedValue.disabled = true; });
    pwFixed.addEventListener("change", () => { pwFixedValue.disabled = false; pwFixedValue.focus(); });

    const groupsPicker = createMultiTagPicker(
      body.querySelector("#imp-groups-mount"),
      () => getTypedAccountNames().then((r) => r.groups),
      "Type a group name\u2026"
    );
    modal.node._importGroupsPicker = groupsPicker;

    const treeMount = body.querySelector("#imp-tree");
    const ouHint = body.querySelector("#imp-ou-hint");
    getContainerTree().then((tree) => {
      treeMount.innerHTML = `<ul class="tree-root">${renderTreeNodeHtml(tree, true)}</ul>`;
      treeMount.addEventListener("click", (e) => {
        const toggle = e.target.closest(".tree-toggle:not(.tree-toggle-empty)");
        if (toggle) {
          const li = toggle.closest("li");
          const childUl = li.querySelector(":scope > ul.tree-children");
          if (childUl) {
            const collapsed = childUl.classList.toggle("collapsed");
            toggle.textContent = collapsed ? "\u25b8" : "\u25be";
          }
          return;
        }
        const row = e.target.closest(".tree-row");
        if (row) {
          treeMount.querySelectorAll(".tree-row.selected").forEach((r) => r.classList.remove("selected"));
          row.classList.add("selected");
          importState.targetDn = row.dataset.dn;
          ouHint.textContent = importState.targetDn === (STATE.baseDN || "") ? "Default location (domain root)." : `Selected: ${importState.targetDn}`;
        }
      });
    }).catch((e) => {
      treeMount.innerHTML = `<div class="alert error">Could not load the directory tree: ${escapeHtml(errText(e))}</div>`;
    });
  }

  async function startImport(node, close) {
    if (!importState.rows.length) { showAlert("error", "Choose a spreadsheet file first."); return; }
    if (!importState.mapping.username) { showAlert("error", "Map a column to Username first."); return; }

    const pwMode = body.querySelector("#imp-pw-fixed") && body.querySelector("#imp-pw-fixed").checked ? "fixed" : "generate";
    const fixedPassword = body.querySelector("#imp-pw-fixed-value") ? body.querySelector("#imp-pw-fixed-value").value : "";
    if (pwMode === "fixed" && !fixedPassword) { showAlert("error", "Enter a fallback password, or switch to generating one per user."); return; }
    const mustChange = body.querySelector("#imp-mustchange").checked;
    const defaultGroups = modal.node._importGroupsPicker ? modal.node._importGroupsPicker.getValues() : [];

    let userouRelative = "";
    if (importState.targetDn && importState.targetDn !== (STATE.baseDN || "")) {
      userouRelative = STATE.baseDN && importState.targetDn.endsWith("," + STATE.baseDN)
        ? importState.targetDn.slice(0, -(STATE.baseDN.length + 1))
        : importState.targetDn;
    }

    close();
    const progressAlert = showAlert("info", `Importing ${importState.rows.length} row(s)\u2026`, { sticky: true });

    let existing = [];
    try { existing = await getAccountNames(true); } catch (e) { /* proceed without dedupe check if this fails */ }

    const results = [];
    for (const row of importState.rows) {
      const username = String(row[importState.mapping.username] || "").trim();
      if (!username) continue;
      if (existing.includes(username)) { results.push({ username, status: "skipped", note: "already exists" }); continue; }

      const given = importState.mapping.given ? String(row[importState.mapping.given] || "").trim() : "";
      const sn = importState.mapping.sn ? String(row[importState.mapping.sn] || "").trim() : "";
      const mail = importState.mapping.mail ? String(row[importState.mapping.mail] || "").trim() : "";
      const rowPassword = importState.mapping.password ? String(row[importState.mapping.password] || "").trim() : "";
      const rowGroupsRaw = importState.mapping.groups ? String(row[importState.mapping.groups] || "").trim() : "";
      const rowGroups = rowGroupsRaw ? rowGroupsRaw.split(/[,;]/).map((s) => s.trim()).filter(Boolean) : [];
      const groups = Array.from(new Set([...rowGroups, ...defaultGroups]));

      const generated = !rowPassword;
      const password = rowPassword || (pwMode === "fixed" ? fixedPassword : generatePassword());

      const args = ["samba-tool", "user", "create", username];
      if (given) args.push("--given-name=" + given);
      if (sn) args.push("--surname=" + sn);
      if (mail) args.push("--mail-address=" + mail);
      if (userouRelative) args.push("--userou=" + userouRelative);
      if (mustChange) args.push("--must-change-at-next-login");

      try {
        await run(args, { input: password + "\n" + password + "\n" });
        const groupWarnings = [];
        for (const g of groups) {
          try { await run(["samba-tool", "group", "addmembers", g, username]); }
          catch (e) { groupWarnings.push(`${g}: ${errText(e)}`); }
        }
        results.push({
          username, status: "created",
          password: generated ? password : "",
          note: groupWarnings.length ? `Created, but group add failed for: ${groupWarnings.join("; ")}` : ""
        });
      } catch (e) {
        results.push({ username, status: "failed", note: errText(e) });
      }
    }

    progressAlert.remove();
    showImportResults(results);
    loadPanel("users", true);
  }

  renderStep1();
}

function showImportResults(results) {
  const created = results.filter((r) => r.status === "created");
  const skipped = results.filter((r) => r.status === "skipped");
  const failed = results.filter((r) => r.status === "failed");
  const rowsHtml = results.map((r) => `
    <tr>
      <td>${escapeHtml(r.username)}</td>
      <td><span class="badge ${r.status === "created" ? "ok" : r.status === "skipped" ? "neutral" : "err"}">${r.status}</span></td>
      <td>${r.password ? `<code class="inline">${escapeHtml(r.password)}</code>` : ""}</td>
      <td>${escapeHtml(r.note || "")}</td>
    </tr>`).join("");

  const modal = openModal("Import results", `
    <p>${created.length} created, ${skipped.length} skipped, ${failed.length} failed.</p>
    ${created.some((r) => r.password) ? `<div class="alert info">Passwords shown below were auto-generated and are <strong>only shown this once</strong> &mdash; download or copy them now.</div>` : ""}
    <div class="tree-picker" style="max-height:360px">
      <table class="data-table"><thead><tr><th>Username</th><th>Status</th><th>Password</th><th>Notes</th></tr></thead><tbody>${rowsHtml}</tbody></table>
    </div>
  `, {
    wide: true,
    buttons: [
      {
        label: "Download results (CSV)", onClick: (close, node) => {
          const csv = toCsv(["username", "status", "password", "note"], results);
          downloadTextFile("import-results.csv", "text/csv", csv);
        }
      },
      { label: "Close", className: "primary", onClick: (close) => close() }
    ]
  });
  return modal;
}



async function loadGroups() {
  const wrap = document.getElementById("groups-table-wrap");
  wrap.innerHTML = `<span class="spinner"></span> Loading&hellip;`;
  try {
    const out = await run(["samba-tool", "group", "list"]);
    const names = out.split("\n").map((s) => s.trim()).filter(Boolean).sort();
    renderGroupsTable(names);
  } catch (e) {
    wrap.innerHTML = `<div class="alert error">${escapeHtml(errText(e))}</div>`;
  }
}

function renderGroupsTable(names) {
  const wrap = document.getElementById("groups-table-wrap");
  if (names.length === 0) {
    wrap.innerHTML = `<div class="empty-state">No groups found.</div>`;
    return;
  }
  const rows = names.map((n) => `
    <tr data-name="${escapeHtml(n)}">
      <td class="col-check"><input type="checkbox" class="row-check" data-name="${escapeHtml(n)}"></td>
      <td>${escapeHtml(n)}</td>
      <td class="row-actions">
        <button class="small btn-members">Members</button>
        <button class="small btn-move">Move</button>
        <button class="small danger btn-delete">Delete</button>
      </td>
    </tr>`).join("");
  wrap.innerHTML = `<table class="data-table"><thead><tr><th class="col-check"><input type="checkbox" class="select-all" title="Select all"></th><th>Group</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;

  wrap.querySelectorAll("tr[data-name]").forEach((tr) => {
    const name = tr.dataset.name;
    tr.querySelector(".btn-members").addEventListener("click", () => openGroupMembers(name));
    tr.querySelector(".btn-move").addEventListener("click", () => {
      openMoveModal({ kind: "group", names: [name], buildArgs: (n, target) => ["samba-tool", "group", "move", n, target], onDone: () => loadPanel("groups", true) });
    });
    tr.querySelector(".btn-delete").addEventListener("click", () => {
      confirmModal(`Delete group "${name}"?`, async () => {
        try {
          await run(["samba-tool", "group", "delete", name]);
          showAlert("success", `Group "${name}" deleted.`);
          loadPanel("groups", true);
        } catch (e) {
          showAlert("error", errText(e));
        }
      });
    });
  });

  document.getElementById("groups-search").oninput = (e) => {
    const q = e.target.value.toLowerCase();
    wrap.querySelectorAll("tr[data-name]").forEach((tr) => {
      tr.style.display = tr.dataset.name.toLowerCase().includes(q) ? "" : "none";
    });
  };

  wireBulkActions(wrap, document.getElementById("groups-bulk-bar"), [
    {
      label: "Move\u2026", run: (sel) => openMoveModal({
        kind: "group", names: sel,
        buildArgs: (n, target) => ["samba-tool", "group", "move", n, target],
        onDone: () => loadPanel("groups", true)
      })
    },
    {
      label: "Delete", className: "danger", run: (sel) => confirmModal(`Delete ${sel.length} selected group(s)?`, async () => {
        summarizeBulk(await bulkRun(sel, (n) => run(["samba-tool", "group", "delete", n])), "Delete");
        loadPanel("groups", true);
      })
    }
  ]);
}

async function openGroupMembers(name) {
  const modal = openModal(`Group: ${name}`, `<span class="spinner"></span> Loading&hellip;`);
  try {
    const out = await run(["samba-tool", "group", "listmembers", name]);
    const members = out.split("\n").map((s) => s.trim()).filter(Boolean);
    const body = modal.node.querySelector(".modal-body");
    body.innerHTML = `
      <div class="form-row">
        <label>Members</label>
        <div class="tag-list" id="group-members-list">
          ${members.map((m) => `<span class="tag">${escapeHtml(m)} <button data-member="${escapeHtml(m)}" class="tag-remove">&times;</button></span>`).join("") || '<span class="muted">none</span>'}
        </div>
      </div>
      <div class="form-row">
        <label>Add members</label>
        <div id="group-add-member-mount"></div>
        <button id="group-add-member-btn" class="small primary" style="margin-top:10px">Add selected</button>
        <p class="form-hint">Start typing a username or group name, pick from the list, and keep going &mdash; everything you pick is added at once.</p>
      </div>
    `;
    const picker = createMultiTagPicker(
      body.querySelector("#group-add-member-mount"),
      () => getAccountNames(),
      "Type a username or group\u2026"
    );

    body.querySelectorAll(".tag-remove").forEach((b) => {
      b.addEventListener("click", async () => {
        try {
          await run(["samba-tool", "group", "removemembers", name, b.dataset.member]);
          showAlert("success", `Removed "${b.dataset.member}" from "${name}".`);
          modal.close();
          openGroupMembers(name);
        } catch (e) { showAlert("error", errText(e)); }
      });
    });
    body.querySelector("#group-add-member-btn").addEventListener("click", async () => {
      const values = picker.getValues();
      if (values.length === 0) { showAlert("error", "Pick at least one member to add."); return; }
      try {
        await run(["samba-tool", "group", "addmembers", name, values.join(",")]);
        showAlert("success", `Added ${values.length} member${values.length > 1 ? "s" : ""} to "${name}".`);
        modal.close();
        openGroupMembers(name);
      } catch (e) { showAlert("error", errText(e)); }
    });
  } catch (e) {
    modal.node.querySelector(".modal-body").innerHTML = `<div class="alert error">${escapeHtml(errText(e))}</div>`;
  }
}

function openAddGroup() {
  openModal("Add group", `
    <div class="form-row"><label>Group name</label><input type="text" id="ag-name"></div>
    <div class="form-row">
      <label>Scope</label>
      <select id="ag-scope">
        <option value="Global">Global</option>
        <option value="DomainLocal">Domain local</option>
        <option value="Universal">Universal</option>
      </select>
    </div>
  `, {
    buttons: [
      { label: "Cancel", onClick: (close) => close() },
      {
        label: "Create group", className: "primary", onClick: async (close, node) => {
          const name = node.querySelector("#ag-name").value.trim();
          const scope = node.querySelector("#ag-scope").value;
          if (!name) { showAlert("error", "Group name is required."); return; }
          try {
            await run(["samba-tool", "group", "add", name, "--group-scope=" + scope]);
            showAlert("success", `Group "${name}" created.`);
            close();
            loadPanel("groups", true);
          } catch (e) { showAlert("error", errText(e)); }
        }
      }
    ]
  });
}

/* ---------------- COMPUTERS ---------------- */

async function loadComputers() {
  const wrap = document.getElementById("computers-table-wrap");
  wrap.innerHTML = `<span class="spinner"></span> Loading&hellip;`;
  try {
    const out = await run(["samba-tool", "computer", "list"]);
    const names = out.split("\n").map((s) => s.trim()).filter(Boolean).sort();
    renderComputersTable(names);
  } catch (e) {
    wrap.innerHTML = `<div class="alert error">${escapeHtml(errText(e))}</div>`;
  }
}

function renderComputersTable(names) {
  const wrap = document.getElementById("computers-table-wrap");
  if (names.length === 0) {
    wrap.innerHTML = `<div class="empty-state">No computer accounts found.</div>`;
    return;
  }
  const rows = names.map((n) => `
    <tr data-name="${escapeHtml(n)}">
      <td class="col-check"><input type="checkbox" class="row-check" data-name="${escapeHtml(n)}"></td>
      <td>${escapeHtml(n)}</td>
      <td class="row-actions">
        <button class="small btn-details">Details</button>
        <button class="small btn-move">Move</button>
        <button class="small danger btn-delete">Delete</button>
      </td>
    </tr>`).join("");
  wrap.innerHTML = `<table class="data-table"><thead><tr><th class="col-check"><input type="checkbox" class="select-all" title="Select all"></th><th>Computer</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;

  wrap.querySelectorAll("tr[data-name]").forEach((tr) => {
    const name = tr.dataset.name;
    tr.querySelector(".btn-details").addEventListener("click", async () => {
      const modal = openModal(`Computer: ${name}`, `<span class="spinner"></span> Loading&hellip;`, { wide: true });
      try {
        const out = await run(["samba-tool", "computer", "show", name]);
        modal.node.querySelector(".modal-body").innerHTML = `<pre class="ldif">${escapeHtml(out.trim())}</pre>`;
      } catch (e) {
        modal.node.querySelector(".modal-body").innerHTML = `<div class="alert error">${escapeHtml(errText(e))}</div>`;
      }
    });
    tr.querySelector(".btn-move").addEventListener("click", () => {
      openMoveModal({ kind: "computer", names: [name], buildArgs: (n, target) => ["samba-tool", "computer", "move", n, target], onDone: () => loadPanel("computers", true) });
    });
    tr.querySelector(".btn-delete").addEventListener("click", () => {
      confirmModal(`Delete computer account "${name}"? The machine will need to rejoin the domain.`, async () => {
        try {
          await run(["samba-tool", "computer", "delete", name]);
          showAlert("success", `Computer "${name}" deleted.`);
          loadPanel("computers", true);
        } catch (e) { showAlert("error", errText(e)); }
      });
    });
  });

  document.getElementById("computers-search").oninput = (e) => {
    const q = e.target.value.toLowerCase();
    wrap.querySelectorAll("tr[data-name]").forEach((tr) => {
      tr.style.display = tr.dataset.name.toLowerCase().includes(q) ? "" : "none";
    });
  };

  wireBulkActions(wrap, document.getElementById("computers-bulk-bar"), [
    {
      label: "Move\u2026", run: (sel) => openMoveModal({
        kind: "computer", names: sel,
        buildArgs: (n, target) => ["samba-tool", "computer", "move", n, target],
        onDone: () => loadPanel("computers", true)
      })
    },
    {
      label: "Delete", className: "danger", run: (sel) => confirmModal(`Delete ${sel.length} selected computer account(s)?`, async () => {
        summarizeBulk(await bulkRun(sel, (n) => run(["samba-tool", "computer", "delete", n])), "Delete");
        loadPanel("computers", true);
      })
    }
  ]);
}

function openAddComputer() {
  openModal("Add computer account", `
    <div class="form-row"><label>Computer name</label><input type="text" id="ac-name" placeholder="WORKSTATION01"></div>
    <p class="form-hint">Normally computer accounts are created automatically when a machine joins the domain. Pre-creating one here is only needed for staged joins.</p>
  `, {
    buttons: [
      { label: "Cancel", onClick: (close) => close() },
      {
        label: "Create", className: "primary", onClick: async (close, node) => {
          const name = node.querySelector("#ac-name").value.trim();
          if (!name) { showAlert("error", "Computer name is required."); return; }
          try {
            await run(["samba-tool", "computer", "create", name]);
            showAlert("success", `Computer "${name}" created.`);
            close();
            loadPanel("computers", true);
          } catch (e) { showAlert("error", errText(e)); }
        }
      }
    ]
  });
}

/* ---------------- ORGANIZATIONAL UNITS ---------------- */

async function loadOUs() {
  const wrap = document.getElementById("ous-table-wrap");
  wrap.innerHTML = `<span class="spinner"></span> Loading&hellip;`;
  try {
    const out = await run(["samba-tool", "ou", "list"]);
    const dns = out.split("\n").map((s) => s.trim()).filter(Boolean).sort();
    renderOUsTable(dns);
  } catch (e) {
    wrap.innerHTML = `<div class="alert error">${escapeHtml(errText(e))}</div>`;
  }
}

function renderOUsTable(dns) {
  const wrap = document.getElementById("ous-table-wrap");
  if (dns.length === 0) {
    wrap.innerHTML = `<div class="empty-state">No organizational units found.</div>`;
    return;
  }
  const rows = dns.map((dn) => `
    <tr data-dn="${escapeHtml(dn)}">
      <td class="col-check"><input type="checkbox" class="row-check" data-name="${escapeHtml(dn)}"></td>
      <td>${escapeHtml(dn)}</td>
      <td class="row-actions">
        <button class="small btn-rename">Rename</button>
        <button class="small btn-move">Move</button>
        <button class="small danger btn-delete">Delete</button>
      </td>
    </tr>`).join("");
  wrap.innerHTML = `<table class="data-table"><thead><tr><th class="col-check"><input type="checkbox" class="select-all" title="Select all"></th><th>Distinguished name</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
  wrap.querySelectorAll("tr[data-dn]").forEach((tr) => {
    const dn = tr.dataset.dn;
    tr.querySelector(".btn-rename").addEventListener("click", () => {
      openModal(`Rename OU`, `
        <div class="form-row"><label>Current DN</label><input type="text" value="${escapeHtml(dn)}" disabled></div>
        <div class="form-row"><label>New DN</label><input type="text" id="ou-new-dn" placeholder="OU=NewName,DC=example,DC=com"></div>
      `, {
        buttons: [
          { label: "Cancel", onClick: (close) => close() },
          {
            label: "Rename", className: "primary", onClick: async (close, node) => {
              const newDn = node.querySelector("#ou-new-dn").value.trim();
              if (!newDn) { showAlert("error", "New DN is required."); return; }
              try { await run(["samba-tool", "ou", "rename", dn, newDn]); showAlert("success", "OU renamed."); close(); loadPanel("ous", true); }
              catch (e) { showAlert("error", errText(e), { sticky: true }); }
            }
          }
        ]
      });
    });
    tr.querySelector(".btn-move").addEventListener("click", () => {
      openMoveModal({ kind: "organizational unit", names: [dn], buildArgs: (n, target) => ["samba-tool", "ou", "move", n, target], onDone: () => loadPanel("ous", true) });
    });
    tr.querySelector(".btn-delete").addEventListener("click", () => {
      confirmModal(`Delete organizational unit:\n${dn}\n\nThis fails if it still contains objects.`, async () => {
        try {
          await run(["samba-tool", "ou", "delete", dn]);
          showAlert("success", "Organizational unit deleted.");
          loadPanel("ous", true);
        } catch (e) { showAlert("error", errText(e)); }
      });
    });
  });

  wireBulkActions(wrap, document.getElementById("ous-bulk-bar"), [
    {
      label: "Move\u2026", run: (sel) => openMoveModal({
        kind: "organizational unit", names: sel,
        buildArgs: (n, target) => ["samba-tool", "ou", "move", n, target],
        onDone: () => loadPanel("ous", true)
      })
    },
    {
      label: "Delete", className: "danger", run: (sel) => confirmModal(`Delete ${sel.length} selected organizational unit(s)? This fails for any that still contain objects.`, async () => {
        summarizeBulk(await bulkRun(sel, (n) => run(["samba-tool", "ou", "delete", n])), "Delete");
        loadPanel("ous", true);
      })
    }
  ]);
}

async function openAddOU() {
  if (!STATE.baseDN) {
    try { await readSmbConf(); } catch (e) { /* handled below via missing baseDN */ }
  }
  const baseHint = STATE.baseDN ? ` (base: ${STATE.baseDN})` : "";
  openModal("Add organizational unit", `
    <div class="form-row"><label>Name</label><input type="text" id="ou-name" placeholder="Marketing"></div>
    <div class="form-row"><label>Parent container (optional)</label><input type="text" id="ou-parent" placeholder="OU=Departments"></div>
    <p class="form-hint">Will be created under your domain's base DN${escapeHtml(baseHint)}.</p>
  `, {
    buttons: [
      { label: "Cancel", onClick: (close) => close() },
      {
        label: "Create", className: "primary", onClick: async (close, node) => {
          const name = node.querySelector("#ou-name").value.trim();
          const parent = node.querySelector("#ou-parent").value.trim();
          if (!name) { showAlert("error", "Name is required."); return; }
          if (!STATE.baseDN) { showAlert("error", "Base DN unknown — open the Configuration tab once so the realm can be read."); return; }
          const dn = `OU=${name}${parent ? "," + parent : ""},${STATE.baseDN}`;
          try {
            await run(["samba-tool", "ou", "create", dn]);
            showAlert("success", `Organizational unit "${name}" created.`);
            close();
            loadPanel("ous", true);
          } catch (e) { showAlert("error", errText(e)); }
        }
      }
    ]
  });
}

/* ---------------- CONFIGURATION + FILE SHARES (smb.conf) ---------------- */

function getSmbConfFile() {
  if (!STATE.smbConfFile) {
    STATE.smbConfFile = cockpit.file(SMB_CONF_PATH, { superuser: "require" });
  }
  return STATE.smbConfFile;
}

async function readSmbConf(force) {
  if (STATE.smbConfText !== null && !force) return STATE.smbConfText;
  const text = await getSmbConfFile().read();
  STATE.smbConfText = text || "";
  const m = STATE.smbConfText.match(/^\s*realm\s*=\s*(\S+)/mi);
  if (m) {
    STATE.realm = m[1];
    STATE.baseDN = "DC=" + m[1].toLowerCase().split(".").join(",DC=");
  }
  const wg = STATE.smbConfText.match(/^\s*workgroup\s*=\s*(\S+)/mi);
  if (wg) STATE.workgroup = wg[1].toUpperCase();
  else if (STATE.realm) STATE.workgroup = STATE.realm.split(".")[0].toUpperCase();
  return STATE.smbConfText;
}

/* Validate candidate smb.conf content with testparm against a temp copy, without touching the real file. */
async function validateConfText(text) {
  const tmpPath = "/tmp/.sadc-smb-check-" + Date.now() + ".conf";
  const tmpFile = cockpit.file(tmpPath, { superuser: "require" });
  try {
    await tmpFile.replace(text);
    let out = "";
    let ok = true;
    try {
      out = await run(["testparm", "-s", tmpPath]);
    } catch (e) {
      ok = false;
      out = errText(e);
    }
    return { ok, out };
  } finally {
    try { await run(["rm", "-f", tmpPath]); } catch (e) { /* ignore */ }
    tmpFile.close();
  }
}

async function commitSmbConf(newText, opts) {
  opts = opts || {};
  const check = await validateConfText(newText);
  if (!check.ok) {
    throw { message: "Configuration is invalid according to testparm:\n\n" + check.out };
  }
  await getSmbConfFile().replace(newText);
  STATE.smbConfText = newText;
  if (opts.reload !== false && STATE.service) {
    try {
      await run(["systemctl", "reload", STATE.service]);
    } catch (e) {
      showAlert("error", `Config saved, but reloading ${STATE.service} failed: ${errText(e)}. A manual restart may be required.`);
    }
  }
  return check.out;
}

async function loadConfig() {
  const editor = document.getElementById("config-editor");
  editor.value = "Loading\u2026";
  SharingUI.renderInto("sharing-diag");
  try {
    const text = await readSmbConf(true);
    editor.value = text;
  } catch (e) {
    editor.value = "";
    showAlert("error", `Could not read ${SMB_CONF_PATH}: ${errText(e)}`);
  }
}

function initConfigButtons() {
  document.getElementById("sharing-diag-run").addEventListener("click", () => SharingUI.renderInto("sharing-diag"));

  document.getElementById("config-validate").addEventListener("click", async () => {
    const editor = document.getElementById("config-editor");
    const resultCard = document.getElementById("config-validate-result");
    const out = document.getElementById("config-validate-output");
    resultCard.style.display = "";
    out.textContent = "Running testparm\u2026";
    const check = await validateConfText(editor.value);
    out.textContent = check.out;
    resultCard.querySelector(".card-header").nextElementSibling; // no-op, keep card
  });

  document.getElementById("config-save").addEventListener("click", async () => {
    const editor = document.getElementById("config-editor");
    try {
      const out = await commitSmbConf(editor.value);
      showAlert("success", "smb.conf saved and service reloaded.");
      const resultCard = document.getElementById("config-validate-result");
      resultCard.style.display = "";
      document.getElementById("config-validate-output").textContent = out;
      loadPanel("shares", true);
    } catch (e) {
      showAlert("error", errText(e), { sticky: true });
    }
  });

  document.getElementById("config-reload").addEventListener("click", async () => {
    if (!STATE.service) { showAlert("error", "No samba service selected."); return; }
    try {
      await run(["systemctl", "reload", STATE.service]);
      showAlert("success", `${STATE.service} reloaded.`);
    } catch (e) {
      showAlert("error", errText(e));
    }
  });
}

/* ---- share section parsing ---- */

const RESERVED_SECTIONS = ["global"];

function parseShares(text) {
  const lines = text.split("\n");
  const sections = [];
  let current = null;
  for (const rawLine of lines) {
    const line = rawLine.replace(/\r$/, "");
    const headerMatch = line.match(/^\s*\[([^\]]+)\]\s*$/);
    if (headerMatch) {
      if (current) sections.push(current);
      current = { name: headerMatch[1], lines: [line], params: {} };
      continue;
    }
    if (current) {
      current.lines.push(line);
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith(";") && !trimmed.startsWith("#")) {
        const kv = trimmed.match(/^([^=]+?)\s*=\s*(.*)$/);
        if (kv) current.params[kv[1].trim().toLowerCase()] = kv[2].trim();
      }
    }
  }
  if (current) sections.push(current);
  return sections;
}

/* ---- valid users: encode/decode ----
   In smb.conf, "valid users = Sales" means a USER named Sales. A group has to
   be written @Sales, or - to be unambiguous on an AD DC - @"DOMAIN\Sales".
   Writing plain group names (as this module used to) means the group never
   matches anybody and every member gets "access denied" from Windows. */

function decodeValidUsers(raw) {
  const out = [];
  const add = (s) => {
    const name = s.trim().replace(/^[@+&]+/, "").replace(/^.*\\/, "").trim();
    if (name) out.push(name);
  };
  // quoted tokens (may contain spaces, e.g. @"EXAMPLE\Domain Users"), then bare tokens
  const rest = (raw || "").replace(/[@+&]*"([^"]*)"/g, (m, quoted) => { add(quoted); return " "; });
  rest.split(/[,\s]+/).forEach(add);
  return Array.from(new Set(out));
}

async function encodeValidUsers(names) {
  const { groups } = await getTypedAccountNames();
  const wg = STATE.workgroup;
  return names.map((n) => {
    const qualified = wg ? `${wg}\\${n}` : n;
    const q = /\s/.test(qualified) || wg ? `"${qualified}"` : qualified;
    return groups.includes(n) ? `@${q}` : q;
  }).join(", ");
}

/* Resolve an account's SID from the AD database (no NSS/winbind needed). */
async function lookupSid(name, kind) {
  const order = kind === "g" ? ["group", "user"] : ["user", "group"];
  for (const type of order) {
    try {
      const out = await run(["samba-tool", type, "show", name]);
      const m = out.match(/^objectSid:\s*(S-[\d-]+)/mi);
      if (m) return m[1];
    } catch (e) { /* try the other type */ }
  }
  throw new Error(`Could not find "${name}" in the directory.`);
}

/* Applies the access to the share directory the way Samba on an AD DC
   actually enforces it for Windows clients: as an NT ACL (stored by
   vfs_acl_xattr), addressed by SID. The old approach used setfacl with
   group NAMES, which needs the DC to resolve AD groups through NSS/winbind
   and which Windows never consults anyway. POSIX permissions are opened up
   (3777) so the NT ACL is the real gate, exactly like Microsoft's model.
   Returns { applied: [names], failed: [{name,error}], sddl, verify }. */
async function applyShareAcl(path, opts) {
  const { users, groups } = await getTypedAccountNames();
  const principals = [];
  const seen = new Set();
  function add(name, kind) {
    if (!name || seen.has(name)) return;
    seen.add(name);
    principals.push({ name, kind });
  }
  (opts.validUsers || []).forEach((n) => add(n, groups.includes(n) ? "g" : (users.includes(n) ? "u" : "g")));
  if (opts.forceGroup) add(opts.forceGroup, "g");
  if (opts.forceUser) add(opts.forceUser, "u");

  const report = { applied: [], failed: [], sddl: "", verify: "" };
  const rights = opts.readOnly ? "0x1200a9" : "0x1301bf"; // read+execute / modify
  let aces = "(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)";
  if (principals.length === 0) {
    aces += `(A;OICI;${rights};;;AU)`; // no restriction listed: any authenticated user
  } else {
    for (const p of principals) {
      try {
        const sid = await lookupSid(p.name, p.kind);
        aces += `(A;OICI;${rights};;;${sid})`;
        report.applied.push(p.name);
      } catch (e) {
        report.failed.push({ name: p.name, error: errText(e) });
      }
    }
  }
  if (principals.length > 0 && report.applied.length === 0) return report;

  report.sddl = `O:BAG:BAD:PAI${aces}`;
  await run(["chmod", "3777", path]);
  await run(["samba-tool", "ntacl", "set", report.sddl, path]);
  try { report.verify = (await run(["samba-tool", "ntacl", "get", "--as-sddl", path])).trim(); } catch (e) { /* non-fatal */ }
  return report;
}

const MANAGED_SHARE_PARAMS = new Set([
  "path", "comment", "browseable", "browsable", "read only", "writable", "writeable", "guest ok", "public",
  "valid users", "force user", "force group", "vfs objects", "map acl inherit", "store dos attributes",
  "acl_xattr:ignore system acls"
]);

function buildShareBlock(opts) {
  const p = [];
  p.push(`[${opts.name}]`);
  if (opts.path) p.push(`   path = ${opts.path}`);
  if (opts.comment) p.push(`   comment = ${opts.comment}`);
  p.push(`   browseable = ${opts.browseable ? "yes" : "no"}`);
  p.push(`   read only = ${opts.readOnly ? "yes" : "no"}`);
  p.push(`   guest ok = ${opts.guestOk ? "yes" : "no"}`);
  if (opts.validUsers) p.push(`   valid users = ${opts.validUsers}`);
  if (opts.forceUser) p.push(`   force user = ${opts.forceUser}`);
  if (opts.forceGroup) p.push(`   force group = ${opts.forceGroup}`);
  // Windows-ACL mode: NT ACLs (set from this UI or from Windows' Security
  // tab) decide access, stored in an xattr by vfs_acl_xattr.
  p.push(`   vfs objects = acl_xattr`);
  p.push(`   map acl inherit = yes`);
  p.push(`   store dos attributes = yes`);
  p.push(`   acl_xattr:ignore system acls = yes`);
  // keep any parameters this form doesn't manage (e.g. hand-added ones)
  (opts.extraLines || []).forEach((l) => p.push(l));
  p.push("");
  return p.join("\n");
}

function extraShareLines(section) {
  if (!section) return [];
  return section.lines.slice(1).filter((l) => {
    const m = l.match(/^\s*([^=;#]+?)\s*=/);
    return m && !MANAGED_SHARE_PARAMS.has(m[1].trim().toLowerCase());
  });
}

async function loadShares() {
  const wrap = document.getElementById("shares-table-wrap");
  wrap.innerHTML = `<span class="spinner"></span> Loading&hellip;`;
  try {
    const text = await readSmbConf();
    const sections = parseShares(text).filter((s) => !RESERVED_SECTIONS.includes(s.name.toLowerCase()));
    renderSharesTable(sections);
  } catch (e) {
    wrap.innerHTML = `<div class="alert error">${escapeHtml(errText(e))}</div>`;
  }
}

function renderSharesTable(sections) {
  const wrap = document.getElementById("shares-table-wrap");
  if (sections.length === 0) {
    wrap.innerHTML = `<div class="empty-state">No shares defined yet.</div>`;
    return;
  }
  const rows = sections.map((s) => `
    <tr data-name="${escapeHtml(s.name)}">
      <td>${escapeHtml(s.name)}</td>
      <td><code class="inline">${escapeHtml(s.params.path || "\u2014")}</code></td>
      <td>${escapeHtml(s.params.comment || "")}</td>
      <td>${(s.params["read only"] || "no").toLowerCase() === "yes" ? '<span class="badge neutral">read only</span>' : '<span class="badge ok">read/write</span>'}</td>
      <td>${(s.params["guest ok"] || "no").toLowerCase() === "yes" ? '<span class="badge warn">guest ok</span>' : ""}</td>
      <td class="row-actions">
        <button class="small btn-test">Test access</button>
        <button class="small btn-edit">Edit</button>
        <button class="small danger btn-delete">Delete</button>
      </td>
    </tr>`).join("");
  wrap.innerHTML = `
    <table class="data-table">
      <thead><tr><th>Share</th><th>Path</th><th>Comment</th><th>Access</th><th></th><th></th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;

  wrap.querySelectorAll("tr[data-name]").forEach((tr) => {
    const name = tr.dataset.name;
    tr.querySelector(".btn-test").addEventListener("click", () => SharingUI.openTest(name));
    tr.querySelector(".btn-edit").addEventListener("click", () => openShareForm(name));
    tr.querySelector(".btn-delete").addEventListener("click", () => {
      confirmModal(`Delete share "${name}" from smb.conf? The underlying directory and its files are not touched.`, async () => {
        try {
          const text = await readSmbConf();
          const sections = parseShares(text);
          const keep = sections.filter((s) => s.name !== name);
          const newText = keep.map((s) => s.lines.join("\n")).join("\n");
          await commitSmbConf(newText);
          showAlert("success", `Share "${name}" removed.`);
          loadPanel("shares", true);
        } catch (e) { showAlert("error", errText(e), { sticky: true }); }
      });
    });
  });
}

async function openShareForm(existingName) {
  const text = await readSmbConf();
  const sections = parseShares(text);
  const existing = existingName ? sections.find((s) => s.name === existingName) : null;
  const p = existing ? existing.params : {};
  const writableRaw = (p.writable || p.writeable || "").toLowerCase();
  const initialReadOnly = p["read only"] !== undefined
    ? p["read only"].toLowerCase() === "yes"
    : (writableRaw ? ["no", "false", "0"].includes(writableRaw) : false);

  const modal = openModal(existingName ? `Edit share: ${existingName}` : "Add share", `
    <div class="form-row"><label>Share name</label><input type="text" id="sh-name" value="${escapeHtml(existingName || "")}" ${existingName ? "disabled" : ""}></div>
    <div class="form-row">
      <label>Path</label>
      <div style="display:flex;gap:8px">
        <input type="text" id="sh-path" value="${escapeHtml(p.path || "")}" style="flex:1" placeholder="/srv/samba/share-name">
        <button id="sh-mkdir" class="small">Create/fix directory &amp; permissions</button>
      </div>
      <div class="form-hint" id="sh-mkdir-result"></div>
      <p class="form-hint">Creates the directory if needed and sets its Windows (NT) ACL so everyone listed in Valid users /
        Force user / Force group gets access (Modify, or Read if the share is read-only). Then click <strong>Save share</strong>
        so the matching <code class="inline">acl_xattr</code> settings are written to smb.conf. Windows caches sessions and
        group membership: after changing access, disconnect the mapped drive (or <code class="inline">net use * /delete</code>)
        and, if the user was only just added to the group, log off and on again.</p>
    </div>
    <div class="form-row"><label>Comment</label><input type="text" id="sh-comment" value="${escapeHtml(p.comment || "")}"></div>
    <div class="form-row"><label>Valid users (leave empty for all)</label><div id="sh-validusers-mount"></div></div>
    <div class="form-grid">
      <div class="form-row"><label>Force user (optional)</label><input type="text" id="sh-forceuser" value="${escapeHtml(p["force user"] || "")}"></div>
      <div class="form-row"><label>Force group (optional)</label><input type="text" id="sh-forcegroup" value="${escapeHtml(p["force group"] || "")}"></div>
    </div>
    <div class="checkbox-row"><input type="checkbox" id="sh-browseable" ${(p.browseable || "yes").toLowerCase() !== "no" ? "checked" : ""}><label for="sh-browseable">Browseable</label></div>
    <div class="checkbox-row"><input type="checkbox" id="sh-readonly" ${initialReadOnly ? "checked" : ""}><label for="sh-readonly">Read only</label></div>
    <div class="checkbox-row"><input type="checkbox" id="sh-guestok" ${(p["guest ok"] || "no").toLowerCase() === "yes" ? "checked" : ""}><label for="sh-guestok">Guest access allowed</label></div>
  `, {
    wide: true,
    buttons: [
      { label: "Cancel", onClick: (close) => close() },
      {
        label: existingName ? "Save share" : "Create share", className: "primary", onClick: async (close, node) => {
          const name = existingName || node.querySelector("#sh-name").value.trim();
          const path = node.querySelector("#sh-path").value.trim();
          if (!name) { showAlert("error", "Share name is required."); return; }
          if (!path) { showAlert("error", "Path is required."); return; }
          const opts = {
            name, path,
            comment: node.querySelector("#sh-comment").value.trim(),
            validNames: node._validUsersPicker ? node._validUsersPicker.getValues() : [],
            validUsers: await encodeValidUsers(node._validUsersPicker ? node._validUsersPicker.getValues() : []),
            extraLines: extraShareLines(existing),
            forceUser: node.querySelector("#sh-forceuser").value.trim(),
            forceGroup: node.querySelector("#sh-forcegroup").value.trim(),
            browseable: node.querySelector("#sh-browseable").checked,
            readOnly: node.querySelector("#sh-readonly").checked,
            guestOk: node.querySelector("#sh-guestok").checked
          };
          try {
            const currentText = await readSmbConf();
            const currentSections = parseShares(currentText);
            const block = buildShareBlock(opts);
            let newText;
            if (existingName) {
              const parts = currentSections.map((s) => s.name === existingName ? block : s.lines.join("\n"));
              newText = parts.join("\n");
            } else {
              if (currentSections.some((s) => s.name.toLowerCase() === name.toLowerCase())) {
                showAlert("error", `A section named "${name}" already exists.`);
                return;
              }
              newText = currentText.replace(/\s*$/, "\n") + "\n" + block;
            }
            await commitSmbConf(newText);
            close();
            showAlert("success", `Share "${name}" saved. Applying filesystem permissions\u2026`, { sticky: true });
            try {
              await run(["mkdir", "-p", path]);
              const report = await applyShareAcl(path, {
                validUsers: opts.validNames,
                readOnly: opts.readOnly,
                forceUser: opts.forceUser,
                forceGroup: opts.forceGroup
              });
              if (report.failed.length === 0) {
                showAlert("success", `Share "${name}" saved and access granted for: ${report.applied.join(", ") || "all authenticated users"}. ` +
                  `Windows clients may need to disconnect and reconnect the share.`);
              } else {
                showAlert("error",
                  `Share "${name}" saved, but filesystem permissions could not be set for: ${report.failed.map((f) => `${f.name} (${f.error})`).join("; ")}. ` +
                  `Check the names exist in the directory (Users/Groups tabs).`,
                  { sticky: true });
              }
            } catch (e) {
              showAlert("error", `Share "${name}" saved, but setting filesystem permissions failed: ${errText(e)}. ` +
                `Check that the path's filesystem supports extended attributes (xattr) and that samba-tool ntacl works on it.`, { sticky: true });
            }
            loadPanel("shares", true);
          } catch (e) {
            showAlert("error", errText(e), { sticky: true });
          }
        }
      }
    ]
  });

  modal.node.querySelector("#sh-mkdir").addEventListener("click", async () => {
    const path = modal.node.querySelector("#sh-path").value.trim();
    const resultEl = modal.node.querySelector("#sh-mkdir-result");
    if (!path) { resultEl.textContent = "Enter a path first."; return; }
    const validUsers = modal.node._validUsersPicker ? modal.node._validUsersPicker.getValues() : [];
    const forceUser = modal.node.querySelector("#sh-forceuser").value.trim();
    const forceGroup = modal.node.querySelector("#sh-forcegroup").value.trim();
    resultEl.textContent = "Working\u2026";
    try {
      await run(["mkdir", "-p", path]);
      await run(["chmod", "0770", path]);
      const readOnly = modal.node.querySelector("#sh-readonly").checked;
      const report = await applyShareAcl(path, { validUsers, forceUser, forceGroup, readOnly });
      const detail = report.verify ? `\n\nNT ACL now on disk:\n${report.verify}` : "";
      if (report.failed.length === 0) {
        resultEl.textContent = `Directory ready: ${path}. Access granted for: ${report.applied.join(", ") || "all authenticated users (no restriction listed)"}.` + detail;
      } else {
        resultEl.textContent = `Directory ready: ${path}. Granted: ${report.applied.join(", ") || "none"}. ` +
          `Could not resolve: ${report.failed.map((f) => `${f.name} (${f.error})`).join("; ")}` + detail;
      }
      resultEl.style.whiteSpace = "pre-wrap";
    } catch (e) {
      resultEl.textContent = "Failed: " + errText(e);
    }
  });

  attachSimpleAutocomplete(modal.node.querySelector("#sh-forceuser"), () => getAccountNames());
  attachSimpleAutocomplete(modal.node.querySelector("#sh-forcegroup"), () => getAccountNames());

  const existingValidUsers = decodeValidUsers(p["valid users"]);
  const validUsersPicker = createMultiTagPicker(
    modal.node.querySelector("#sh-validusers-mount"),
    () => getAccountNames(),
    "Type a username or group\u2026",
    existingValidUsers
  );
  modal.node.dataset.validUsersPicker = "1";
  modal.node._validUsersPicker = validUsersPicker;
}

/* ---------------- boot ---------------- */

function initButtons() {
  document.getElementById("sadc-refresh-all").addEventListener("click", () => {
    const active = document.querySelector(".sadc-tab.active").dataset.panel;
    detectService();
    loadPanel(active, true);
  });
  document.getElementById("sadc-service-restart").addEventListener("click", restartService);

  const dbUrlInput = document.getElementById("sadc-db-url");
  try { dbUrlInput.value = localStorage.getItem("sadc:dbUrl") || ""; } catch (e) {}
  STATE.dbUrl = dbUrlInput.value.trim() || null;
  dbUrlInput.addEventListener("change", () => {
    STATE.dbUrl = dbUrlInput.value.trim() || null;
    try { localStorage.setItem("sadc:dbUrl", dbUrlInput.value.trim()); } catch (e) {}
  });

  document.getElementById("sadc-creds-btn").addEventListener("click", () => openCredentialsModal(updateDnsCredsNote));
  updateCredsBadge();

  document.getElementById("users-refresh").addEventListener("click", () => loadPanel("users", true));
  document.getElementById("users-add").addEventListener("click", openAddUser);
  document.getElementById("users-import").addEventListener("click", openImportUsersModal);

  document.getElementById("groups-refresh").addEventListener("click", () => loadPanel("groups", true));
  document.getElementById("groups-add").addEventListener("click", openAddGroup);

  document.getElementById("computers-refresh").addEventListener("click", () => loadPanel("computers", true));
  document.getElementById("computers-add").addEventListener("click", openAddComputer);

  document.getElementById("contacts-refresh").addEventListener("click", () => loadPanel("contacts", true));
  document.getElementById("contacts-add").addEventListener("click", openAddContact);


  document.getElementById("ous-refresh").addEventListener("click", () => loadPanel("ous", true));
  document.getElementById("ous-add").addEventListener("click", openAddOU);

  document.getElementById("shares-refresh").addEventListener("click", () => loadPanel("shares", true));
  document.getElementById("shares-add").addEventListener("click", () => openShareForm(null));

  initConfigButtons();
}

function initThemeSync() {
  function resolve() {
    let manual = null;
    try { manual = localStorage.getItem("sadc:theme"); } catch (e) { /* ignore */ }
    if (manual === "light" || manual === "dark") return manual;

    let pref = "auto";
    try { pref = localStorage.getItem("shell:style") || "auto"; } catch (e) { /* ignore */ }
    if (pref === "light" || pref === "dark") return pref;

    return (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) ? "dark" : "light";
  }
  function currentManual() {
    try { return localStorage.getItem("sadc:theme") || "auto"; } catch (e) { return "auto"; }
  }
  function apply() {
    document.documentElement.setAttribute("data-theme", resolve());
    const btn = document.getElementById("sadc-theme-toggle");
    if (btn) {
      const m = currentManual();
      btn.textContent = "Theme: " + (m === "auto" ? "Auto" : m === "dark" ? "Dark" : "Light");
    }
  }
  apply();
  window.addEventListener("storage", (e) => { if (!e.key || e.key === "shell:style" || e.key === "sadc:theme") apply(); });
  window.addEventListener("cockpit-style", apply);
  if (window.matchMedia) {
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    (mq.addEventListener ? mq.addEventListener.bind(mq) : mq.addListener.bind(mq))("change", apply);
  }

  const toggleBtn = document.getElementById("sadc-theme-toggle");
  toggleBtn.addEventListener("click", () => {
    const order = ["auto", "light", "dark"];
    const next = order[(order.indexOf(currentManual()) + 1) % order.length];
    try {
      if (next === "auto") localStorage.removeItem("sadc:theme");
      else localStorage.setItem("sadc:theme", next);
    } catch (e) { /* ignore */ }
    apply();
  });
}

/* ---------------- credentials ---------------- */

function updateCredsBadge() {
  const btn = document.getElementById("sadc-creds-btn");
  if (!btn) return;
  btn.textContent = STATE.creds ? `Credentials: ${STATE.creds.user}` : "Credentials: not set";
}

function openCredentialsModal(onSaved) {
  openModal("Credentials", `
    <p class="form-hint">
      Plain list/show/create/delete for users, groups, computers, contacts, and OUs work fine as local root
      and never need this. A handful of commands genuinely talk to the domain over RPC and need a real account
      &mdash; DRS replication status, FSMO transfer/seize, Group Policy (sysvol access), and DNS management.
      Set domain administrator credentials here and they'll be used automatically only where needed.
    </p>
    <div class="form-row"><label>Username</label><input type="text" id="cr-user" value="${escapeHtml(STATE.creds ? STATE.creds.user : "administrator")}"></div>
    <div class="form-row"><label>Password</label><input type="password" id="cr-pass" value="${escapeHtml(STATE.creds ? STATE.creds.pass : "")}"></div>
    <p class="form-hint">Kept in memory only for this browser tab &mdash; never written to disk or localStorage.</p>
  `, {
    buttons: [
      { label: "Clear", className: "danger", onClick: (close) => { STATE.creds = null; updateCredsBadge(); if (onSaved) onSaved(); close(); showAlert("success", "Credentials cleared."); } },
      { label: "Cancel", onClick: (close) => close() },
      {
        label: "Save", className: "primary", onClick: (close, node) => {
          const user = node.querySelector("#cr-user").value.trim();
          const pass = node.querySelector("#cr-pass").value;
          if (!user || !pass) { showAlert("error", "Username and password are required."); return; }
          STATE.creds = { user, pass };
          updateCredsBadge();
          if (onSaved) onSaved();
          close();
          showAlert("success", "Credentials saved for this session.");
        }
      }
    ]
  });
}

document.addEventListener("DOMContentLoaded", () => {
  initThemeSync();
  initTabs();
  initButtons();
  detectService();
  detectSelfFqdn();
  loadPanel("overview");

  cockpit.transport.wait(() => {
    // page ready
  });
});

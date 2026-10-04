"use strict";
/* ---------------------------------------------------------------------
 * Group Policy UI: a Group Policy Management Console (GPMC) style
 * manager plus a Group Policy Management Editor (GPME) style editor.
 * Depends on gpo-core.js, gpo-builtin.js and helpers from samba-adc.js
 * (openModal, confirmModal, showAlert, errText, escapeHtml, STATE).
 * All AD / SYSVOL work goes through gpo_backend.py (run as root on the DC).
 * ------------------------------------------------------------------- */
const GpoUI = (function () {
  const C = GpoCore;
  const esc = (s) => escapeHtml(s == null ? "" : s);
  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  const G = { gpos: [], containers: [], info: null, sel: { kind: "domain", id: null }, tab: "scope", expanded: new Set(), ed: null, tpl: null };

  /* ---------------- backend ---------------- */
  let backendSrc = null;
  async function backend(req) {
    if (!backendSrc) {
      const r = await fetch("gpo_backend.py", { cache: "no-store" });
      if (!r.ok) throw new Error("Could not load gpo_backend.py from the module folder (HTTP " + r.status + ")");
      backendSrc = await r.text();
    }
    const out = await cockpit.spawn(["python3", "-c", backendSrc], { superuser: "require", err: "message" }).input(JSON.stringify(Object.assign({ server: STATE.selfFqdn || null }, req)));
    let res;
    try { res = JSON.parse(out); } catch (e) { throw new Error("Unexpected response from the GPO helper: " + String(out).slice(0, 300)); }
    if (!res.ok) throw new Error(res.error);
    return res.data;
  }
  const readFile = async (root, path) => { const b = await backend({ cmd: "read_file", root, path }); return b == null ? null : C.b64ToBytes(b); };
  const writeFile = (root, path, bytes, extra) => backend(Object.assign({ cmd: "write_file", root, path, data: C.bytesToB64(bytes) }, extra || {}));

  /* ---------------- templates (ADMX) ---------------- */
  async function loadTemplates(force, progress) {
    if (G.tpl && !force) return G.tpl;
    const models = []; let source = "builtin"; let files = 0;
    const note = (m) => { if (progress) progress(m); };
    try {
      const top = await backend({ cmd: "list_dir", root: "policies", path: "PolicyDefinitions" });
      const admxNames = top.filter((d) => !d.dir && /\.admx$/i.test(d.name)).map((d) => d.name);
      if (admxNames.length) {
        const lang = (navigator.language || "en-US");
        const langs = [lang, lang.split("-")[0], "en-US"];
        const dirNames = top.filter((d) => d.dir).map((d) => d.name);
        const pick = langs.map((l) => dirNames.find((d) => d.toLowerCase() === l.toLowerCase() || d.toLowerCase().startsWith(l.toLowerCase() + "-"))).find(Boolean);
        const readBatches = async (dir, names, label) => {
          const out = {}; const size = 25;
          for (let i = 0; i < names.length; i += size) {
            note(`${label} ${Math.min(i + size, names.length)} / ${names.length}\u2026`);
            Object.assign(out, await backend({ cmd: "read_files", root: "policies", paths: names.slice(i, i + size).map((n) => dir + "/" + n) }));
          }
          return out;
        };
        const admx = await readBatches("PolicyDefinitions", admxNames, "Reading templates");
        let adml = {};
        if (pick) {
          const an = (await backend({ cmd: "list_dir", root: "policies", path: "PolicyDefinitions/" + pick })).filter((d) => !d.dir && /\.adml$/i.test(d.name)).map((d) => d.name);
          adml = await readBatches("PolicyDefinitions/" + pick, an, "Reading descriptions");
        }
        note("Parsing templates\u2026"); await new Promise((r) => setTimeout(r, 0));
        const defs = {};
        for (const path of Object.keys(admx)) {
          const base = path.split("/").pop().replace(/\.admx$/i, "");
          const mlKey = Object.keys(adml).find((k) => k.split("/").pop().toLowerCase() === base.toLowerCase() + ".adml");
          try {
            const al = mlKey ? C.parseAdml(C.decodeText(C.b64ToBytes(adml[mlKey]))) : undefined;
            if (al && al.definitions) Object.assign(defs, al.definitions);
            const m = C.parseAdmx(C.decodeText(C.b64ToBytes(admx[path])), al);
            models.push(m); files++;
          } catch (e) { console.warn("Skipping ADMX", path, e); }
        }
        if (models.length) { source = "central"; G.supported = defs; }
      }
    } catch (e) { console.warn("Central Store not readable", e); }
    if (!models.length) models.push(GpoBuiltin.model);
    G.tpl = { models, source, files, policyCount: models.reduce((a, m) => a + m.policies.length, 0) };
    G.tpl.byId = new Map(); for (const m of models) for (const p of m.policies) G.tpl.byId.set(p.id, p);
    return G.tpl;
  }

  /* ---------------- data ---------------- */
  async function reload() {
    const [info, gpos, containers] = await Promise.all([backend({ cmd: "info" }), backend({ cmd: "list_gpos" }), backend({ cmd: "list_containers" })]);
    G.info = info; G.gpos = gpos; G.containers = containers;
  }
  const gpoByGuid = (g) => G.gpos.find((x) => x.guid.toUpperCase() === String(g).toUpperCase());
  const baseDn = () => G.info.base_dn;
  const parentDn = (dn) => { const parts = dn.replace(/\\,/g, "\u0000").split(","); parts.shift(); return parts.join(",").replace(/\u0000/g, "\\,"); };
  const FLAG_LABEL = ["Enabled", "User configuration settings disabled", "Computer configuration settings disabled", "All settings disabled"];
  const fmtAdTime = (s) => { const m = /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)/.exec(s || ""); return m ? `${m[1]}-${m[2]}-${m[3]} ${m[4]}:${m[5]}:${m[6]} UTC` : (s || ""); };
  function spin(node) { node.innerHTML = `<span class="spinner"></span> Loading&hellip;`; }

  /* ---------------- root / toolbar ---------------- */
  async function load() {
    const root = $("#gpo-root");
    spin(root);
    try { await reload(); } catch (e) { root.innerHTML = `<div class="alert error">${esc(errText(e))}</div>`; return; }
    G.ed = null;
    if (!G.sel.id) G.sel = { kind: "domain", id: baseDn() };
    renderManager();
  }

  function renderManager() {
    const root = $("#gpo-root");
    root.innerHTML = `
      <div class="sadc-toolbar">
        <div class="left"><span class="gpo-title">Group Policy Management</span><span class="muted">&nbsp;&mdash; ${esc(G.info.realm)}</span></div>
        <div class="right">
          <button id="gpo-health" class="small" title="Why does gpupdate fail? Checks every GPO, SYSVOL permissions, DNS, time">Health check</button>
          <button id="gpo-refresh2" class="small">Refresh</button>
          <button id="gpo-new" class="primary">New GPO&hellip;</button>
        </div>
      </div>
      <div class="gpmc">
        <div class="gpmc-tree" id="gpmc-tree"></div>
        <div class="gpmc-detail" id="gpmc-detail"></div>
      </div>`;
    $("#gpo-refresh2").onclick = async () => { spin($("#gpmc-detail")); try { await reload(); renderManager(); } catch (e) { showAlert("error", errText(e)); } };
    $("#gpo-health").onclick = openHealth;
    $("#gpo-new").onclick = () => openNewGpo(G.sel.kind === "container" || G.sel.kind === "domain" ? G.sel.id : null);
    renderTree(); renderDetail();
  }

  /* ---- tree ---- */
  function renderTree() {
    const t = $("#gpmc-tree");
    const byParent = new Map();
    for (const c of G.containers) {
      if (c.type === "site" || c.dn === baseDn()) continue;
      const p = parentDn(c.dn); if (!byParent.has(p)) byParent.set(p, []); byParent.get(p).push(c);
    }
    const sel = (kind, id) => G.sel.kind === kind && G.sel.id === id ? " selected" : "";
    const exp = (id) => G.expanded.has(id) || !G.expandedInit;
    const domain = G.containers.find((c) => c.dn === baseDn());
    const node = (c, depth) => {
      const kids = (byParent.get(c.dn) || []).sort((a, b) => a.name.localeCompare(b.name));
      const links = c.links.map((l) => ({ l, g: gpoByGuid(l.guid) })).filter((x) => x.g);
      const open = G.expanded.has(c.dn);
      const hasKids = kids.length + links.length > 0;
      let h = `<div class="tn${sel("container", c.dn)}" data-kind="container" data-id="${esc(c.dn)}" style="padding-left:${depth * 16 + 6}px">` +
        `<span class="tw">${hasKids ? (open ? "&#9662;" : "&#9656;") : ""}</span><span class="ti">${c.type === "domain" ? "&#127970;" : "&#128193;"}</span>${esc(c.type === "domain" ? G.info.realm.toLowerCase() : c.name)}</div>`;
      if (open) {
        for (const k of kids) h += node(k, depth + 1);
        for (const { l, g } of links) h += `<div class="tn link${sel("gpo", g.guid)}" data-kind="gpo" data-id="${esc(g.guid)}" style="padding-left:${(depth + 1) * 16 + 6}px"><span class="tw"></span><span class="ti">&#128279;</span>${esc(g.name)}${l.disabled ? ' <em class="muted">(link disabled)</em>' : ""}</div>`;
      }
      return h;
    };
    const gposOpen = G.expanded.has("__gpos");
    let html = domain ? node(domain, 0) : "";
    html += `<div class="tn${sel("gpos", "__gpos")}" data-kind="gpos" data-id="__gpos" style="padding-left:6px"><span class="tw">${gposOpen ? "&#9662;" : "&#9656;"}</span><span class="ti">&#128451;</span>Group Policy Objects (${G.gpos.length})</div>`;
    if (gposOpen) for (const g of G.gpos) html += `<div class="tn${sel("gpo", g.guid)}" data-kind="gpo" data-id="${esc(g.guid)}" style="padding-left:22px"><span class="tw"></span><span class="ti">&#128196;</span>${esc(g.name)}</div>`;
    const sites = G.containers.filter((c) => c.type === "site");
    if (sites.length) {
      const so = G.expanded.has("__sites");
      html += `<div class="tn" data-kind="toggle" data-id="__sites" style="padding-left:6px"><span class="tw">${so ? "&#9662;" : "&#9656;"}</span><span class="ti">&#127760;</span>Sites</div>`;
      if (so) for (const s of sites) html += `<div class="tn${sel("container", s.dn)}" data-kind="container" data-id="${esc(s.dn)}" style="padding-left:22px"><span class="tw"></span><span class="ti">&#127968;</span>${esc(s.name)}</div>`;
    }
    t.innerHTML = html;
    if (!G.expandedInit) { G.expandedInit = true; G.expanded.add(baseDn()); G.expanded.add("__gpos"); renderTree(); return; }
    $$(".tn", t).forEach((n) => n.addEventListener("click", (ev) => {
      const kind = n.dataset.kind, id = n.dataset.id;
      const onToggle = ev.target.classList.contains("tw");
      if (kind === "toggle") { G.expanded.has(id) ? G.expanded.delete(id) : G.expanded.add(id); renderTree(); return; }
      if (kind === "gpos" || kind === "container") {
        if (onToggle || G.sel.id === id) G.expanded.has(id) ? G.expanded.delete(id) : G.expanded.add(id);
        else G.expanded.add(id);
      }
      G.sel = { kind, id }; G.tab = kind === "gpo" ? (G.tab === "details" || G.tab === "settings" ? G.tab : "scope") : "links";
      renderTree(); renderDetail();
    }));
  }

  /* ---- detail pane ---- */
  function renderDetail() {
    const d = $("#gpmc-detail");
    if (G.sel.kind === "container" || G.sel.kind === "domain") return renderContainer(d, G.containers.find((c) => c.dn === G.sel.id));
    if (G.sel.kind === "gpo") return renderGpo(d, gpoByGuid(G.sel.id));
    if (G.sel.kind === "gpos") return renderGpoList(d);
  }

  function tabsHtml(tabs, cur) { return `<div class="gpmc-tabs">${tabs.map(([id, label]) => `<button class="gtab${id === cur ? " active" : ""}" data-tab="${id}">${label}</button>`).join("")}</div>`; }

  function renderGpoList(d) {
    const rows = G.gpos.map((g) => `<tr data-guid="${esc(g.guid)}"><td>${esc(g.name)}</td><td>${esc(FLAG_LABEL[g.flags] || "")}</td><td>${g.machine_version} / ${g.user_version}</td><td>${esc(fmtAdTime(g.changed))}</td><td class="row-actions"><button class="small b-edit">Edit&hellip;</button></td></tr>`).join("");
    d.innerHTML = `<h3 class="gpmc-h">Group Policy Objects</h3><p class="muted">All GPOs in ${esc(G.info.realm)}. Select one on the left for details, or use Edit to open the policy editor.</p>
      <table class="data-table"><thead><tr><th>Name</th><th>GPO status</th><th>Version (computer / user)</th><th>Modified</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
    $$("tr[data-guid]", d).forEach((tr) => { tr.querySelector(".b-edit").onclick = () => openEditor(tr.dataset.guid); tr.ondblclick = () => openEditor(tr.dataset.guid); });
  }

  /* ---- container (domain / OU / site) ---- */
  function containerPath(c) { return c.type === "domain" ? G.info.realm.toLowerCase() : c.dn; }

  /* Effective GPOs for a domain/OU (GPMC "Group Policy Inheritance" tab). Index 0 = highest precedence. */
  function effectiveGpos(c) {
    const chain = []; let dn = c.dn;
    while (dn) { const x = G.containers.find((k) => k.dn === dn); if (x) chain.unshift(x); if (dn === baseDn()) break; dn = parentDn(dn); }
    let low = []; const enforced = [];
    for (const x of chain) {
      if (x.block_inheritance) low = [];
      const own = x.links.filter((l) => !l.disabled).slice().sort((a, b) => b.order - a.order);   // lowest precedence first
      for (const l of own) { if (!l.enforced) low.push({ guid: l.guid, from: x, enforced: false }); }
      enforced.push(...own.filter((l) => l.enforced).map((l) => ({ guid: l.guid, from: x, enforced: true })));
    }
    // Enforced GPOs: a parent's enforced link beats a child's, so deepest first (lowest) then up the chain
    const enf = []; for (let i = chain.length - 1; i >= 0; i--) { const x = chain[i]; enf.push(...x.links.filter((l) => !l.disabled && l.enforced).slice().sort((a, b) => b.order - a.order).map((l) => ({ guid: l.guid, from: x, enforced: true }))); }
    return low.concat(enf).reverse().map((e, i) => Object.assign(e, { precedence: i + 1 }));
  }

  function renderContainer(d, c) {
    if (!c) { d.innerHTML = `<div class="empty-state">Select a container.</div>`; return; }
    const tab = G.tab === "inherit" ? "inherit" : "links";
    const canBlock = c.type !== "site";
    let body = "";
    if (tab === "links") {
      const links = c.links.slice().sort((a, b) => a.order - b.order);
      const rows = links.map((l, i) => {
        const g = gpoByGuid(l.guid);
        return `<tr data-guid="${esc(l.guid)}"><td>${l.order}</td><td>${g ? `<a href="#" class="gpo-open">${esc(g.name)}</a>` : `<em>(missing GPO ${esc(l.guid)})</em>`}</td>
          <td><input type="checkbox" class="chk-enf" ${l.enforced ? "checked" : ""}></td><td><input type="checkbox" class="chk-en" ${l.disabled ? "" : "checked"}></td>
          <td>${g ? esc(FLAG_LABEL[g.flags]) : ""}</td>
          <td class="row-actions"><button class="small b-up" ${i === 0 ? "disabled" : ""} title="Move up (higher precedence)">&uarr;</button><button class="small b-down" ${i === links.length - 1 ? "disabled" : ""} title="Move down">&darr;</button><button class="small b-edit">Edit&hellip;</button><button class="small danger b-unlink">Unlink</button></td></tr>`;
      }).join("");
      body = `<p class="muted">Link order 1 has the highest precedence. <strong>Enforced</strong> links cannot be overridden by child containers or Block Inheritance.</p>
        ${links.length ? `<table class="data-table"><thead><tr><th>Link order</th><th>Group Policy Object</th><th>Enforced</th><th>Link enabled</th><th>GPO status</th><th></th></tr></thead><tbody>${rows}</tbody></table>` : `<div class="empty-state">No GPOs are linked here.</div>`}
        <div class="gpmc-actions"><button id="b-link" class="small">Link an existing GPO&hellip;</button><button id="b-newlink" class="small">Create a GPO and link it here&hellip;</button>
        ${canBlock ? `<label class="inline-check"><input type="checkbox" id="chk-block" ${c.block_inheritance ? "checked" : ""}> Block inheritance</label>` : ""}</div>`;
    } else {
      const eff = effectiveGpos(c);
      body = `<p class="muted">The GPOs that apply to this container, highest precedence first (Local policy and security filtering are not evaluated here).</p>
        ${eff.length ? `<table class="data-table"><thead><tr><th>Precedence</th><th>Group Policy Object</th><th>Location</th><th>Enforced</th></tr></thead><tbody>${eff.map((e) => { const g = gpoByGuid(e.guid); return `<tr><td>${e.precedence}</td><td>${esc(g ? g.name : e.guid)}</td><td>${esc(e.from.type === "domain" ? G.info.realm.toLowerCase() : e.from.name)}</td><td>${e.enforced ? "Yes" : "No"}</td></tr>`; }).join("")}</tbody></table>` : `<div class="empty-state">No GPOs apply.</div>`}`;
    }
    d.innerHTML = `<h3 class="gpmc-h">${esc(c.type === "domain" ? G.info.realm.toLowerCase() : c.name)}</h3><div class="muted small-path">${esc(c.dn)}</div>
      ${canBlock ? tabsHtml([["links", "Linked Group Policy Objects"], ["inherit", "Group Policy Inheritance"]], tab) : tabsHtml([["links", "Linked Group Policy Objects"]], "links")}
      <div class="gpmc-body">${body}</div>`;
    $$(".gtab", d).forEach((b) => b.onclick = () => { G.tab = b.dataset.tab; renderDetail(); });
    if (tab !== "links") return;

    /* Every edit is read-modify-write against the directory, never against the (possibly stale) rendered copy. */
    const edit = async (fn, extra) => {
      try {
        const fresh = (await backend({ cmd: "list_containers" })).find((x) => x.dn === c.dn);
        const ls = fresh.links.slice().sort((a, b) => a.order - b.order).map((l) => Object.assign({}, l));
        fn(ls); ls.forEach((l, i) => { l.order = i + 1; });
        await backend(Object.assign({ cmd: "set_links", dn: c.dn, links: ls }, extra || {}));
        await reload(); renderTree(); renderDetail();
      } catch (e) { showAlert("error", errText(e)); }
    };
    $$("tr[data-guid]", d).forEach((tr) => {
      const guid = tr.dataset.guid;
      const op = (fn) => edit((ls) => { const i = ls.findIndex((l) => l.guid === guid); if (i >= 0) fn(ls, i, ls[i]); });
      tr.querySelector(".chk-enf").onchange = (e) => op((ls, i, l) => { l.enforced = e.target.checked; });
      tr.querySelector(".chk-en").onchange = (e) => op((ls, i, l) => { l.disabled = !e.target.checked; });
      tr.querySelector(".b-up").onclick = () => op((ls, i) => { if (i > 0) [ls[i - 1], ls[i]] = [ls[i], ls[i - 1]]; });
      tr.querySelector(".b-down").onclick = () => op((ls, i) => { if (i < ls.length - 1) [ls[i + 1], ls[i]] = [ls[i], ls[i + 1]]; });
      tr.querySelector(".b-unlink").onclick = () => confirmModal("Remove the link to this GPO? The GPO itself is not deleted.", () => op((ls, i) => { ls.splice(i, 1); }));
      tr.querySelector(".b-edit").onclick = () => openEditor(guid);
      const a = tr.querySelector(".gpo-open"); if (a) a.onclick = (e) => { e.preventDefault(); G.sel = { kind: "gpo", id: guid }; G.tab = "scope"; renderTree(); renderDetail(); };
    });
    $("#b-link", d).onclick = () => openLinkExisting(c, edit);
    $("#b-newlink", d).onclick = () => openNewGpo(c.dn);
    const blk = $("#chk-block", d);
    if (blk) blk.onchange = () => edit(() => {}, { block_inheritance: blk.checked });
  }


  /* ---- health check: why does gpupdate fail on the clients? ---- */
  async function openHealth() {
    const modal = openModal("Group Policy health check", `<div id="hl-body"><span class="spinner"></span> Checking every GPO, SYSVOL permissions, DNS and time&hellip;</div>`, { wide: true, buttons: [{ label: "Close", onClick: (c) => c() }] });
    const body = modal.node.querySelector("#hl-body");
    const draw = async () => {
      body.innerHTML = `<span class="spinner"></span> Checking&hellip;`;
      let h, dom;
      try { [h, dom] = await Promise.all([backend({ cmd: "health" }), SharingUI.fetchDomainChecks()]); } catch (e) { body.innerHTML = `<div class="alert error">${esc(errText(e))}</div>`; return; }
      const sick = h.gpos.filter((g) => g.findings.some((f) => f.level !== "info"));
      const domBad = dom.filter((c) => c.status === "fail" || c.status === "warn");
      const total = sick.length + h.dangling_links.length + dom.filter((c) => c.status === "fail").length;
      let html = total ? `<div class="alert error"><strong>${total} problem${total > 1 ? "s" : ""} found.</strong> Any of these can make <code>gpupdate</code> fail or settings silently not apply.</div>` : `<div class="alert success">No problems found on the server. If a Windows computer still fails, the cause is on that computer (see the checklist below).</div>`;
      html += `<h4 class="diag-h">Delivery (SYSVOL, DNS, time, authentication)</h4>` + SharingUI.listHtml(dom.filter((c) => c.status !== "ok" || /SYSVOL|SRV|share/.test(c.title)), 0);
      html += `<h4 class="diag-h">Group Policy Objects (${h.gpos.length})</h4>`;
      if (!sick.length) html += `<div class="diag diag-ok"><div class="diag-icon">\u2705</div><div class="diag-main"><div class="diag-title">All ${h.gpos.length} GPOs are consistent between Active Directory and SYSVOL</div></div></div>`;
      for (const g of sick) html += `<div class="diag diag-fail"><div class="diag-icon">\u274C</div><div class="diag-main"><div class="diag-title">${esc(g.name)} <span class="muted small-path">${esc(g.guid)}</span></div>${g.findings.map((f) => `<div class="diag-detail">${f.level === "fail" ? "\u274C" : f.level === "warn" ? "\u26A0\uFE0F" : "\u2139\uFE0F"} ${esc(f.msg)}</div>`).join("")}</div><div class="diag-fix"><button class="small primary b-repair" data-guid="${esc(g.guid)}">Repair</button></div></div>`;
      for (const d of h.dangling_links) html += `<div class="diag diag-warn"><div class="diag-icon">\u26A0\uFE0F</div><div class="diag-main"><div class="diag-title">A link to a deleted GPO remains on ${esc(d.container)}</div><div class="diag-detail">${esc(d.guid)}</div></div><div class="diag-fix"><button class="small b-unlink-dead" data-dn="${esc(d.container)}" data-guid="${esc(d.guid)}">Remove link</button></div></div>`;
      html += `<h4 class="diag-h">On the Windows computer</h4>
        <p class="muted">Event <strong>1129</strong> / <em>&ldquo;lack of network connectivity to a domain controller&rdquo;</em> means the PC could not find or reach this DC at all. It is a network/DNS problem, not a problem with the GPO. Work through these in order on the PC (PowerShell):</p>
        <ol class="checklist">
        <li><code>ipconfig /all</code> &mdash; <strong>DNS Servers must be this DC only</strong> (${esc((G.info.realm || "").toLowerCase())}'s DC address), not your router or 8.8.8.8. This is the most common cause: a domain PC that uses another DNS server cannot find the DC.</li>
        <li><code>nslookup -type=SRV _ldap._tcp.dc._msdcs.${esc((G.info.realm || "").toLowerCase())}</code> &mdash; must list this DC.</li>
        <li><code>nltest /dsgetdc:${esc((G.info.realm || "").toLowerCase())}</code> &mdash; must return this DC.</li>
        <li><code>Test-NetConnection &lt;DC-IP&gt; -Port 389</code>, then <code>-Port 88</code>, <code>-Port 135</code>, <code>-Port 445</code>. Any <em>False</em> is a firewall problem: see the firewall result above (open the AD ports on the DC with the <em>Open these ports</em> button).</li>
        <li><code>w32tm /query /status</code> &mdash; clock within 5 minutes of the DC.</li>
        <li><code>nltest /sc_verify:${esc(G.info.domain || "DOMAIN")}</code> &mdash; if it reports a failure or &ldquo;access denied&rdquo;, the computer's account password no longer matches: rejoin the domain.</li>
        <li>Is the PC actually <strong>joined</strong> (<code>systeminfo | findstr /B Domain</code>) and are you signed in with a <strong>domain</strong> account? A workgroup PC shows &ldquo;access denied&rdquo; on <code>\\\\${esc(G.info.realm.split(".")[0].toLowerCase())}</code>.</li>
        <li>After fixing: <code>gpupdate /force</code>, then <code>gpresult /r</code> to see which GPOs applied. A GPO that is not <em>linked</em> to the OU holding the computer/user never applies.</li></ol>`;
      body.innerHTML = html;
      $$("button[data-i]", body).forEach((b) => b.addEventListener("click", () => { const c = dom.filter((x) => x.status !== "ok" || /SYSVOL|SRV|share/.test(x.title))[Number(b.dataset.i)]; SharingUI.runFix(c.fix, draw); }));
      $$(".b-repair", body).forEach((b) => b.addEventListener("click", async () => {
        b.disabled = true; b.textContent = "Repairing\u2026";
        try { const done = await backend({ cmd: "repair_gpo", guid: b.dataset.guid }); showAlert("success", "Repaired: " + done.join("; ") + "."); await reload(); draw(); } catch (e) { showAlert("error", errText(e), { sticky: true }); b.disabled = false; b.textContent = "Repair"; }
      }));
      $$(".b-unlink-dead", body).forEach((b) => b.addEventListener("click", async () => {
        try { const c = G.containers.find((x) => x.dn === b.dataset.dn) || (await backend({ cmd: "list_containers" })).find((x) => x.dn === b.dataset.dn); const links = c.links.filter((l) => l.guid.toUpperCase() !== b.dataset.guid.toUpperCase()).map((l, i) => Object.assign({}, l, { order: i + 1 })); await backend({ cmd: "set_links", dn: c.dn, links }); await reload(); draw(); } catch (e) { showAlert("error", errText(e)); }
      }));
    };
    draw();
  }

  function openLinkExisting(c, edit) {
    const linked = new Set(c.links.map((l) => l.guid));
    const avail = G.gpos.filter((g) => !linked.has(g.guid));
    if (!avail.length) { showAlert("info", "Every GPO is already linked here."); return; }
    openModal("Link an existing GPO", `<div class="form-row"><label>Group Policy Object</label><select id="lk-gpo">${avail.map((g) => `<option value="${esc(g.guid)}">${esc(g.name)}</option>`).join("")}</select></div>`, {
      buttons: [{ label: "Cancel", onClick: (close) => close() }, {
        label: "Link", className: "primary", onClick: async (close, node) => {
          const guid = $("#lk-gpo", node).value;
          close();
          await edit((ls) => { if (!ls.some((l) => l.guid === guid)) ls.push({ guid, order: ls.length + 1, enforced: false, disabled: false }); });
          showAlert("success", "GPO linked.");
        }
      }]
    });
  }

  function openNewGpo(linkDn) {
    const c = linkDn ? G.containers.find((x) => x.dn === linkDn) : null;
    openModal("New GPO", `<div class="form-row"><label>Name</label><input type="text" id="ng-name" placeholder="e.g. Workstation security baseline"></div>
      ${c ? `<label class="inline-check"><input type="checkbox" id="ng-link" checked> Also link it to <strong>${esc(c.type === "domain" ? G.info.realm.toLowerCase() : c.name)}</strong></label>` : ""}`, {
      buttons: [{ label: "Cancel", onClick: (close) => close() }, {
        label: "Create", className: "primary", onClick: async (close, node) => {
          const name = $("#ng-name", node).value.trim();
          if (!name) { showAlert("error", "A name is required."); return; }
          try {
            const guid = await backend({ cmd: "create_gpo", name });
            if (c && $("#ng-link", node) && $("#ng-link", node).checked) {
              const fresh = (await backend({ cmd: "list_containers" })).find((x) => x.dn === c.dn);
              const links = fresh.links.slice().sort((a, b) => a.order - b.order).map((l) => Object.assign({}, l));
              links.push({ guid, order: links.length + 1, enforced: false, disabled: false });
              await backend({ cmd: "set_links", dn: c.dn, links });
            }
            close(); await reload(); G.sel = { kind: "gpo", id: guid }; G.tab = "scope"; G.expanded.add("__gpos"); renderTree(); renderDetail();
            showAlert("success", `GPO "${name}" created.`);
          } catch (e) { showAlert("error", errText(e), { sticky: true }); }
        }
      }]
    });
  }

  /* ---- GPO detail ---- */
  function renderGpo(d, g) {
    if (!g) { d.innerHTML = `<div class="empty-state">GPO not found.</div>`; return; }
    const tab = ["scope", "details", "settings"].includes(G.tab) ? G.tab : "scope";
    d.innerHTML = `<div class="gpmc-gpohead"><div><h3 class="gpmc-h">${esc(g.name)}</h3><div class="muted small-path">${esc(g.guid)}</div></div>
      <div class="gpmc-actions" style="margin:0"><button class="primary" id="g-edit">Edit&hellip;</button><button class="small" id="g-rename">Rename&hellip;</button><button class="small danger" id="g-del">Delete</button></div></div>
      ${tabsHtml([["scope", "Scope"], ["details", "Details"], ["settings", "Settings"]], tab)}<div class="gpmc-body" id="g-body"></div>`;
    $$(".gtab", d).forEach((b) => b.onclick = () => { G.tab = b.dataset.tab; renderDetail(); });
    $("#g-edit", d).onclick = () => openEditor(g.guid);
    $("#g-rename", d).onclick = () => openModal("Rename GPO", `<div class="form-row"><label>Name</label><input type="text" id="rn-name" value="${esc(g.name)}"></div>`, {
      buttons: [{ label: "Cancel", onClick: (c) => c() }, { label: "Rename", className: "primary", onClick: async (close, node) => {
        try { await backend({ cmd: "set_gpo_attr", guid: g.guid, name: $("#rn-name", node).value }); close(); await reload(); renderTree(); renderDetail(); } catch (e) { showAlert("error", errText(e)); }
      } }]
    });
    $("#g-del", d).onclick = () => confirmModal(`Delete the GPO "${g.name}"? It is removed from every container it is linked to, and its SYSVOL files are deleted. This cannot be undone.`, async () => {
      try { await backend({ cmd: "delete_gpo", guid: g.guid }); G.sel = { kind: "gpos", id: "__gpos" }; await reload(); renderTree(); renderDetail(); showAlert("success", "GPO deleted."); } catch (e) { showAlert("error", errText(e)); }
    });
    const body = $("#g-body", d);
    if (tab === "scope") {
      const where = [];
      for (const c of G.containers) for (const l of c.links) if (l.guid.toUpperCase() === g.guid.toUpperCase()) where.push({ c, l });
      body.innerHTML = `<p class="muted">Containers this GPO is linked to.</p>${where.length ? `<table class="data-table"><thead><tr><th>Location</th><th>Enforced</th><th>Link enabled</th><th>Path</th></tr></thead><tbody>${where.map(({ c, l }) => `<tr><td>${esc(c.type === "domain" ? G.info.realm.toLowerCase() : c.name)}</td><td>${l.enforced ? "Yes" : "No"}</td><td>${l.disabled ? "No" : "Yes"}</td><td><code class="inline">${esc(c.dn)}</code></td></tr>`).join("")}</tbody></table>` : `<div class="empty-state">This GPO is not linked anywhere, so it applies to nobody. Select a domain or OU and use <em>Link an existing GPO</em>.</div>`}
        <div class="alert info" style="margin-top:12px">Security filtering (which users/groups the GPO applies to) and WMI filters are not editable here. By default a GPO applies to <em>Authenticated Users</em>.</div>`;
    } else if (tab === "details") {
      body.innerHTML = `<div class="kv"><div>Domain</div><div>${esc(G.info.realm.toLowerCase())}</div><div>Unique ID</div><div><code class="inline">${esc(g.guid)}</code></div>
        <div>Created</div><div>${esc(fmtAdTime(g.created))}</div><div>Modified</div><div>${esc(fmtAdTime(g.changed))}</div>
        <div>Computer version</div><div>${g.machine_version}</div><div>User version</div><div>${g.user_version}</div>
        <div>GPO status</div><div><select id="g-status">${FLAG_LABEL.map((l, i) => `<option value="${i}" ${i === g.flags ? "selected" : ""}>${esc(l)}</option>`).join("")}</select></div>
        <div>Client-side extensions</div><div>${esc([...new Set([...C.extNames(g.machine_exts), ...C.extNames(g.user_exts)])].join(", ") || "none registered yet")}</div>
        <div>SYSVOL path</div><div><code class="inline">${esc(g.path)}</code></div></div>`;
      $("#g-status", body).onchange = async (e) => { try { await backend({ cmd: "set_gpo_attr", guid: g.guid, flags: Number(e.target.value) }); await reload(); renderDetail(); showAlert("success", "GPO status updated."); } catch (er) { showAlert("error", errText(er)); } };
    } else {
      spin(body);
      buildReport(g).then((html) => { body.innerHTML = html; }).catch((e) => { body.innerHTML = `<div class="alert error">${esc(errText(e))}</div>`; });
    }
  }

  /* =====================================================================
   * EDITOR (Group Policy Management Editor)
   * ===================================================================== */
  const INF_PATH = "Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf";
  const WELL_KNOWN = {
    "S-1-1-0": "Everyone", "S-1-5-11": "Authenticated Users", "S-1-5-18": "SYSTEM", "S-1-5-19": "LOCAL SERVICE", "S-1-5-20": "NETWORK SERVICE", "S-1-5-4": "INTERACTIVE", "S-1-5-2": "NETWORK",
    "S-1-5-6": "SERVICE", "S-1-5-32-544": "Administrators", "S-1-5-32-545": "Users", "S-1-5-32-546": "Guests", "S-1-5-32-547": "Power Users", "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators", "S-1-5-32-550": "Print Operators", "S-1-5-32-551": "Backup Operators", "S-1-5-32-555": "Remote Desktop Users", "S-1-5-32-573": "Event Log Readers"
  };
  const PRIVS = GpoCatalogs.privileges;
  const SEC_OPTIONS = GpoCatalogs.secOptions;
  const PW_FIELDS = [
    { key: "PasswordHistorySize", label: "Enforce password history", unit: "passwords remembered", min: 0, max: 24, def: 24 },
    { key: "MaximumPasswordAge", label: "Maximum password age", unit: "days (0 = never expires)", min: 0, max: 999, def: 42 },
    { key: "MinimumPasswordAge", label: "Minimum password age", unit: "days", min: 0, max: 998, def: 1 },
    { key: "MinimumPasswordLength", label: "Minimum password length", unit: "characters", min: 0, max: 128, def: 12 },
    { key: "PasswordComplexity", label: "Password must meet complexity requirements", bool: true, def: 1 },
    { key: "ClearTextPassword", label: "Store passwords using reversible encryption", bool: true, def: 0 }
  ];
  const LOCK_FIELDS = [
    { key: "LockoutBadCount", label: "Account lockout threshold", unit: "invalid logon attempts (0 = never lock out)", min: 0, max: 999, def: 5 },
    { key: "LockoutDuration", label: "Account lockout duration", unit: "minutes (-1 = until an administrator unlocks)", min: -1, max: 99999, def: 15 },
    { key: "ResetLockoutCount", label: "Reset account lockout counter after", unit: "minutes", min: 1, max: 99999, def: 15 }
  ];

  const Cls = (cls) => (cls === "machine" ? "Machine" : "User");
  async function refreshMeta() { G.gpos = await backend({ cmd: "list_gpos" }); const g = gpoByGuid(G.ed.guid); const m = $("#ed-meta"); if (g && m) m.textContent = `Computer v${g.machine_version} \u00b7 User v${g.user_version}`; }

  async function mutatePol(cls, fn) {
    const cur = await backend({ cmd: "read_pol", guid: G.ed.guid, class: cls });
    const next = fn(cur);
    await backend({ cmd: "write_pol", guid: G.ed.guid, class: cls, entries: next });
    G.ed.pol[cls] = next; await refreshMeta();
  }
  async function readInf(guid) { const b = await readFile(guid || G.ed.guid, INF_PATH); return b ? C.parseInf(C.decodeText(b)) : { sections: [] }; }
  async function mutateInf(fn) {
    const m = await readInf(); fn(m);
    await writeFile(G.ed.guid, INF_PATH, C.encodeUtf16le(C.serializeInf(m)), { bump: ["machine"], exts: { machine: [[C.CSE.security.cse, C.CSE.security.machine]] } });
    await refreshMeta();
  }

  function catNodes(tree, prefix) { return tree.map((c) => ({ id: prefix + "/" + c.id, label: c.name, cat: c, children: catNodes(c.children, prefix) })); }
  const PH = {
    "cc/sw": ["Software Settings (Software installation)", "MSI package deployment stores application objects in Active Directory and Windows Installer advertisement data. Samba has no tooling for it; manage it from a Windows PC with RSAT."],
    "uc/sw": ["Software Settings (Software installation)", "MSI package deployment stores application objects in Active Directory and Windows Installer advertisement data. Samba has no tooling for it; manage it from a Windows PC with RSAT."],
    "cc/nrpt": ["Name Resolution Policy", "The NRPT (used by DirectAccess / DNSSEC) is stored as many GUID-named registry subkeys with binary-encoded fields. Use RSAT, or Administrative Templates \u2192 Network \u2192 DNS Client for the common DNS settings."],
    "cc/printers": ["Deployed Printers", "Deployed printers are stored as connection objects in Active Directory (msPrintConnectionPolicy) and applied with PushPrinterConnections. Use RSAT / Print Management, or Preferences."],
    "uc/printers": ["Deployed Printers", "Deployed printers are stored as connection objects in Active Directory (msPrintConnectionPolicy) and applied with PushPrinterConnections. Use RSAT / Print Management, or Preferences."],
    "cc/qos": ["Policy-based QoS", "Not implemented in this editor. Use RSAT."],
    "uc/qos": ["Policy-based QoS", "Not implemented in this editor. Use RSAT."],
    "uc/folderredir": ["Folder Redirection", "Folder Redirection uses a dedicated fdeploy.ini format per folder and per security group. Not implemented; use RSAT."],
    "cc/sec/kerberos": ["Kerberos Policy", "Samba's AD DC takes its Kerberos ticket lifetimes from the directory/smb.conf, not from a GPO, so editing it here would have no effect."],
    "cc/sec/eventlog": ["Event Log", "Not implemented in this editor. Use RSAT."],
    "cc/sec/restricted": ["Restricted Groups", "Not implemented in this editor. Use RSAT (or Preferences \u2192 Local Users and Groups on a Windows admin PC)."],
    "cc/sec/services": ["System Services", "Not implemented in this editor. Use RSAT."],
    "cc/sec/registry": ["Registry (security descriptors)", "This node sets permissions (ACLs) on registry keys. Not implemented; use RSAT. To set registry *values*, use Preferences \u2192 Registry or Administrative Templates."],
    "cc/sec/filesystem": ["File System (security descriptors)", "This node sets permissions (ACLs) on files and folders. Not implemented; use RSAT."],
    "cc/sec/wired": ["Wired Network (IEEE 802.3) Policies", "Not implemented in this editor. Use RSAT."],
    "cc/sec/wireless": ["Wireless Network (IEEE 802.11) Policies", "Not implemented in this editor. Use RSAT."],
    "cc/sec/nlm": ["Network List Manager Policies", "Not implemented in this editor. Use RSAT."],
    "cc/sec/pki": ["Public Key Policies", "Certificate stores (trusted roots, auto-enrollment, EFS) are stored as binary certificate blobs. Not implemented; use RSAT."],
    "cc/sec/srp": ["Software Restriction Policies", "Deprecated by Microsoft in favour of AppLocker / App Control. Not implemented; use RSAT if you still need it."],
    "cc/sec/applocker": ["Application Control Policies (AppLocker)", "AppLocker rules are XML documents stored in per-rule registry subkeys. Not implemented; author the policy on a Windows PC with RSAT or export/import it with PowerShell (Set-AppLockerPolicy -Ldap)."],
    "cc/sec/ipsec": ["IP Security Policies", "Not implemented in this editor. Use RSAT."]
  };
  const phNode = (id) => ({ id, label: PH[id][0].replace(/ \(.*\)$/, ""), ph: true });

  function edTree() {
    const adm = (cls, p) => ({ id: p + "/admin", label: "Administrative Templates", children: catNodes(C.buildTree(G.ed.tpl.models, cls), p + "/admin").concat([{ id: p + "/admin/__all", label: "All Settings", all: cls }]) });
    return [
      { id: "cc", label: "Computer Configuration", children: [
        { id: "cc/pol", label: "Policies", children: [
          phNode("cc/sw"),
          { id: "cc/win", label: "Windows Settings", children: [
            phNode("cc/nrpt"),
            { id: "cc/scripts", label: "Scripts (Startup/Shutdown)" },
            phNode("cc/printers"),
            { id: "cc/sec", label: "Security Settings", children: [
              { id: "cc/sec/acct", label: "Account Policies", children: [{ id: "cc/sec/pw", label: "Password Policy" }, { id: "cc/sec/lockout", label: "Account Lockout Policy" }, phNode("cc/sec/kerberos")] },
              { id: "cc/sec/local", label: "Local Policies", children: [{ id: "cc/sec/legacyaudit", label: "Audit Policy" }, { id: "cc/sec/rights", label: "User Rights Assignment" }, { id: "cc/sec/options", label: "Security Options" }] },
              phNode("cc/sec/eventlog"), phNode("cc/sec/restricted"), phNode("cc/sec/services"), phNode("cc/sec/registry"), phNode("cc/sec/filesystem"), phNode("cc/sec/wired"),
              { id: "cc/sec/firewall", label: "Windows Defender Firewall with Advanced Security" },
              phNode("cc/sec/nlm"), phNode("cc/sec/wireless"), phNode("cc/sec/pki"), phNode("cc/sec/srp"), phNode("cc/sec/applocker"), phNode("cc/sec/ipsec"),
              { id: "cc/sec/adv", label: "Advanced Audit Policy Configuration", children: [{ id: "cc/sec/audit", label: "System Audit Policies" }] }] },
            phNode("cc/qos")] },
          adm("Machine", "cc/pol")] },
        { id: "cc/pref", label: "Preferences", children: [{ id: "cc/pref/win", label: "Windows Settings", children: [{ id: "cc/pref/registry", label: "Registry" }] }] }] },
      { id: "uc", label: "User Configuration", children: [
        { id: "uc/pol", label: "Policies", children: [
          phNode("uc/sw"),
          { id: "uc/win", label: "Windows Settings", children: [{ id: "uc/scripts", label: "Scripts (Logon/Logoff)" }, phNode("uc/printers"), phNode("uc/folderredir"), phNode("uc/qos")] },
          adm("User", "uc/pol")] },
        { id: "uc/pref", label: "Preferences", children: [{ id: "uc/pref/win", label: "Windows Settings", children: [{ id: "uc/pref/drives", label: "Drive Maps" }, { id: "uc/pref/registry", label: "Registry" }] }] }] }
    ];
  }
  function flat(nodes, map) { map = map || {}; for (const n of nodes) { map[n.id] = n; if (n.children) flat(n.children, map); } return map; }

  async function openEditor(guid) {
    const g = gpoByGuid(guid); const root = $("#gpo-root"); spin(root);
    try {
      const tpl = await loadTemplates(false, (m) => { root.innerHTML = `<span class="spinner"></span> ${esc(m)}`; });
      const [m, u] = await Promise.all([backend({ cmd: "read_pol", guid, class: "machine" }), backend({ cmd: "read_pol", guid, class: "user" })]);
      G.ed = { guid, name: g.name, pol: { machine: m, user: u }, node: "cc/pol/admin", tpl, exp: new Set(["cc", "uc", "cc/pol", "uc/pol"]), filter: "", configuredOnly: false, sel: null };
    } catch (e) { showAlert("error", errText(e)); renderManager(); return; }
    renderEditor();
  }

  function renderEditor() {
    const g = gpoByGuid(G.ed.guid); const root = $("#gpo-root");
    const t = G.ed.tpl;
    const tplNote = t.source === "central" ? `${t.policyCount} policies from ${t.files} ADMX files in the domain Central Store` : `Built-in templates (${t.policyCount} common policies). Import ADMX files for the full Windows set.`;
    root.innerHTML = `
      <div class="sadc-toolbar ed-bar">
        <div class="left"><button class="small" id="ed-back">&larr; Group Policy Management</button><span class="gpo-title" style="margin-left:12px">${esc(g.name)}</span><span class="muted">&nbsp;[${esc(G.info.realm.toLowerCase())}] &middot; <span id="ed-meta">Computer v${g.machine_version} &middot; User v${g.user_version}</span></span></div>
        <div class="right"><span class="muted small-path" style="margin-right:8px">${esc(tplNote)}</span><button class="small" id="ed-admx">Templates&hellip;</button></div>
      </div>
      ${g.flags ? `<div class="alert warning">GPO status: <strong>${esc(FLAG_LABEL[g.flags])}</strong>. Disabled sections are stored but not applied by clients.</div>` : ""}
      <div class="gpmc ed"><div class="gpmc-tree" id="ed-tree"></div><div class="gpmc-detail" id="ed-pane"></div></div>`;
    $("#ed-back").onclick = () => { G.ed = null; load(); };
    $("#ed-admx").onclick = openTemplatesDialog;
    renderEdTree(); renderEdPage();
  }

  function renderEdTree() {
    const tree = edTree(); const map = flat(tree); G.ed.map = map;
    const draw = (n, depth) => {
      const kids = n.children || []; const open = G.ed.exp.has(n.id);
      let h = `<div class="tn${G.ed.node === n.id ? " selected" : ""}" data-id="${esc(n.id)}" style="padding-left:${depth * 14 + 6}px"><span class="tw">${kids.length ? (open ? "&#9662;" : "&#9656;") : ""}</span><span class="ti">${kids.length ? "&#128193;" : "&#128196;"}</span>${esc(n.label)}</div>`;
      if (open) for (const k of kids) h += draw(k, depth + 1);
      return h;
    };
    const el = $("#ed-tree"); el.innerHTML = tree.map((n) => draw(n, 0)).join("");
    $$(".tn", el).forEach((d) => d.addEventListener("click", (ev) => {
      const id = d.dataset.id; const n = map[id];
      if (n.children && n.children.length) { if (ev.target.classList.contains("tw") || G.ed.node === id) G.ed.exp.has(id) ? G.ed.exp.delete(id) : G.ed.exp.add(id); else G.ed.exp.add(id); }
      G.ed.node = id; G.ed.sel = null; renderEdTree(); renderEdPage();
    }));
  }

  function renderEdPage() {
    const pane = $("#ed-pane"); const id = G.ed.node; const n = G.ed.map[id];
    if (!n) return;
    const cls = id.startsWith("cc") ? "machine" : "user";
    const run = (p) => p.catch((e) => { pane.innerHTML = `<div class="alert error">${esc(errText(e))}</div>`; });
    if (n.cat || n.all || id.endsWith("/admin")) return pagePolicies(pane, cls, n);
    if (id === "cc/sec/pw") return run(pageSecurityFields(pane, "Password Policy", PW_FIELDS, true));
    if (id === "cc/sec/lockout") return run(pageSecurityFields(pane, "Account Lockout Policy", LOCK_FIELDS, false));
    if (id === "cc/sec/rights") return run(pageRights(pane));
    if (id === "cc/sec/options") return run(pageSecOptions(pane));
    if (id === "cc/sec/audit") return run(pageAdvAudit(pane));
    if (id === "cc/sec/legacyaudit") return run(pageLegacyAudit(pane));
    if (id === "cc/sec/firewall") return run(pageFirewall(pane));
    if (n.ph) return pagePlaceholder(pane, id);
    if (id.endsWith("/scripts")) return run(pageScripts(pane, cls));
    if (id === "cc/pref/registry" || id === "uc/pref/registry") return run(pagePrefRegistry(pane, cls));
    if (id === "uc/pref/drives") return run(pagePrefDrives(pane));
    pane.innerHTML = `<h3 class="gpmc-h">${esc(n.label)}</h3><p class="muted">Select a node on the left to view its settings.</p>`;
  }

  /* ---------------- Administrative Templates page ---------------- */
  const supportedText = (p) => (G.supported && G.supported[p.supportedOnRef]) || p.supportedOn || "";
  const STATE_LABEL = { notconfigured: "Not configured", enabled: "Enabled", disabled: "Disabled" };
  function pagePolicies(pane, cls, n) {
    const t = G.ed.tpl;
    let list;
    if (n.all) list = t.models.flatMap((m) => m.policies).filter((p) => p.cls === "Both" || p.cls === Cls(cls));
    else if (n.cat) list = n.cat.policies;
    else list = [];
    const entries = G.ed.pol[cls];
    const q = G.ed.filter.toLowerCase();
    const keys = C.keySet(entries);
    // cheap text filter first, then compute state only where a matching registry key exists
    let cand = q ? list.filter((p) => p.displayName.toLowerCase().includes(q) || (p.explain || "").toLowerCase().includes(q)) : list;
    const stateOf = (p) => (C.policyMayBeConfigured(p, keys) ? C.getPolicyState(entries, p).state : "notconfigured");
    if (G.ed.configuredOnly) cand = cand.filter((p) => stateOf(p) !== "notconfigured");
    const total = cand.length; const LIMIT = 400;
    cand = cand.slice().sort((a, b) => a.displayName.localeCompare(b.displayName));
    let rows = cand.slice(0, LIMIT).map((p) => ({ p, st: stateOf(p) }));
    const isRoot = n.id.endsWith("/admin");
    const t0 = G.ed.tpl.source === "builtin" ? `<div class="alert info">Showing the built-in template set. To get the full Windows policy catalog, download the ADMX templates for your Windows version from Microsoft and use <strong>Templates&hellip; &rarr; Import</strong>.</div>` : "";
    pane.innerHTML = `<h3 class="gpmc-h">${esc(n.label)}</h3>${isRoot ? t0 + `<p class="muted">Expand the tree to browse categories, or open <strong>All Settings</strong> to search every policy.</p>` : ""}
      ${isRoot ? "" : `<div class="ed-filter"><input type="text" id="pf-q" placeholder="Filter settings\u2026" value="${esc(G.ed.filter)}"><label class="inline-check"><input type="checkbox" id="pf-conf" ${G.ed.configuredOnly ? "checked" : ""}> Configured only</label><span class="muted">${total > LIMIT ? `Showing the first ${LIMIT} of ${total} settings \u2014 type in the filter to narrow down` : `${total} setting${total === 1 ? "" : "s"}`}</span></div>
      ${rows.length ? `<div class="ed-table"><table class="data-table"><thead><tr><th>Setting</th><th>State</th></tr></thead><tbody>${rows.map((r) => `<tr data-id="${esc(r.p.id)}" class="${G.ed.sel === r.p.id ? "sel" : ""}"><td>${esc(r.p.displayName)}</td><td class="st-${r.st}">${STATE_LABEL[r.st]}</td></tr>`).join("")}</tbody></table></div>` : `<div class="empty-state">No settings.</div>`}
      <div class="ed-help" id="pf-help"></div>`}`;
    if (isRoot) return;
    const help = $("#pf-help", pane);
    const showHelp = () => {
      const p = rows.find((r) => r.p.id === G.ed.sel);
      help.innerHTML = p ? `<div class="ed-help-head"><strong>${esc(p.p.displayName)}</strong><button class="small primary" id="pf-edit">Edit setting&hellip;</button></div><pre class="explain">${esc(p.p.explain || "No description available.")}</pre>${supportedText(p.p) ? `<div class="muted">Supported on: ${esc(supportedText(p.p))}</div>` : ""}` : `<span class="muted">Select a setting to see its description. Double-click to edit.</span>`;
      const b = $("#pf-edit", help); if (b) b.onclick = () => openPolicyDialog(cls, p.p);
    };
    showHelp();
    $$("tr[data-id]", pane).forEach((tr) => { tr.onclick = () => { G.ed.sel = tr.dataset.id; $$("tr[data-id]", pane).forEach((x) => x.classList.toggle("sel", x === tr)); showHelp(); }; tr.ondblclick = () => openPolicyDialog(cls, rows.find((r) => r.p.id === tr.dataset.id).p); });
    const qi = $("#pf-q", pane); qi.oninput = () => { G.ed.filter = qi.value; const pos = qi.selectionStart; pagePolicies(pane, cls, n); const q2 = $("#pf-q", pane); q2.focus(); q2.setSelectionRange(pos, pos); };
    $("#pf-conf", pane).onchange = (e) => { G.ed.configuredOnly = e.target.checked; pagePolicies(pane, cls, n); };
  }

  function elControlHtml(el, val) {
    const id = "el-" + el.id; const lab = `<label for="${esc(id)}">${esc(el.label)}</label>`;
    if (el.type === "decimal" || el.type === "longDecimal") return `<div class="form-row">${lab}<input type="number" id="${esc(id)}" min="${el.min}" max="${el.max}" value="${val === undefined ? (el.defaultValue !== undefined ? el.defaultValue : el.min) : val}"></div>`;
    if (el.type === "text") return `<div class="form-row">${lab}<input type="text" id="${esc(id)}" value="${esc(val === undefined ? (el.defaultValue || "") : val)}"></div>`;
    if (el.type === "boolean") return `<div class="form-row"><label class="inline-check"><input type="checkbox" id="${esc(id)}" ${val ? "checked" : ""}> ${esc(el.label)}</label></div>`;
    if (el.type === "enum") return `<div class="form-row">${lab}<select id="${esc(id)}">${el.items.map((it, i) => `<option value="${i}" ${i === val ? "selected" : ""}>${esc(it.name)}</option>`).join("")}</select></div>`;
    if (el.type === "multiText") return `<div class="form-row">${lab}<textarea id="${esc(id)}" rows="4">${esc((val || []).join("\n"))}</textarea></div>`;
    if (el.type === "list") {
      const lines = (val || []).map((x) => (el.explicitValue ? x.name + "=" + x.value : x)).join("\n");
      return `<div class="form-row">${lab}<textarea id="${esc(id)}" rows="5" placeholder="${el.explicitValue ? "name=value, one per line" : "one entry per line"}">${esc(lines)}</textarea></div>`;
    }
    return "";
  }
  function readElValues(node, pol) {
    const v = {};
    for (const el of pol.elements) {
      const c = node.querySelector("#" + CSS.escape("el-" + el.id)); if (!c) continue;
      if (el.type === "decimal" || el.type === "longDecimal") v[el.id] = c.value === "" ? undefined : Number(c.value);
      else if (el.type === "boolean") v[el.id] = c.checked;
      else if (el.type === "enum") v[el.id] = Number(c.value);
      else if (el.type === "multiText") v[el.id] = c.value.split(/\r?\n/).filter(Boolean);
      else if (el.type === "list") { const lines = c.value.split(/\r?\n/).map((x) => x.trim()).filter(Boolean); v[el.id] = el.explicitValue ? lines.map((l) => { const i = l.indexOf("="); return { name: i < 0 ? l : l.slice(0, i), value: i < 0 ? "" : l.slice(i + 1) }; }) : lines; }
      else v[el.id] = c.value;
    }
    return v;
  }
  function validatePolicy(pol, state, vals) {
    if (state !== "enabled") return null;
    for (const el of pol.elements) {
      const v = vals[el.id];
      if ((el.type === "decimal" || el.type === "longDecimal") && (v === undefined || isNaN(v) || v < el.min || v > el.max)) return `"${el.label}" must be a number between ${el.min} and ${el.max}.`;
      if (el.type === "text" && el.required && !v) return `"${el.label}" is required.`;
    }
    const listOnly = !pol.valueName && !(pol.enabledList && pol.enabledList.length) && pol.elements.length && pol.elements.every((e) => e.type === "list");
    if (listOnly && pol.elements.every((e) => !(vals[e.id] || []).length)) return "Add at least one entry. (An Enabled list policy with no entries is stored identically to Disabled.)";
    return null;
  }

  function openPolicyDialog(cls, pol) {
    const cur = C.getPolicyState(G.ed.pol[cls], pol);
    const modal = openModal(pol.displayName, `
      <div class="pol-radios"><label><input type="radio" name="pstate" value="notconfigured"> Not Configured</label><label><input type="radio" name="pstate" value="enabled"> Enabled</label><label><input type="radio" name="pstate" value="disabled"> Disabled</label></div>
      <div class="pol-split"><div class="pol-opts" id="pol-opts">${pol.elements.map((el) => elControlHtml(el, cur.values[el.id])).join("") || `<span class="muted">This setting has no options.</span>`}</div>
      <div class="pol-help"><div class="muted">Supported on: ${esc(supportedText(pol) || "\u2014")}</div><pre class="explain">${esc(pol.explain || "")}</pre></div></div>
      <div class="muted small-path">${esc(Cls(cls))} \u00b7 ${esc(pol.key || "")}${pol.valueName ? "\\" + esc(pol.valueName) : ""}</div>`, {
      wide: true, buttons: [{ label: "Cancel", onClick: (c) => c() }, {
        label: "OK", className: "primary", onClick: async (close, node) => {
          const state = $("input[name=pstate]:checked", node).value; const vals = readElValues(node, pol);
          const err = validatePolicy(pol, state, vals); if (err) { showAlert("error", err); return; }
          try { await mutatePol(cls, (entries) => C.applyPolicy(entries, pol, state, vals)); close(); renderEdPage(); showAlert("success", "Setting saved."); }
          catch (e) { showAlert("error", errText(e), { sticky: true }); }
        }
      }]
    });
    const node = modal.node;
    $(`input[name=pstate][value=${cur.state}]`, node).checked = true;
    const sync = () => { const on = $("input[name=pstate]:checked", node).value === "enabled"; $$("#pol-opts input,#pol-opts select,#pol-opts textarea", node).forEach((x) => x.disabled = !on); };
    $$("input[name=pstate]", node).forEach((r) => r.onchange = sync); sync();
  }

  /* ---------------- Security Settings ---------------- */
  async function pageSecurityFields(pane, title, fields, isPassword) {
    spin(pane);
    const m = await readInf();
    const rows = fields.map((f) => {
      const v = C.infGet(m, "System Access", f.key); const on = v !== undefined;
      const ctl = f.bool ? `<select data-k="${f.key}"><option value="1" ${v === "1" || (!on && f.def === 1) ? "selected" : ""}>Enabled</option><option value="0" ${v === "0" || (!on && f.def === 0) ? "selected" : ""}>Disabled</option></select>`
        : `<input type="number" data-k="${f.key}" min="${f.min}" max="${f.max}" value="${on ? esc(v) : f.def}">`;
      return `<tr><td><input type="checkbox" class="def" data-k="${f.key}" ${on ? "checked" : ""}></td><td>${esc(f.label)}</td><td>${ctl}</td><td class="muted">${esc(f.unit || "")}</td></tr>`;
    }).join("");
    pane.innerHTML = `<h3 class="gpmc-h">${esc(title)}</h3>
      <div class="alert warning">Samba's AD DC enforces the <em>domain</em> password and lockout policy from the directory (see <code>samba-tool domain passwordsettings</code>), not from this GPO. These settings still apply to <strong>local accounts</strong> on Windows computers when the GPO is linked to an OU containing them.</div>
      <table class="data-table"><thead><tr><th>Define</th><th>Policy</th><th>Setting</th><th></th></tr></thead><tbody>${rows}</tbody></table>
      <div class="gpmc-actions"><button class="primary" id="sf-apply">Apply</button></div>`;
    $("#sf-apply", pane).onclick = async () => {
      try {
        const upd = {};
        for (const f of fields) {
          const on = $(`.def[data-k=${f.key}]`, pane).checked; const c = $(`[data-k=${f.key}]:not(.def)`, pane);
          if (on) { const n = Number(c.value); if (isNaN(n) || (!f.bool && (n < f.min || n > f.max))) throw new Error(`"${f.label}" must be between ${f.min} and ${f.max}.`); upd[f.key] = n; } else upd[f.key] = null;
        }
        await mutateInf((mm) => { for (const k in upd) C.infSet(mm, "System Access", k, upd[k]); });
        showAlert("success", "Security settings saved.");
      } catch (e) { showAlert("error", errText(e)); }
    };
  }

  const unq = (v) => v.replace(/^"(.*)"$/, "$1");
  async function pageSecOptions(pane) {
    spin(pane); const m = await readInf();
    const groups = {}; SEC_OPTIONS.forEach((o, i) => { (groups[o.group] = groups[o.group] || []).push([o, i]); });
    const row = ([o, i]) => {
      const rv = C.infGetRegValue(m, o.path); const on = !!rv; const val = on ? unq(rv.value) : "";
      let ctl;
      if (o.kind === "bool") ctl = `<select data-i="${i}"><option value="1" ${val === "1" ? "selected" : ""}>Enabled</option><option value="0" ${val === "0" ? "selected" : ""}>Disabled</option></select>`;
      else if (o.kind === "num") ctl = `<input type="number" data-i="${i}" ${o.min != null ? `min="${o.min}" max="${o.max}"` : 'min="0"'} value="${on ? esc(val) : (o.def != null ? o.def : 0)}"> <span class="muted">${esc(o.unit || "")}</span>`;
      else if (o.kind === "enum") ctl = `<select data-i="${i}">${o.options.map(([v, l]) => `<option value="${v}" ${String(v) === val ? "selected" : ""}>${esc(l)}</option>`).join("")}</select>`;
      else if (o.kind === "bitmask") { const n = Number(val) || 0; ctl = o.options.map(([v, l]) => `<label class="inline-check" style="display:flex"><input type="checkbox" data-i="${i}" data-bit="${v}" ${(n & v) === v ? "checked" : ""}> ${esc(l)}</label>`).join(""); }
      else if (o.kind === "multi") ctl = `<textarea data-i="${i}" rows="3">${esc(val.split(",").join("\n"))}</textarea>`;
      else ctl = `<input type="text" data-i="${i}" value="${esc(val)}">`;
      return `<tr data-q="${esc(o.label.toLowerCase())}"><td><input type="checkbox" class="def" data-i="${i}" ${on ? "checked" : ""}></td><td>${esc(o.label.replace(/^[^:]+:\s*/, ""))}</td><td>${ctl}</td></tr>`;
    };
    pane.innerHTML = `<h3 class="gpmc-h">Security Options</h3><p class="muted">${SEC_OPTIONS.length} settings from Windows' own security template definitions. Tick <em>Define</em> to configure one; unticked settings are left untouched on the clients.</p>
      <div class="ed-filter"><input type="text" id="so-q" placeholder="Filter settings\u2026"><label class="inline-check"><input type="checkbox" id="so-conf"> Defined only</label></div>
      ${Object.keys(groups).sort().map((g) => `<details class="so-group" open><summary>${esc(g)} <span class="muted">(${groups[g].length})</span></summary><table class="data-table"><tbody>${groups[g].map(row).join("")}</tbody></table></details>`).join("")}
      <div class="gpmc-actions"><button class="primary" id="so-apply">Apply</button></div>`;
    const filt = () => { const q = $("#so-q", pane).value.toLowerCase(), only = $("#so-conf", pane).checked;
      $$("tr[data-q]", pane).forEach((tr) => { const ok = (!q || tr.dataset.q.includes(q)) && (!only || tr.querySelector(".def").checked); tr.style.display = ok ? "" : "none"; });
      $$(".so-group", pane).forEach((d) => { d.style.display = $$("tr[data-q]", d).some((t) => t.style.display !== "none") ? "" : "none"; }); };
    $("#so-q", pane).oninput = filt; $("#so-conf", pane).onchange = filt;
    $("#so-apply", pane).onclick = async () => {
      try {
        await mutateInf((mm) => {
          SEC_OPTIONS.forEach((o, i) => {
            const on = $(`.def[data-i="${i}"]`, pane).checked;
            if (!on) { C.infSetRegValue(mm, o.path, null); return; }
            let v;
            if (o.kind === "bitmask") v = $$(`[data-i="${i}"][data-bit]`, pane).reduce((a, c) => a | (c.checked ? Number(c.dataset.bit) : 0), 0);
            else { const c = $(`[data-i="${i}"]:not(.def)`, pane); v = c.value; if (o.kind === "multi") v = v.split(/\r?\n/).filter(Boolean).join(","); }
            if (o.kind === "num") { const n = Number(v); if (v === "" || isNaN(n) || (o.min != null && (n < o.min || n > o.max))) throw new Error(`"${o.label}" needs a valid number.`); }
            if (o.type === 1 || o.type === 2) v = '"' + String(v).replace(/"/g, "") + '"';
            C.infSetRegValue(mm, o.path, o.type, v);
          });
        });
        showAlert("success", "Security options saved.");
      } catch (e) { showAlert("error", errText(e)); }
    };
  }

  /* ---------------- Audit: legacy categories + Advanced Audit Policy ---------------- */
  const LEGACY_AUDIT = [["AuditAccountLogon", "Audit account logon events"], ["AuditAccountManage", "Audit account management"], ["AuditDSAccess", "Audit directory service access"], ["AuditLogonEvents", "Audit logon events"], ["AuditObjectAccess", "Audit object access"], ["AuditPolicyChange", "Audit policy change"], ["AuditPrivilegeUse", "Audit privilege use"], ["AuditProcessTracking", "Audit process tracking"], ["AuditSystemEvents", "Audit system events"]];
  const auditSelect = (id, cur, withNC) => `<select data-id="${esc(id)}">${withNC ? `<option value="">Not configured</option>` : ""}${[0, 1, 2, 3].map((v) => `<option value="${v}" ${cur === v ? "selected" : ""}>${C.AUDIT_LABEL[v]}</option>`).join("")}</select>`;
  async function pageLegacyAudit(pane) {
    spin(pane); const m = await readInf();
    pane.innerHTML = `<h3 class="gpmc-h">Audit Policy (legacy categories)</h3>
      <div class="alert info">Modern baselines use <strong>Advanced Audit Policy Configuration</strong> instead. If you use both, enable the Security Option <em>Audit: Force audit policy subcategory settings&hellip; to override audit policy category settings</em> so the advanced settings win.</div>
      <table class="data-table"><thead><tr><th>Policy</th><th>Policy setting</th></tr></thead><tbody>${LEGACY_AUDIT.map(([k, l]) => { const v = C.infGet(m, "Event Audit", k); return `<tr><td>${esc(l)}</td><td>${auditSelect(k, v === undefined ? "" : Number(v), true)}</td></tr>`; }).join("")}</tbody></table>
      <div class="gpmc-actions"><button class="primary" id="la-apply">Apply</button></div>`;
    $("#la-apply", pane).onclick = async () => {
      try { await mutateInf((mm) => { for (const [k] of LEGACY_AUDIT) { const v = $(`select[data-id="${k}"]`, pane).value; C.infSet(mm, "Event Audit", k, v === "" ? null : v); } }); showAlert("success", "Audit policy saved."); } catch (e) { showAlert("error", errText(e)); }
    };
  }

  const AUDIT_PATH = "Machine/Microsoft/Windows NT/Audit/audit.csv";
  async function pageAdvAudit(pane) {
    spin(pane);
    const raw = await readFile(G.ed.guid, AUDIT_PATH); const rows = raw ? C.parseAuditCsv(C.decodeText(raw)) : [];
    const byGuid = new Map(rows.map((r) => [r.guid, r]));
    const known = new Set(GpoCatalogs.audit.flatMap((c) => c.subs.map((s) => s.guid)));
    const extra = rows.filter((r) => !known.has(r.guid));
    pane.innerHTML = `<h3 class="gpmc-h">System Audit Policies</h3>
      <p class="muted">Settings are stored in <code>audit.csv</code>. Only subcategories you configure are written.</p>
      ${GpoCatalogs.audit.map((c) => `<details class="so-group" open><summary>${esc(c.name)}</summary><table class="data-table"><tbody>${c.subs.map((sc) => { const r = byGuid.get(sc.guid); return `<tr><td>Audit ${esc(sc.name)}</td><td>${auditSelect(sc.guid, r ? r.value : "", true)}</td></tr>`; }).join("")}</tbody></table></details>`).join("")}
      ${extra.length ? `<p class="muted">${extra.length} additional subcategor${extra.length > 1 ? "ies" : "y"} defined in this GPO (newer Windows features) are preserved untouched.</p>` : ""}
      <div class="gpmc-actions"><button class="primary" id="aa-apply">Apply</button></div>`;
    $("#aa-apply", pane).onclick = async () => {
      try {
        const cur = await readFile(G.ed.guid, AUDIT_PATH); const keep = cur ? C.parseAuditCsv(C.decodeText(cur)).filter((r) => !known.has(r.guid)) : [];
        const out = [];
        for (const c of GpoCatalogs.audit) for (const sc of c.subs) { const v = $(`select[data-id="${sc.guid}"]`, pane).value; if (v !== "") out.push({ machine: "", target: "System", name: "Audit " + sc.name, guid: sc.guid, value: Number(v) }); }
        await writeFile(G.ed.guid, AUDIT_PATH, C.encodeUtf8(C.buildAuditCsv(keep.concat(out))), { bump: ["machine"], exts: { machine: [[C.CSE.audit.cse, C.CSE.audit.machine]] } });
        await refreshMeta(); showAlert("success", "Advanced audit policy saved.");
      } catch (e) { showAlert("error", errText(e)); }
    };
  }

  /* ---------------- Windows Defender Firewall with Advanced Security ---------------- */
  const FW_BASE = "Software\\Policies\\Microsoft\\WindowsFirewall\\";
  const FW_PROFILES = [["DomainProfile", "Domain Profile"], ["StandardProfile", "Private Profile"], ["PublicProfile", "Public Profile"]];
  const FW_FIELDS = [
    ["EnableFirewall", "Firewall state", "", [[1, "On (recommended)"], [0, "Off"]]],
    ["DefaultInboundAction", "Inbound connections", "", [[1, "Block (default)"], [0, "Allow"]]],
    ["DefaultOutboundAction", "Outbound connections", "", [[0, "Allow (default)"], [1, "Block"]]],
    ["DisableNotifications", "Display a notification", "", [[0, "Yes"], [1, "No"]]],
    ["AllowLocalPolicyMerge", "Apply local firewall rules", "", [[1, "Yes (default)"], [0, "No"]]],
    ["AllowLocalIPsecPolicyMerge", "Apply local connection security rules", "", [[1, "Yes (default)"], [0, "No"]]],
    ["LogDroppedPackets", "Log dropped packets", "Logging", [[1, "Yes"], [0, "No (default)"]]],
    ["LogSuccessfulConnections", "Log successful connections", "Logging", [[1, "Yes"], [0, "No (default)"]]]
  ];
  async function pageFirewall(pane) {
    const ui = G.ed.fw = G.ed.fw || { tab: "profiles" };
    spin(pane); const entries = await backend({ cmd: "read_pol", guid: G.ed.guid, class: "machine" }); G.ed.pol.machine = entries;
    const tabs = [["profiles", "Profiles"], ["In", "Inbound Rules"], ["Out", "Outbound Rules"]];
    const head = `<h3 class="gpmc-h">Windows Defender Firewall with Advanced Security</h3>${tabsHtml(tabs, ui.tab)}`;
    const wire = () => $$(".gtab", pane).forEach((b) => b.onclick = () => { ui.tab = b.dataset.tab; pageFirewall(pane); });
    if (ui.tab === "profiles") {
      const val = (sub, k) => { const e = C.findEntry(entries, FW_BASE + sub + (k[2] ? "\\" + k[2] : ""), k[0]); return e ? Number(e.data) : ""; };
      pane.innerHTML = head + `<p class="muted">Leave a setting on <em>Not configured</em> to let each computer decide.</p>` + FW_PROFILES.map(([sub, label]) => `<details class="so-group" open><summary>${label}</summary><table class="data-table"><tbody>
        ${FW_FIELDS.map((f) => `<tr><td>${esc(f[1])}</td><td><select data-p="${sub}" data-k="${f[0]}" data-sub="${f[2]}"><option value="">Not configured</option>${f[3].map(([v, l]) => `<option value="${v}" ${val(sub, [f[0], 0, f[2]]) === v ? "selected" : ""}>${esc(l)}</option>`).join("")}</select></td></tr>`).join("")}
        <tr><td>Log file size limit (KB)</td><td><input type="number" min="1" max="32767" data-p="${sub}" data-k="LogFileSize" data-sub="Logging" data-num="1" value="${esc((C.findEntry(entries, FW_BASE + sub + "\\Logging", "LogFileSize") || {}).data ?? "")}" placeholder="Not configured"></td></tr>
        <tr><td>Log file path</td><td><input type="text" data-p="${sub}" data-k="LogFilePath" data-sub="Logging" data-str="1" value="${esc((C.findEntry(entries, FW_BASE + sub + "\\Logging", "LogFilePath") || {}).data || "")}" placeholder="Not configured"></td></tr></tbody></table></details>`).join("") +
        `<div class="gpmc-actions"><button class="primary" id="fw-apply">Apply</button></div>`;
      wire();
      $("#fw-apply", pane).onclick = async () => {
        try {
          await mutatePol("machine", (cur) => {
            let out = cur.slice();
            for (const el of $$("[data-p]", pane)) {
              const key = FW_BASE + el.dataset.p + (el.dataset.sub ? "\\" + el.dataset.sub : ""); const name = el.dataset.k;
              out = out.filter((e) => !(e.key.toLowerCase() === key.toLowerCase() && e.name.toLowerCase() === name.toLowerCase()));
              if (el.value === "") continue;
              if (el.dataset.str) out.push({ key, name, type: C.REG.SZ, data: el.value });
              else { const n = Number(el.value); if (isNaN(n)) throw new Error("Log size must be a number."); out.push({ key, name, type: C.REG.DWORD, data: n }); }
            }
            return out;
          });
          showAlert("success", "Firewall profile settings saved.");
        } catch (e) { showAlert("error", errText(e)); }
      };
      return;
    }
    const dir = ui.tab;
    const rules = entries.filter((e) => e.key.toLowerCase() === C.FW_KEY.toLowerCase()).map((e) => ({ id: e.name, r: C.parseFwRule(e.data) })).filter((x) => x.r.dir === dir);
    pane.innerHTML = head + `${rules.length ? `<div class="ed-table"><table class="data-table"><thead><tr><th>Name</th><th>Enabled</th><th>Action</th><th>Protocol</th><th>${dir === "In" ? "Local" : "Remote"} port</th><th>Program</th><th>Profiles</th><th></th></tr></thead><tbody>${rules.map(({ id, r }) => `<tr data-id="${esc(id)}"><td>${esc(r.name)}</td><td>${r.active ? "Yes" : "No"}</td><td>${esc(r.action)}</td><td>${esc(C.FW_PROTO[r.protocol] || r.protocol || "Any")}</td><td>${esc((dir === "In" ? r.lport : r.rport).join(", ") || "Any")}</td><td>${esc(r.app || "Any")}</td><td>${esc(r.profiles.join(", ") || "All")}</td><td class="row-actions"><button class="small b-edit">Edit&hellip;</button><button class="small danger b-del">Delete</button></td></tr>`).join("")}</tbody></table></div>` : `<div class="empty-state">No ${dir === "In" ? "inbound" : "outbound"} rules in this GPO.</div>`}
      <div class="gpmc-actions"><button class="small" id="fw-new">New rule&hellip;</button></div><p class="muted">Rules defined here are enforced on every computer the GPO applies to, in addition to local rules (unless a profile sets <em>Apply local firewall rules</em> to No).</p>`;
    wire();
    const edit = (cur) => {
      const r = cur ? Object.assign({}, cur.r) : { version: "v2.31", action: "Allow", active: true, dir, protocol: "6", lport: [], rport: [], profiles: [], la4: [], ra4: [], app: "", svc: "", name: "", desc: "", group: "", extra: [] };
      const protoOpts = [["", "Any"], ["6", "TCP"], ["17", "UDP"], ["1", "ICMPv4"], ["58", "ICMPv6"]];
      openModal(cur ? "Edit rule" : `New ${dir === "In" ? "inbound" : "outbound"} rule`, `
        <div class="form-row"><label>Name</label><input type="text" id="fr-name" value="${esc(r.name)}"></div>
        <div class="form-row"><label>Description</label><input type="text" id="fr-desc" value="${esc(r.desc)}"></div>
        <div class="form-grid"><div class="form-row"><label>Action</label><select id="fr-act"><option ${r.action === "Allow" ? "selected" : ""}>Allow</option><option ${r.action === "Block" ? "selected" : ""}>Block</option></select></div>
        <div class="form-row"><label>Protocol</label><select id="fr-proto">${protoOpts.map(([v, l]) => `<option value="${v}" ${r.protocol === v ? "selected" : ""}>${l}</option>`).join("")}</select></div></div>
        <div class="form-grid"><div class="form-row"><label>Local port(s) (e.g. 80, 443, 5000-5010)</label><input type="text" id="fr-lp" value="${esc(r.lport.join(", "))}"></div>
        <div class="form-row"><label>Remote port(s)</label><input type="text" id="fr-rp" value="${esc(r.rport.join(", "))}"></div></div>
        <div class="form-row"><label>Remote IP addresses (comma separated; blank = any)</label><input type="text" id="fr-ra" value="${esc(r.ra4.join(", "))}" placeholder="10.0.0.0/255.0.0.0, 192.168.1.5"></div>
        <div class="form-row"><label>Program (blank = any)</label><input type="text" id="fr-app" value="${esc(r.app)}" placeholder="%SystemRoot%\\system32\\svchost.exe"></div>
        <div class="form-row"><label>Group</label><input type="text" id="fr-grp" value="${esc(r.group)}"></div>
        <div class="form-row"><label>Profiles (none ticked = all)</label><div>${["Domain", "Private", "Public"].map((p) => `<label class="inline-check" style="margin-right:14px"><input type="checkbox" class="fr-prof" value="${p}" ${r.profiles.includes(p) ? "checked" : ""}> ${p}</label>`).join("")}</div></div>
        <label class="inline-check"><input type="checkbox" id="fr-on" ${r.active ? "checked" : ""}> Enabled</label>`, {
        wide: true, buttons: [{ label: "Cancel", onClick: (c) => c() }, { label: "OK", className: "primary", onClick: async (close, node) => {
          try {
            const name = $("#fr-name", node).value.trim(); if (!name) throw new Error("A name is required.");
            const list = (id) => $(id, node).value.split(",").map((x) => x.trim()).filter(Boolean);
            for (const p of [...list("#fr-lp"), ...list("#fr-rp")]) if (!/^\d{1,5}(-\d{1,5})?$/.test(p) && !/^(RPC|RPC-EPMap|IPHTTPSIn|Teredo|PlayToDiscovery)$/i.test(p)) throw new Error(`"${p}" is not a valid port or port range.`);
            const nr = Object.assign({}, r, { name, desc: $("#fr-desc", node).value, action: $("#fr-act", node).value, protocol: $("#fr-proto", node).value, lport: list("#fr-lp"), rport: list("#fr-rp"), ra4: list("#fr-ra"), app: $("#fr-app", node).value.trim(), group: $("#fr-grp", node).value.trim(), active: $("#fr-on", node).checked, profiles: $$(".fr-prof", node).filter((c) => c.checked).map((c) => c.value), dir });
            if ((nr.lport.length || nr.rport.length) && !["6", "17"].includes(nr.protocol)) throw new Error("Ports can only be used with TCP or UDP.");
            const id = cur ? cur.id : C.guid();
            await mutatePol("machine", (e) => e.filter((x) => !(x.key.toLowerCase() === C.FW_KEY.toLowerCase() && x.name === id)).concat([{ key: C.FW_KEY, name: id, type: C.REG.SZ, data: C.buildFwRule(nr) }]));
            close(); pageFirewall(pane);
          } catch (e) { showAlert("error", errText(e)); }
        } }]
      });
    };
    $("#fw-new", pane).onclick = () => edit(null);
    $$("tr[data-id]", pane).forEach((tr) => { const cur = rules.find((x) => x.id === tr.dataset.id); tr.querySelector(".b-edit").onclick = () => edit(cur);
      tr.querySelector(".b-del").onclick = () => confirmModal(`Delete the rule "${cur.r.name}"?`, async () => { try { await mutatePol("machine", (e) => e.filter((x) => !(x.key.toLowerCase() === C.FW_KEY.toLowerCase() && x.name === cur.id))); pageFirewall(pane); } catch (er) { showAlert("error", errText(er)); } }); });
  }

  function pagePlaceholder(pane, id) {
    const [title, why] = PH[id] || ["Not available", ""];
    pane.innerHTML = `<h3 class="gpmc-h">${esc(title)}</h3><div class="alert warning"><strong>Not editable in this tool.</strong> ${esc(why)}</div>
      <p>You can still edit this part of the same GPO from a Windows computer: install <strong>RSAT: Group Policy Management Tools</strong>, open <code>gpmc.msc</code> as a domain administrator, and edit the GPO named <em>${esc(G.ed.name)}</em>. Samba stores GPOs in the standard SYSVOL layout, so changes made there and here coexist.</p>`;
  }

  const sidOf = (p) => p.replace(/^\*/, "");
  async function principalLabels(list) {
    const sids = list.filter((p) => p.startsWith("*")).map(sidOf).filter((s) => !WELL_KNOWN[s]);
    const names = list.filter((p) => !p.startsWith("*"));
    let found = {};
    if (sids.length || names.length) try { found = await backend({ cmd: "lookup_principals", sids, names }); } catch (e) { /* best effort */ }
    return list.map((p) => { const s = sidOf(p); return p.startsWith("*") ? { raw: p, label: WELL_KNOWN[s] || (found[s] && found[s].name) || s } : { raw: p, label: p }; });
  }
  async function pageRights(pane) {
    spin(pane); const m = await readInf();
    const data = PRIVS.map(([k, label]) => ({ k, label, list: C.infGetPrivilege(m, k) }));
    const labelled = await Promise.all(data.map((d) => d.list ? principalLabels(d.list) : Promise.resolve(null)));
    pane.innerHTML = `<h3 class="gpmc-h">User Rights Assignment</h3><p class="muted">A defined right <em>replaces</em> the default list on every computer the GPO applies to, so include Administrators where needed.</p>
      <table class="data-table"><thead><tr><th>Policy</th><th>Policy setting</th><th></th></tr></thead><tbody>${data.map((d, i) => `<tr data-k="${d.k}"><td>${esc(d.label)}</td><td>${labelled[i] ? (labelled[i].map((x) => esc(x.label)).join(", ") || "<em>(nobody)</em>") : '<span class="muted">Not defined</span>'}</td><td class="row-actions"><button class="small b-edit">Edit&hellip;</button></td></tr>`).join("")}</tbody></table>`;
    $$("tr[data-k]", pane).forEach((tr, i) => tr.querySelector(".b-edit").onclick = () => openRightDialog(data[i], labelled[i] || [], pane));
  }
  function openRightDialog(d, current, pane) {
    let items = current.map((x) => Object.assign({}, x)); let defined = !!d.list;
    const modal = openModal(d.label, `<label class="inline-check"><input type="checkbox" id="rt-def" ${defined ? "checked" : ""}> Define these policy settings</label>
      <div id="rt-list" class="rt-list"></div>
      <div class="form-row"><label>Add user or group</label><div style="display:flex;gap:6px"><input type="text" id="rt-name" list="rt-dl" placeholder="name, or choose a built-in group" style="flex:1"><button class="small" id="rt-add">Add</button></div><datalist id="rt-dl">${Object.values(WELL_KNOWN).map((n) => `<option value="${esc(n)}">`).join("")}</datalist></div>`, {
      buttons: [{ label: "Cancel", onClick: (c) => c() }, {
        label: "OK", className: "primary", onClick: async (close, node) => {
          try {
            const on = $("#rt-def", node).checked;
            await mutateInf((mm) => C.infSetPrivilege(mm, d.k, on ? items.map((x) => x.raw) : undefined));
            close(); renderEdPage();
          } catch (e) { showAlert("error", errText(e)); }
        }
      }]
    });
    const node = modal.node;
    const draw = () => { $("#rt-list", node).innerHTML = items.length ? items.map((x, i) => `<div class="rt-item"><span>${esc(x.label)}</span><button class="small danger" data-i="${i}">Remove</button></div>`).join("") : `<span class="muted">Nobody.</span>`; $$("button[data-i]", node).forEach((b) => b.onclick = () => { items.splice(Number(b.dataset.i), 1); draw(); }); };
    draw();
    const nameIn = $("#rt-name", node); let t = null;
    nameIn.oninput = () => { clearTimeout(t); t = setTimeout(async () => { if (nameIn.value.length < 2) return; try { const r = await backend({ cmd: "search_principals", q: nameIn.value }); $("#rt-dl", node).innerHTML = Object.values(WELL_KNOWN).concat(r.map((x) => x.name)).map((n) => `<option value="${esc(n)}">`).join(""); } catch (e) { /* ignore */ } }, 250); };
    $("#rt-add", node).onclick = async () => {
      const v = nameIn.value.trim(); if (!v) return;
      const wk = Object.entries(WELL_KNOWN).find(([, n]) => n.toLowerCase() === v.toLowerCase());
      let sid = wk ? wk[0] : (/^S-1-\d+(-\d+)+$/i.test(v) ? v.toUpperCase() : null);
      if (!sid) { try { const r = await backend({ cmd: "lookup_principals", names: [v] }); sid = r[v] && r[v].sid; } catch (e) { showAlert("error", errText(e)); return; } }
      if (!sid) { showAlert("error", `"${v}" was not found in the directory.`); return; }
      if (!items.some((x) => sidOf(x.raw) === sid)) items.push({ raw: "*" + sid, label: wk ? wk[1] : v });
      nameIn.value = ""; draw();
    };
  }

  /* ---------------- Scripts ---------------- */
  async function pageScripts(pane, cls) {
    const Cl = Cls(cls); const sections = cls === "machine" ? ["Startup", "Shutdown"] : ["Logon", "Logoff"];
    const st = G.ed.scriptsUi = G.ed.scriptsUi || {}; const key = cls; st[key] = st[key] || { sec: sections[0], ps: false };
    const ui = st[key];
    spin(pane);
    const iniName = ui.ps ? "psscripts.ini" : "scripts.ini"; const iniPath = `${Cl}/Scripts/${iniName}`;
    const raw = await readFile(G.ed.guid, iniPath); const data = raw ? C.parseScriptsIni(C.decodeText(raw)) : {};
    const list = data[ui.sec] || [];
    pane.innerHTML = `<h3 class="gpmc-h">${esc(cls === "machine" ? "Startup / Shutdown" : "Logon / Logoff")} scripts</h3>
      <div class="gpmc-tabs">${sections.map((s) => `<button class="gtab ${ui.sec === s ? "active" : ""}" data-sec="${s}">${s}</button>`).join("")}<span style="flex:1"></span><button class="gtab ${!ui.ps ? "active" : ""}" data-ps="0">Scripts</button><button class="gtab ${ui.ps ? "active" : ""}" data-ps="1">PowerShell Scripts</button></div>
      ${list.length ? `<table class="data-table"><thead><tr><th>Order</th><th>Name</th><th>Parameters</th><th></th></tr></thead><tbody>${list.map((s, i) => `<tr data-i="${i}"><td>${i + 1}</td><td>${esc(s.cmd)}</td><td>${esc(s.params)}</td><td class="row-actions"><button class="small b-up" ${i === 0 ? "disabled" : ""}>&uarr;</button><button class="small b-down" ${i === list.length - 1 ? "disabled" : ""}>&darr;</button><button class="small danger b-del">Remove</button></td></tr>`).join("")}</tbody></table>` : `<div class="empty-state">No ${ui.sec.toLowerCase()} ${ui.ps ? "PowerShell " : ""}scripts.</div>`}
      <div class="gpmc-actions"><button class="small" id="sc-add">Add&hellip;</button></div>
      <p class="muted">Scripts you add with content are stored in this GPO's <code>${esc(Cl)}\\Scripts\\${esc(ui.sec)}</code> folder in SYSVOL. Clients run them in the order shown.</p>`;
    $$("[data-sec]", pane).forEach((b) => b.onclick = () => { ui.sec = b.dataset.sec; pageScripts(pane, cls); });
    $$("[data-ps]", pane).forEach((b) => b.onclick = () => { ui.ps = b.dataset.ps === "1"; pageScripts(pane, cls); });
    const save = async (fn, filesToWrite) => {
      const cur = raw ? C.parseScriptsIni(C.decodeText(raw)) : {}; cur[ui.sec] = cur[ui.sec] || []; fn(cur[ui.sec]);
      const ext = { [cls]: [[C.CSE.scripts.cse, C.CSE.scripts[cls]]] };
      for (const f of filesToWrite || []) await writeFile(G.ed.guid, f.path, f.bytes);
      await writeFile(G.ed.guid, iniPath, C.encodeUtf16le(C.serializeScriptsIni(cur)), { bump: [cls], exts: ext });
      await refreshMeta(); pageScripts(pane, cls);
    };
    $$("tr[data-i]", pane).forEach((tr) => { const i = Number(tr.dataset.i);
      tr.querySelector(".b-up").onclick = () => save((l) => { [l[i - 1], l[i]] = [l[i], l[i - 1]]; }).catch((e) => showAlert("error", errText(e)));
      tr.querySelector(".b-down").onclick = () => save((l) => { [l[i + 1], l[i]] = [l[i], l[i + 1]]; }).catch((e) => showAlert("error", errText(e)));
      tr.querySelector(".b-del").onclick = () => confirmModal("Remove this script from the list? (The file stays in SYSVOL.)", () => save((l) => { l.splice(i, 1); }).catch((e) => showAlert("error", errText(e))));
    });
    $("#sc-add", pane).onclick = () => openModal("Add a script", `<div class="form-row"><label>Script name (file name, or full path / UNC)</label><input type="text" id="sc-name" placeholder="${ui.ps ? "setup.ps1" : "map-drives.bat"}"></div>
      <div class="form-row"><label>Script parameters</label><input type="text" id="sc-params"></div>
      <div class="form-row"><label>Script content (optional; creates the file in the GPO folder)</label><textarea id="sc-body" rows="8" style="font-family:monospace"></textarea></div>
      <div class="form-row"><label>&hellip;or upload a file</label><input type="file" id="sc-file"></div>`, {
      wide: true, buttons: [{ label: "Cancel", onClick: (c) => c() }, {
        label: "Add", className: "primary", onClick: async (close, node) => {
          try {
            let name = $("#sc-name", node).value.trim(); const params = $("#sc-params", node).value; let body = $("#sc-body", node).value; const f = $("#sc-file", node).files[0];
            let bytes = null;
            if (f) { bytes = new Uint8Array(await f.arrayBuffer()); if (!name) name = f.name; } else if (body) bytes = C.encodeUtf8(body.replace(/\r?\n/g, "\r\n"));
            if (!name) throw new Error("A script name is required.");
            if (/[\\/]/.test(name) && bytes) throw new Error("When providing content, use a plain file name (no path).");
            await save((l) => { l.push({ cmd: name, params }); }, bytes ? [{ path: `${Cl}/Scripts/${ui.sec}/${name}`, bytes }] : []);
            close(); showAlert("success", "Script added.");
          } catch (e) { showAlert("error", errText(e)); }
        }
      }]
    });
  }

  /* ---------------- Preferences ---------------- */
  async function pagePrefRegistry(pane, cls) {
    const Cl = Cls(cls); const path = `${Cl}/Preferences/Registry/Registry.xml`;
    spin(pane); const raw = await readFile(G.ed.guid, path); const items = raw ? C.parseRegistryXml(C.decodeText(raw)) : [];
    const ACT = { C: "Create", R: "Replace", U: "Update", D: "Delete" };
    pane.innerHTML = `<h3 class="gpmc-h">Registry (Preferences)</h3><p class="muted">Preference items set a registry value but, unlike policies, users can change them afterwards.</p>
      ${items.length ? `<table class="data-table"><thead><tr><th>Name</th><th>Action</th><th>Key</th><th>Type</th><th>Value</th><th></th></tr></thead><tbody>${items.map((r, i) => `<tr data-i="${i}"><td>${esc(r.name || "(Default)")}</td><td>${ACT[r.action] || r.action}</td><td>${esc(r.hive.replace("HKEY_", "").replace("_", " "))}\\${esc(r.key)}</td><td>${esc(r.type)}</td><td>${esc(r.value)}</td><td class="row-actions"><button class="small b-edit">Edit&hellip;</button><button class="small danger b-del">Delete</button></td></tr>`).join("")}</tbody></table>` : `<div class="empty-state">No registry preference items.</div>`}
      <div class="gpmc-actions"><button class="small" id="pr-add">New registry item&hellip;</button></div>`;
    const save = async (fn) => {
      const cur = (await readFile(G.ed.guid, path)); const arr = cur ? C.parseRegistryXml(C.decodeText(cur)) : []; fn(arr);
      await writeFile(G.ed.guid, path, C.encodeUtf8(C.buildRegistryXml(arr)), { bump: [cls], exts: { [cls]: [[C.CSE.prefRegistry.cse, C.CSE.prefRegistry[cls]]] } });
      await refreshMeta(); pagePrefRegistry(pane, cls);
    };
    const dlg = (it, idx) => {
      it = it || { action: "U", hive: cls === "machine" ? "HKEY_LOCAL_MACHINE" : "HKEY_CURRENT_USER", key: "", name: "", type: "REG_SZ", value: "" };
      openModal(idx == null ? "New registry item" : "Edit registry item", `<div class="form-grid"><div class="form-row"><label>Action</label><select id="rg-act">${Object.entries(ACT).map(([k, v]) => `<option value="${k}" ${it.action === k ? "selected" : ""}>${v}</option>`).join("")}</select></div>
        <div class="form-row"><label>Hive</label><select id="rg-hive">${C.HIVES.map((h) => `<option ${it.hive === h ? "selected" : ""}>${h}</option>`).join("")}</select></div></div>
        <div class="form-row"><label>Key path</label><input type="text" id="rg-key" value="${esc(it.key)}" placeholder="SOFTWARE\\Contoso\\App"></div>
        <div class="form-grid"><div class="form-row"><label>Value name (empty = Default)</label><input type="text" id="rg-name" value="${esc(it.name)}"></div>
        <div class="form-row"><label>Value type</label><select id="rg-type">${["REG_SZ", "REG_EXPAND_SZ", "REG_DWORD"].map((t) => `<option ${it.type === t ? "selected" : ""}>${t}</option>`).join("")}</select></div></div>
        <div class="form-row"><label>Value data</label><input type="text" id="rg-val" value="${esc(it.value)}"></div>`, {
        buttons: [{ label: "Cancel", onClick: (c) => c() }, {
          label: "OK", className: "primary", onClick: async (close, node) => {
            try {
              const r = Object.assign({}, it, { action: $("#rg-act", node).value, hive: $("#rg-hive", node).value, key: $("#rg-key", node).value.trim().replace(/^\\+/, ""), name: $("#rg-name", node).value, type: $("#rg-type", node).value, value: $("#rg-val", node).value });
              if (!r.key) throw new Error("A key path is required.");
              if (r.type === "REG_DWORD") { r.value = Number(r.value); if (!Number.isInteger(r.value) || r.value < 0 || r.value > 4294967295) throw new Error("DWORD data must be an integer between 0 and 4294967295."); }
              await save((a) => { if (idx == null) a.push(r); else a[idx] = r; }); close();
            } catch (e) { showAlert("error", errText(e)); }
          }
        }]
      });
    };
    $("#pr-add", pane).onclick = () => dlg();
    $$("tr[data-i]", pane).forEach((tr) => { const i = Number(tr.dataset.i); tr.querySelector(".b-edit").onclick = () => dlg(items[i], i); tr.querySelector(".b-del").onclick = () => confirmModal("Delete this item?", () => save((a) => { a.splice(i, 1); }).catch((e) => showAlert("error", errText(e)))); });
  }

  async function pagePrefDrives(pane) {
    const path = "User/Preferences/Drives/Drives.xml";
    spin(pane); const raw = await readFile(G.ed.guid, path); const items = raw ? C.parseDrivesXml(C.decodeText(raw)) : [];
    const ACT = { C: "Create", R: "Replace", U: "Update", D: "Delete" };
    pane.innerHTML = `<h3 class="gpmc-h">Drive Maps (Preferences)</h3><p class="muted">Maps network drives at user logon.</p>
      ${items.length ? `<table class="data-table"><thead><tr><th>Drive</th><th>Action</th><th>Location</th><th>Label</th><th>Reconnect</th><th></th></tr></thead><tbody>${items.map((r, i) => `<tr data-i="${i}"><td>${esc(r.letter)}:</td><td>${ACT[r.action] || r.action}</td><td>${esc(r.path)}</td><td>${esc(r.label)}</td><td>${r.persistent ? "Yes" : "No"}</td><td class="row-actions"><button class="small b-edit">Edit&hellip;</button><button class="small danger b-del">Delete</button></td></tr>`).join("")}</tbody></table>` : `<div class="empty-state">No drive maps.</div>`}
      <div class="gpmc-actions"><button class="small" id="dm-add">New drive map&hellip;</button></div>`;
    const save = async (fn) => {
      const cur = await readFile(G.ed.guid, path); const arr = cur ? C.parseDrivesXml(C.decodeText(cur)) : []; fn(arr);
      await writeFile(G.ed.guid, path, C.encodeUtf8(C.buildDrivesXml(arr)), { bump: ["user"], exts: { user: [[C.CSE.drives.cse, C.CSE.drives.user]] } });
      await refreshMeta(); pagePrefDrives(pane);
    };
    const dlg = (it, idx) => {
      it = it || { action: "U", letter: "S", path: "", label: "", persistent: true };
      openModal(idx == null ? "New drive map" : "Edit drive map", `<div class="form-grid"><div class="form-row"><label>Action</label><select id="dm-act">${Object.entries(ACT).map(([k, v]) => `<option value="${k}" ${it.action === k ? "selected" : ""}>${v}</option>`).join("")}</select></div>
        <div class="form-row"><label>Drive letter</label><select id="dm-let">${"DEFGHIJKLMNOPQRSTUVWXYZ".split("").map((l) => `<option ${it.letter === l ? "selected" : ""}>${l}</option>`).join("")}</select></div></div>
        <div class="form-row"><label>Location</label><input type="text" id="dm-path" value="${esc(it.path)}" placeholder="\\\\server\\share"></div>
        <div class="form-row"><label>Label as</label><input type="text" id="dm-label" value="${esc(it.label)}"></div>
        <label class="inline-check"><input type="checkbox" id="dm-persist" ${it.persistent ? "checked" : ""}> Reconnect</label>`, {
        buttons: [{ label: "Cancel", onClick: (c) => c() }, {
          label: "OK", className: "primary", onClick: async (close, node) => {
            try {
              const r = Object.assign({}, it, { action: $("#dm-act", node).value, letter: $("#dm-let", node).value, path: $("#dm-path", node).value.trim(), label: $("#dm-label", node).value, persistent: $("#dm-persist", node).checked });
              if (!/^\\\\[^\\]+\\[^\\]+/.test(r.path) && r.action !== "D") throw new Error("Location must be a UNC path such as \\\\server\\share.");
              await save((a) => { if (idx == null) a.push(r); else a[idx] = r; }); close();
            } catch (e) { showAlert("error", errText(e)); }
          }
        }]
      });
    };
    $("#dm-add", pane).onclick = () => dlg();
    $$("tr[data-i]", pane).forEach((tr) => { const i = Number(tr.dataset.i); tr.querySelector(".b-edit").onclick = () => dlg(items[i], i); tr.querySelector(".b-del").onclick = () => confirmModal("Delete this drive map?", () => save((a) => { a.splice(i, 1); }).catch((e) => showAlert("error", errText(e)))); });
  }

  /* ---------------- ADMX templates dialog ---------------- */
  async function openTemplatesDialog() {
    const t = G.ed ? G.ed.tpl : G.tpl;
    let st = { admx: 0, languages: {}, msiextract: false };
    try { st = await backend({ cmd: "admx_status" }); } catch (e) { /* show dialog anyway */ }
    const langs = Object.keys(st.languages);
    const modal = openModal("Administrative Templates", `
      <p>Currently using: <strong>${t.source === "central" ? `${t.policyCount} policies from ${t.files} ADMX files in the domain Central Store` : `the built-in set (${t.policyCount} common policies)`}</strong>${langs.length ? ` &middot; languages: ${esc(langs.join(", "))}` : ""}.</p>
      <div class="so-group" style="padding:10px 12px;border:1px solid var(--border);border-radius:var(--radius-sm)">
        <strong>Get every Windows 11 / Windows Server policy</strong>
        <p class="muted" style="margin:6px 0">Downloads Microsoft's official <em>Administrative Templates (.admx) for Windows 11</em> (about 15 MB) straight from microsoft.com to this server and installs them in the domain <strong>Central Store</strong> (<code>SYSVOL\\&lt;domain&gt;\\Policies\\PolicyDefinitions</code>), exactly like the manual Windows procedure. They also cover Windows Server of the same generation.</p>
        <div class="form-grid"><div class="form-row"><label>Language</label><select id="tp-ml"><option value="en-US">English (en-US)</option><option value="${esc((navigator.language || "en-US"))}">${esc(navigator.language || "en-US")} (your browser)</option><option value="*">All languages (large)</option></select></div>
        <div class="form-row"><label>Source</label><select id="tp-src"><option value="url">Download from Microsoft</option><option value="path">An .msi file already on this server</option></select></div></div>
        <div class="form-row" id="tp-url-row"><label>Download address (https://download.microsoft.com/&hellip;)</label><input type="text" id="tp-url" value="${esc(st.default_url || "")}"></div>
        <div class="form-row" id="tp-path-row" style="display:none"><label>Path of the .msi (or an extracted PolicyDefinitions folder) on this server</label><input type="text" id="tp-path" placeholder="/root/Administrative Templates (.admx) for Windows 11 Sep 2026 Update.msi"></div>
        <div class="gpmc-actions"><button class="primary" id="tp-ms">Download &amp; install</button><span class="muted" id="tp-ms-status"></span></div>
        <div class="muted small-path">${st.msiextract ? "msitools is installed." : "The <code>msitools</code> package will be installed first (apt) to unpack Microsoft's installer."} Newer Windows releases publish a new download; paste its address above to update.</div>
      </div>
      <details style="margin-top:12px"><summary>Other ways to add templates</summary>
        <p class="muted">Upload individual files or a whole <code>PolicyDefinitions</code> folder (Chrome, Edge, Office, vendors&hellip;), or install Samba's own templates for Linux clients.</p>
        <div class="form-row"><label>Import files (.admx and .adml)</label><input type="file" id="tp-files" multiple accept=".admx,.adml"></div>
        <div class="form-row"><label>&hellip;or a PolicyDefinitions folder</label><input type="file" id="tp-dir" webkitdirectory multiple></div>
        <div class="form-row"><label>Language for .adml files that are not in a language folder</label><input type="text" id="tp-lang" value="en-US"></div>
        <div class="gpmc-actions"><button class="small" id="tp-up">Import selected files</button><button class="small" id="tp-samba">Install Samba's own templates</button></div></details>
      <div id="tp-status" class="muted" style="margin-top:8px"></div>`, { wide: true, buttons: [{ label: "Close", onClick: (c) => c() }] });
    const node = modal.node;
    const reloadTpl = async (msg) => { G.tpl = null; G.ed.tpl = await loadTemplates(true, (m) => { $("#tp-status", node).textContent = m; }); modal.close(); showAlert("success", `${msg} ${G.ed.tpl.policyCount} policies available.`); renderEditor(); };
    $("#tp-src", node).onchange = (e) => { $("#tp-url-row", node).style.display = e.target.value === "url" ? "" : "none"; $("#tp-path-row", node).style.display = e.target.value === "path" ? "" : "none"; };
    $("#tp-ms", node).onclick = async () => {
      const btn = $("#tp-ms", node), status = $("#tp-ms-status", node); btn.disabled = true;
      try {
        if (!st.msiextract) { status.innerHTML = `<span class="spinner"></span> Installing msitools\u2026`; await run(["apt-get", "install", "-y", "msitools"]); st.msiextract = true; }
        status.innerHTML = `<span class="spinner"></span> Downloading and installing (up to a minute)\u2026`;
        const lang = $("#tp-ml", node).value; const req = { cmd: "import_ms_admx", languages: [lang] };
        if ($("#tp-src", node).value === "path") req.path = $("#tp-path", node).value.trim(); else req.url = $("#tp-url", node).value.trim();
        const r = await backend(req);
        status.textContent = `Installed ${r.admx} ADMX + ${r.adml} language files. Loading\u2026`;
        await reloadTpl(`Installed ${r.admx} template files.`);
      } catch (e) { status.textContent = ""; btn.disabled = false; showAlert("error", errText(e), { sticky: true }); }
    };
    $("#tp-up", node).onclick = async () => {
      const status = $("#tp-status", node);
      const files = [...$("#tp-files", node).files, ...$("#tp-dir", node).files].filter((f) => /\.(admx|adml)$/i.test(f.name));
      if (!files.length) { showAlert("error", "Choose some .admx / .adml files first."); return; }
      try {
        const defLang = $("#tp-lang", node).value.trim() || "en-US"; const batch = []; let n = 0, bytes = 0;
        const flush = async () => { if (batch.length) await backend({ cmd: "write_files", root: "policies", files: batch.splice(0) }); };
        for (const f of files) {
          const isAdml = /\.adml$/i.test(f.name); let dest = "PolicyDefinitions/" + f.name;
          if (isAdml) { const parts = (f.webkitRelativePath || "").split("/"); const lang = parts.find((p) => /^[a-z]{2,3}(-[A-Za-z]{2,4})+$/.test(p)) || defLang; dest = `PolicyDefinitions/${lang}/${f.name}`; }
          const buf = new Uint8Array(await f.arrayBuffer()); batch.push({ path: dest, data: C.bytesToB64(buf) }); bytes += buf.length; n++;
          status.textContent = `Uploading ${n} of ${files.length}\u2026`; if (bytes > 3e6) { await flush(); bytes = 0; }
        }
        await flush(); await reloadTpl(`Imported ${n} file(s).`);
      } catch (e) { showAlert("error", errText(e), { sticky: true }); }
    };
    $("#tp-samba", node).onclick = async () => { try { const n = await backend({ cmd: "install_samba_admx" }); await reloadTpl(`Installed ${n} Samba template files.`); } catch (e) { showAlert("error", errText(e)); } };
  }

  /* ---------------- Settings report (GPMC "Settings" tab) ---------------- */
  async function buildReport(g) {
    const tpl = await loadTemplates();
    const out = [];
    const sect = (title, body) => body ? `<div class="rep-sec"><h4>${esc(title)}</h4>${body}</div>` : "";
    const fmt = (e) => esc(Array.isArray(e.data) ? e.data.join("; ") : e.data);
    for (const cls of ["machine", "user"]) {
      const Cl = Cls(cls); const entries = await backend({ cmd: "read_pol", guid: g.guid, class: cls });
      const used = new Set(); let adm = "";
      for (const m of tpl.models) for (const p of m.policies) {
        if (p.cls !== "Both" && p.cls !== Cl) continue;
        const s = C.getPolicyState(entries, p); if (s.state === "notconfigured") continue;
        for (const e of entries) if (C.removePolicy([e], p).length === 0) used.add(e);
        const vals = s.state === "enabled" ? p.elements.map((el) => { const v = s.values[el.id]; const sv = el.type === "enum" ? (el.items[v] || {}).name : (el.type === "boolean" ? (v ? "Yes" : "No") : (Array.isArray(v) ? v.map((x) => (x && x.name != null ? x.name + "=" + x.value : x)).join(", ") : v)); return `<div class="muted">${esc(el.label)} ${esc(sv == null ? "" : sv)}</div>`; }).join("") : "";
        adm += `<tr><td>${esc(p.displayName)}${vals}</td><td class="st-${s.state}">${STATE_LABEL[s.state]}</td></tr>`;
      }
      const extra = entries.filter((e) => !used.has(e) && !e.name.startsWith("**delvals"));
      const extraHtml = extra.length ? `<h5>Other registry settings</h5><table class="data-table"><tbody>${extra.map((e) => `<tr><td><code class="inline">${esc(e.key)}\\${esc(e.name)}</code></td><td>${fmt(e)}</td></tr>`).join("")}</tbody></table>` : "";
      const body = (adm ? `<table class="data-table"><thead><tr><th>Policy</th><th>Setting</th></tr></thead><tbody>${adm}</tbody></table>` : "") + extraHtml;
      let secHtml = "";
      if (cls === "machine") {
        const inf = await readInf(g.guid);
        const rows = [];
        for (const s of inf.sections) if (!["Unicode", "Version"].includes(s.name)) for (const it of s.items) rows.push(`<tr><td>${esc(s.name)}</td><td><code class="inline">${esc(it.key)}</code></td><td>${esc(it.value == null ? "" : it.value)}</td></tr>`);
        secHtml = rows.length ? `<h5>Security Settings</h5><table class="data-table"><tbody>${rows.join("")}</tbody></table>` : "";
      }
      let scr = "";
      for (const ini of ["scripts.ini", "psscripts.ini"]) {
        const b = await readFile(g.guid, `${Cl}/Scripts/${ini}`); if (!b) continue;
        const d = C.parseScriptsIni(C.decodeText(b));
        for (const sec in d) for (const s of d[sec]) scr += `<tr><td>${esc(sec)}${ini.startsWith("ps") ? " (PowerShell)" : ""}</td><td>${esc(s.cmd)}</td><td>${esc(s.params)}</td></tr>`;
      }
      const scrHtml = scr ? `<h5>Scripts</h5><table class="data-table"><tbody>${scr}</tbody></table>` : "";
      let prefs = "";
      const rb = await readFile(g.guid, `${Cl}/Preferences/Registry/Registry.xml`);
      if (rb) { const it = C.parseRegistryXml(C.decodeText(rb)); if (it.length) prefs += `<h5>Preferences: Registry</h5><table class="data-table"><tbody>${it.map((r) => `<tr><td>${esc(r.action)}</td><td><code class="inline">${esc(r.hive)}\\${esc(r.key)}\\${esc(r.name)}</code></td><td>${esc(r.value)}</td></tr>`).join("")}</tbody></table>`; }
      if (cls === "user") { const db = await readFile(g.guid, "User/Preferences/Drives/Drives.xml"); if (db) { const it = C.parseDrivesXml(C.decodeText(db)); if (it.length) prefs += `<h5>Preferences: Drive Maps</h5><table class="data-table"><tbody>${it.map((r) => `<tr><td>${esc(r.letter)}:</td><td>${esc(r.path)}</td><td>${esc(r.label)}</td></tr>`).join("")}</tbody></table>`; } }
      out.push(sect(cls === "machine" ? "Computer Configuration" : "User Configuration", body + secHtml + scrHtml + prefs));
    }
    const html = out.join("");
    return html || `<div class="empty-state">This GPO has no settings configured.</div>`;
  }

  return { load };
})();

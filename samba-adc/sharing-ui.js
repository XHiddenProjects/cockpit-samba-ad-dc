"use strict";
/* ---------------------------------------------------------------------
 * File sharing & network discovery: diagnostics, repair actions, and a
 * per-share sign-in test. Backend: sharing_diag.py (run as root).
 * Uses helpers from samba-adc.js (run, openModal, confirmModal,
 * showAlert, errText, escapeHtml, STATE).
 * ------------------------------------------------------------------- */
const SharingUI = (function () {
  const esc = (s) => escapeHtml(s == null ? "" : s);
  const src = {};
  async function py(file, req) {
    if (!src[file]) {
      const r = await fetch(file, { cache: "no-store" });
      if (!r.ok) throw new Error("Could not load " + file + " (HTTP " + r.status + ")");
      src[file] = await r.text();
    }
    const out = await cockpit.spawn(["python3", "-c", src[file]], { superuser: "require", err: "message" }).input(JSON.stringify(req));
    let res; try { res = JSON.parse(out); } catch (e) { throw new Error("Unexpected helper output: " + String(out).slice(0, 300)); }
    if (!res.ok) throw new Error(res.error);
    return res.data;
  }

  const ICON = { ok: "\u2705", warn: "\u26A0\uFE0F", fail: "\u274C", info: "\u2139\uFE0F" };
  let last = [];

  function listHtml(checks, offset) {
    return `<div class="diag-list">` + checks.map((c, i) => `
      <div class="diag diag-${c.status}"><div class="diag-icon">${ICON[c.status] || ""}</div>
        <div class="diag-main"><div class="diag-title">${esc(c.title)}</div>${c.detail ? `<div class="diag-detail">${esc(c.detail)}</div>` : ""}</div>
        ${c.fix ? `<div class="diag-fix"><button class="small primary" data-i="${i + offset}">${esc(c.fix.label)}</button></div>` : ""}</div>`).join("") + `</div>`;
  }
  const service = () => STATE.service || "samba-ad-dc.service";
  const fetchDomainChecks = () => py("sharing_diag.py", { cmd: "domain_checks", service: service() });

  async function renderInto(id) {
    const host = document.getElementById(id);
    host.innerHTML = `<span class="spinner"></span> Running checks&hellip;`;
    let share, dom;
    try { [share, dom] = await Promise.all([py("sharing_diag.py", { cmd: "checks", service: service() }), fetchDomainChecks()]); }
    catch (e) { host.innerHTML = `<div class="alert error">${esc(errText(e))}</div>`; return; }
    last = share.concat(dom);
    const all = last, bad = all.filter((c) => c.status === "fail").length, warn = all.filter((c) => c.status === "warn").length;
    const summary = bad ? `<div class="alert error"><strong>${bad} problem${bad > 1 ? "s" : ""} found.</strong> These can make the server visible in Explorer but impossible to open, or make <code>gpupdate</code> fail. Fix the red items first.</div>`
      : warn ? `<div class="alert warning">No blocking problems, ${warn} warning${warn > 1 ? "s" : ""}.</div>` : `<div class="alert success">All server-side checks passed.</div>`;
    host.innerHTML = summary + `<h4 class="diag-h">File sharing &amp; discovery</h4>` + listHtml(share, 0) +
      `<h4 class="diag-h">Domain sign-in &amp; Group Policy delivery</h4>` + listHtml(dom, share.length) +
      `<div class="gpmc-actions"><button class="small" id="diag-signin">Test sign-in to \\\\server&hellip;</button></div>
      <div class="form-hint">These checks run on the server. Anything on the Windows client (is it joined to the domain, signed in with a domain account, using this DC for DNS, with a correct clock?) cannot be seen from here. <strong>Test sign-in</strong> proves the server side works for a given account.</div>`;
    host.querySelectorAll("button[data-i]").forEach((b) => b.addEventListener("click", () => runFix(last[Number(b.dataset.i)].fix, id)));
    host.querySelector("#diag-signin").addEventListener("click", () => openTest(""));
  }

  /* ---------------- fixes ---------------- */
  const dropIn = (svc) => `# Written by the Samba AD DC Cockpit module.
# The stock unit is bound to smbd.service, which is disabled on an AD DC
# (Samba runs as ${svc}), so systemd would refuse to keep it running.
[Unit]
BindsTo=
After=
PartOf=
Wants=network-online.target
After=network-online.target ${svc}
BindsTo=${svc}
PartOf=${svc}
`;

  async function bindUnit(unit) {
    const svc = STATE.service || "samba-ad-dc.service";
    await run(["mkdir", "-p", `/etc/systemd/system/${unit}.d`]);
    await cockpit.file(`/etc/systemd/system/${unit}.d/samba-ad-dc.conf`, { superuser: "require" }).replace(dropIn(svc));
    await run(["systemctl", "daemon-reload"]);
    await run(["systemctl", "enable", unit]);
    await run(["systemctl", "restart", unit]);
  }

  async function pickPackage() {
    for (const p of ["wsdd2", "wsdd-server"]) {
      try { const o = await run(["apt-cache", "policy", p]); if (/Candidate:\s*(?!\(none\))\S+/.test(o)) return p; } catch (e) { /* try next */ }
    }
    return null;
  }

  function confirmSteps(title, steps, go) {
    openModal(title, `<p>This will:</p><ol>${steps.map((s) => `<li>${s}</li>`).join("")}</ol>`, {
      buttons: [{ label: "Cancel", onClick: (c) => c() }, { label: "Apply", className: "primary", onClick: async (close) => { close(); try { await go(); } catch (e) { showAlert("error", errText(e), { sticky: true }); } } }]
    });
  }

  function runFix(fix, id) {
    const again = typeof id === "function" ? id : () => renderInto(id);
    if (fix.action === "install_discovery") {
      confirmSteps("Install network discovery", [
        "Install the <code>wsdd2</code> package (or <code>wsdd-server</code> if that is what your distribution offers). Debian 13 no longer ships the old Python <code>wsdd</code>.",
        `Add a systemd drop-in so it is tied to <code>${esc(STATE.service || "samba-ad-dc.service")}</code> instead of <code>smbd.service</code>.`,
        "Enable it at boot and start it."], async () => {
        const pkg = await pickPackage();
        if (!pkg) throw new Error("Neither wsdd2 nor wsdd-server is available from your configured package sources. Run 'apt update' or install one manually, then use this button again.");
        await run(["apt-get", "install", "-y", pkg]);
        const unit = pkg + ".service";
        await bindUnit(unit);
        showAlert("success", `${pkg} installed and running. Give Windows clients up to a minute to notice the server.`);
        again();
      });
    } else if (fix.action === "fix_wsdd_binding") {
      confirmSteps("Fix " + fix.unit, [`Write <code>/etc/systemd/system/${esc(fix.unit)}.d/samba-ad-dc.conf</code> binding the unit to <code>${esc(STATE.service || "samba-ad-dc.service")}</code>.`, "Reload systemd, enable and restart the unit."], async () => {
        await bindUnit(fix.unit); showAlert("success", fix.unit + " is bound to the Samba AD DC service and restarted."); again();
      });
    } else if (fix.action === "enable_discovery") {
      run(["systemctl", "enable", "--now", fix.unit]).then(() => { showAlert("success", fix.unit + " enabled and started."); again(); }).catch((e) => showAlert("error", errText(e), { sticky: true }));
    } else if (fix.action === "sysvolreset") {
      confirmSteps("Reset SYSVOL permissions", ["Run <code>samba-tool ntacl sysvolreset</code>, Samba's standard repair. It re-applies the correct Windows ACLs to every file in SYSVOL (it does not change their contents)."], async () => {
        let out = ""; try { out = await run(["samba-tool", "ntacl", "sysvolreset"]); } catch (e) { out = errText(e); }
        openModal("sysvolreset output", `<pre class="ldif">${esc(out.trim() || "Done (no output).")}</pre>`, { wide: true, buttons: [{ label: "Close", onClick: (c) => c() }] }); again();
      });
    } else if (fix.action === "dns_update") {
      confirmSteps("Refresh DNS records", ["Run <code>samba_dnsupdate --verbose --all-names</code> to (re)register this server's A/AAAA and service records in AD DNS."], async () => {
        let out = ""; try { out = await run(["samba_dnsupdate", "--verbose", "--all-names"]); } catch (e) { out = errText(e); }
        openModal("samba_dnsupdate output", `<pre class="ldif">${esc(out.trim() || "(no output)")}</pre>`, { wide: true, buttons: [{ label: "Close", onClick: (c) => c() }] }); again();
      });
    } else if (fix.action === "open_firewall") {
      if (fix.engine === "nftables") {
        const snippet = fix.ports.map(([p, n]) => `nft add rule inet filter input ${p} dport ${n} accept`).join("\n");
        openModal("Open ports in nftables", `<p>nftables rule sets differ too much between systems to edit automatically. Add rules like these to the table/chain you use (then persist them in <code>/etc/nftables.conf</code>):</p><pre class="ldif">${esc(snippet)}</pre>`, { buttons: [{ label: "Close", onClick: (c) => c() }] });
        return;
      }
      const ufwSpec = ([p, n]) => `${n.replace("-", ":")}/${p}`;      // ufw ranges use ':'
      const fwdSpec = ([p, n]) => `${n}/${p}`;                          // firewalld ranges use '-'
      confirmSteps("Open firewall ports (" + fix.engine + ")", fix.ports.map((x) => `Allow <code>${esc(fix.engine === "ufw" ? ufwSpec(x) : fwdSpec(x))}</code>`), async () => {
        if (fix.engine === "ufw") for (const x of fix.ports) await run(["ufw", "allow", ufwSpec(x)]);
        else { for (const x of fix.ports) await run(["firewall-cmd", "--permanent", "--add-port=" + fwdSpec(x)]); await run(["firewall-cmd", "--reload"]); }
        showAlert("success", "Firewall updated."); again();
      });
    }
  }

  /* ---------------- sign-in test ---------------- */
  function openTest(share) {
    const LAYER = { none: "success", auth: "error", acl: "error", share: "error", network: "error", protocol: "error", unknown: "warning" };
    openModal(share ? `Test access to \\\\${share}` : `Test sign-in to \\\\${STATE.selfFqdn || "this server"}`, `<p class="muted">Signs in ${share ? "to this share" : "to the server and lists its shares (what Explorer does for <code>\\\\server</code>)"} <em>from the server itself</em> over the network address, exactly like a client would, and tells you which layer fails. The password is sent to the server-side helper over a pipe and is never stored.</p>
      <div class="form-row"><label>User (e.g. alice or TEST\\alice)</label><input type="text" id="st-user" autocomplete="off"></div>
      <div class="form-row"><label>Password</label><input type="password" id="st-pass" autocomplete="new-password"></div><div id="st-result"></div>`, {
      buttons: [{ label: "Close", onClick: (c) => c() }, {
        label: "Run test", className: "primary", onClick: async (close, node) => {
          const out = node.querySelector("#st-result"); out.innerHTML = `<span class="spinner"></span> Testing&hellip;`;
          try {
            const r = await py("sharing_diag.py", { cmd: "smb_test", share, user: node.querySelector("#st-user").value.trim(), pass: node.querySelector("#st-pass").value });
            out.innerHTML = `<div class="alert ${LAYER[r.layer] || "warning"}"><strong>${r.ok ? "Success" : "Failed" + (r.code ? " (" + esc(r.code) + ")" : "")}</strong><br>${esc(r.message)}</div>${r.ok ? "" : `<pre class="ldif">${esc(r.raw || "")}</pre>`}`;
          } catch (e) { out.innerHTML = `<div class="alert error">${esc(errText(e))}</div>`; }
        }
      }]
    });
  }

  return { renderInto, openTest, fetchDomainChecks, listHtml, runFix };
})();

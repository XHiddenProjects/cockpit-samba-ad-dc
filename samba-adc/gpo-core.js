"use strict";
/* ---------------------------------------------------------------------
 * GpoCore - pure logic for the Group Policy editor (no UI, no I/O).
 *   - Registry.pol entry helpers
 *   - ADMX / ADML parsing and the Enabled / Disabled / Not configured engine
 *   - GptTmpl.inf (Security Settings), scripts.ini, GPP Drives/Registry XML
 * Works in the browser (window.GpoCore) and in Node (module.exports) so it
 * can be unit tested.
 * ------------------------------------------------------------------- */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.GpoCore = factory();
})(typeof self !== "undefined" ? self : this, function () {

  const REG = { SZ: 1, EXPAND_SZ: 2, BINARY: 3, DWORD: 4, MULTI_SZ: 7, QWORD: 11 };

  /* ---------------- bytes / text ---------------- */
  function b64ToBytes(b64) {
    if (typeof Buffer !== "undefined") return new Uint8Array(Buffer.from(b64, "base64"));
    const bin = atob(b64); const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function bytesToB64(bytes) {
    if (typeof Buffer !== "undefined") return Buffer.from(bytes).toString("base64");
    let s = ""; for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(s);
  }
  /* Decode text honoring a BOM (GPO files are very often UTF-16LE with BOM). */
  function decodeText(bytes) {
    if (!bytes || bytes.length === 0) return "";
    if (bytes[0] === 0xFF && bytes[1] === 0xFE) return new TextDecoder("utf-16le").decode(bytes.subarray(2));
    if (bytes[0] === 0xFE && bytes[1] === 0xFF) return new TextDecoder("utf-16be").decode(bytes.subarray(2));
    if (bytes[0] === 0xEF && bytes[1] === 0xBB && bytes[2] === 0xBF) return new TextDecoder("utf-8").decode(bytes.subarray(3));
    return new TextDecoder("utf-8").decode(bytes);
  }
  function encodeUtf16le(str) {
    const out = new Uint8Array(2 + str.length * 2);
    out[0] = 0xFF; out[1] = 0xFE;
    for (let i = 0; i < str.length; i++) { const c = str.charCodeAt(i); out[2 + i * 2] = c & 0xFF; out[3 + i * 2] = c >> 8; }
    return out;
  }
  function encodeUtf8(str) { return new TextEncoder().encode(str); }
  function guid() {
    const u = (typeof crypto !== "undefined" && crypto.randomUUID) ? crypto.randomUUID()
      : "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => { const r = Math.random() * 16 | 0; return (c === "x" ? r : (r & 3 | 8)).toString(16); });
    return "{" + u.toUpperCase() + "}";
  }
  function xmlEscape(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }

  /* ---------------- Registry.pol entries ---------------- */
  const ieq = (a, b) => String(a).toLowerCase() === String(b).toLowerCase();
  const findEntry = (entries, key, name) => entries.find((e) => ieq(e.key, key) && ieq(e.name, name));

  function valToEntry(key, name, v) {
    if (v.t === "delete") return { key, name: "**del." + name, type: REG.SZ, data: " " };
    if (v.t === "string") return { key, name, type: REG.SZ, data: String(v.v) };
    if (v.t === "long") return { key, name, type: REG.QWORD, data: Number(v.v) };
    return { key, name, type: REG.DWORD, data: Number(v.v) };
  }
  function entryMatches(e, v) {
    if (!e || !v) return false;
    if (v.t === "string") return String(e.data) === String(v.v);
    if (v.t === "delete") return false;
    return Number(e.data) === Number(v.v) && (e.type === REG.DWORD || e.type === REG.QWORD || e.type === REG.SZ);
  }

  /* ---------------- ADML / ADMX parsing ---------------- */
  function parseXml(text) {
    const doc = new DOMParser().parseFromString(text.replace(/^\uFEFF/, ""), "application/xml");
    if (doc.getElementsByTagName("parsererror").length) throw new Error("Invalid XML");
    return doc;
  }
  const kids = (el, name) => Array.from(el.children).filter((c) => (c.localName || c.tagName) === name);
  const kid = (el, name) => kids(el, name)[0] || null;

  function parseAdml(text) {
    const doc = parseXml(text);
    const strings = {};
    for (const s of Array.from(doc.getElementsByTagName("string"))) if (s.parentNode && (s.parentNode.localName || s.parentNode.tagName) === "stringTable") strings[s.getAttribute("id")] = s.textContent;
    const presentations = {};
    for (const p of Array.from(doc.getElementsByTagName("presentation"))) {
      const map = { __labels: [] };
      let lastLabel = "";
      for (const c of Array.from(p.children)) {
        const tag = c.localName || c.tagName;
        const ref = c.getAttribute("refId");
        if (tag === "text") { lastLabel = c.textContent.trim(); map.__labels.push(lastLabel); continue; }
        if (!ref) continue;
        const o = { type: tag, label: "", defaultValue: undefined, defaultChecked: false, defaultItem: undefined, spinStep: undefined };
        if (tag === "checkBox") { o.label = c.textContent.trim(); o.defaultChecked = c.getAttribute("defaultChecked") === "true"; }
        else if (tag === "decimalTextBox" || tag === "longDecimalTextBox") { o.label = lastLabel || c.textContent.trim(); o.defaultValue = c.getAttribute("defaultValue"); o.spinStep = c.getAttribute("spinStep"); }
        else if (tag === "textBox" || tag === "comboBox") { const l = kid(c, "label"); o.label = l ? l.textContent.trim() : lastLabel; const d = kid(c, "defaultValue"); o.defaultValue = d ? d.textContent : undefined; }
        else if (tag === "dropdownList") { o.label = lastLabel || c.textContent.trim(); o.defaultItem = c.getAttribute("defaultItem"); }
        else { o.label = c.textContent.trim() || lastLabel; }
        map[ref] = o; lastLabel = "";
      }
      presentations[p.getAttribute("id")] = map;
    }
    const definitions = {};
    for (const d of Array.from(doc.getElementsByTagName("definition"))) definitions[d.getAttribute("name")] = resolveStr(d.getAttribute("displayName"), strings);
    return { strings, presentations, definitions };
  }

  function parseValueObj(el) {
    if (!el) return null;
    const c = el.children[0];
    if (!c) return null;
    const tag = c.localName || c.tagName;
    if (tag === "decimal") return { t: "decimal", v: Number(c.getAttribute("value")) };
    if (tag === "longDecimal") return { t: "long", v: Number(c.getAttribute("value")) };
    if (tag === "string") return { t: "string", v: c.textContent };
    if (tag === "delete") return { t: "delete" };
    return null;
  }
  function parseValueList(el, defKey) {
    if (!el) return null;
    return kids(el, "item").map((it) => ({ key: it.getAttribute("key") || defKey, valueName: it.getAttribute("valueName"), value: parseValueObj(kid(it, "value")) || { t: "decimal", v: 1 } }));
  }

  function resolveStr(s, strings) {
    if (s == null) return "";
    const m = /^\$\((?:string|resource)\.([^)]+)\)$/.exec(s);
    return m ? (strings[m[1]] != null ? strings[m[1]] : m[1]) : s;
  }

  /* Returns a model: { namespace, categories:[{id,name,parent}], policies:[...] } */
  function parseAdmx(admxText, adml) {
    adml = adml || { strings: {}, presentations: {} };
    const doc = parseXml(admxText);
    const rootEl = doc.documentElement;
    const nsEl = kid(rootEl, "policyNamespaces");
    const target = nsEl ? kid(nsEl, "target") : null;
    const ns = target ? target.getAttribute("namespace") : "unknown";
    const prefix = target ? target.getAttribute("prefix") : "";
    const usings = {};
    if (nsEl) for (const u of kids(nsEl, "using")) usings[u.getAttribute("prefix")] = u.getAttribute("namespace");
    const refId = (ref) => {
      if (!ref) return null;
      const i = ref.indexOf(":");
      if (i < 0) return ns + ":" + ref;
      const p = ref.slice(0, i), n = ref.slice(i + 1);
      return (p === prefix ? ns : (usings[p] || p)) + ":" + n;
    };
    const S = (s) => resolveStr(s, adml.strings);

    const categories = [];
    const catsEl = kid(rootEl, "categories");
    if (catsEl) for (const c of kids(catsEl, "category")) {
      const pc = kid(c, "parentCategory");
      categories.push({ id: ns + ":" + c.getAttribute("name"), name: S(c.getAttribute("displayName")), parent: pc ? refId(pc.getAttribute("ref")) : null });
    }

    const policies = [];
    const polsEl = kid(rootEl, "policies");
    if (polsEl) for (const p of kids(polsEl, "policy")) {
      const pkey = p.getAttribute("key");
      const pres = adml.presentations[(p.getAttribute("presentation") || "").replace(/^\$\(presentation\.(.*)\)$/, "$1")] || {};
      const pc = kid(p, "parentCategory");
      const sup = kid(p, "supportedOn");
      const pol = {
        id: ns + ":" + p.getAttribute("name"), name: p.getAttribute("name"), cls: p.getAttribute("class") || "Both",
        displayName: S(p.getAttribute("displayName")), explain: S(p.getAttribute("explainText")),
        key: pkey, valueName: p.getAttribute("valueName"), category: pc ? refId(pc.getAttribute("ref")) : null,
        supportedOnRef: sup ? (sup.getAttribute("ref") || "").split(":").pop() : "",
        supportedOn: sup ? S("$(string." + (sup.getAttribute("ref") || "").split(":").pop() + ")").replace(/^[A-Za-z0-9_]+$/, "") : "",
        enabledValue: parseValueObj(kid(p, "enabledValue")), disabledValue: parseValueObj(kid(p, "disabledValue")),
        enabledList: parseValueList(kid(p, "enabledList"), pkey), disabledList: parseValueList(kid(p, "disabledList"), pkey),
        elements: []
      };
      const elsEl = kid(p, "elements");
      if (elsEl) for (const e of Array.from(elsEl.children)) {
        const type = e.localName || e.tagName;
        const id = e.getAttribute("id");
        const pr = pres[id] || {};
        const el = { type, id, key: e.getAttribute("key") || pkey, valueName: e.getAttribute("valueName"), required: e.getAttribute("required") === "true", label: pr.label || id };
        if (type === "decimal" || type === "longDecimal") {
          el.min = e.getAttribute("minValue") != null ? Number(e.getAttribute("minValue")) : 0;
          el.max = e.getAttribute("maxValue") != null ? Number(e.getAttribute("maxValue")) : 4294967295;
          el.storeAsText = e.getAttribute("storeAsText") === "true";
          el.defaultValue = pr.defaultValue != null ? Number(pr.defaultValue) : undefined;
        } else if (type === "text") {
          el.maxLength = Number(e.getAttribute("maxLength") || 1023); el.expandable = e.getAttribute("expandable") === "true";
          el.defaultValue = pr.defaultValue;
        } else if (type === "boolean") {
          el.trueValue = parseValueObj(kid(e, "trueValue")); el.falseValue = parseValueObj(kid(e, "falseValue"));
          el.trueList = parseValueList(kid(e, "trueList"), el.key); el.falseList = parseValueList(kid(e, "falseList"), el.key);
          el.defaultChecked = !!pr.defaultChecked;
        } else if (type === "enum") {
          el.items = kids(e, "item").map((it) => ({ name: S(it.getAttribute("displayName")), value: parseValueObj(kid(it, "value")) || { t: "decimal", v: 0 }, list: parseValueList(kid(it, "valueList"), el.key) }));
          el.defaultItem = pr.defaultItem != null ? Number(pr.defaultItem) : 0;
        } else if (type === "list") {
          el.additive = e.getAttribute("additive") === "true"; el.expandable = e.getAttribute("expandable") === "true";
          el.explicitValue = e.getAttribute("explicitValue") === "true"; el.valuePrefix = e.getAttribute("valuePrefix") || "";
        } else if (type === "multiText") {
          el.maxLength = Number(e.getAttribute("maxLength") || 1023);
        }
        pol.elements.push(el);
      }
      policies.push(pol);
    }
    return { namespace: ns, categories, policies };
  }

  /* Merge models into one category tree for a class ("Machine" | "User"). */
  function buildTree(models, cls) {
    const cats = new Map();
    const ensure = (id, name) => { if (!cats.has(id)) cats.set(id, { id, name: name || id.split(":").pop(), parent: null, children: [], policies: [] }); return cats.get(id); };
    for (const m of models) for (const c of m.categories) { const n = ensure(c.id, c.name); n.name = c.name; n.parent = c.parent; }
    for (const m of models) for (const p of m.policies) {
      if (p.cls !== "Both" && p.cls !== cls) continue;
      const parent = p.category ? ensure(p.category) : ensure("(none):Other", "Other");
      parent.policies.push(p);
    }
    const roots = [];
    for (const c of cats.values()) {
      if (c.parent) ensure(c.parent).children.push(c); else roots.push(c);
    }
    // fix up categories whose parent was auto-created without a parent (placeholder) - they are roots already
    const prune = (c) => { c.children = c.children.filter(prune); c.children.sort((a, b) => a.name.localeCompare(b.name)); c.policies.sort((a, b) => a.displayName.localeCompare(b.displayName)); return c.children.length > 0 || c.policies.length > 0; };
    const out = roots.filter(prune);
    out.sort((a, b) => a.name.localeCompare(b.name));
    return out;
  }

  /* ---------------- the Enabled / Disabled engine ---------------- */
  const ek = (pol, el) => el.key || pol.key;

  function touchpoints(pol) {
    const t = [];
    if (pol.valueName) t.push({ key: pol.key, name: pol.valueName });
    for (const l of [pol.enabledList, pol.disabledList]) if (l) for (const i of l) t.push({ key: i.key, name: i.valueName });
    for (const el of pol.elements) {
      if (el.type === "list") { t.push({ key: ek(pol, el), all: true }); continue; }
      if (el.valueName) t.push({ key: ek(pol, el), name: el.valueName });
      for (const l of [el.trueList, el.falseList]) if (l) for (const i of l) t.push({ key: i.key || ek(pol, el), name: i.valueName });
      if (el.items) for (const it of el.items) if (it.list) for (const i of it.list) t.push({ key: i.key || ek(pol, el), name: i.valueName });
    }
    return t;
  }

  function removePolicy(entries, pol) {
    const tp = touchpoints(pol);
    return entries.filter((e) => !tp.some((t) => ieq(e.key, t.key) && (t.all || ieq(e.name, t.name) || ieq(e.name, "**del." + t.name))));
  }

  function elementEntries(pol, el, val) {
    const out = [];
    const key = ek(pol, el);
    if (el.type === "decimal" || el.type === "longDecimal") {
      const v = (val === undefined || val === "" || val === null) ? (el.defaultValue !== undefined ? el.defaultValue : el.min) : Number(val);
      if (el.storeAsText) out.push({ key, name: el.valueName, type: REG.SZ, data: String(v) });
      else out.push({ key, name: el.valueName, type: el.type === "longDecimal" ? REG.QWORD : REG.DWORD, data: v });
    } else if (el.type === "text") {
      const v = val == null ? (el.defaultValue || "") : String(val);
      out.push({ key, name: el.valueName, type: el.expandable ? REG.EXPAND_SZ : REG.SZ, data: v });
    } else if (el.type === "boolean") {
      const checked = val == null ? el.defaultChecked : !!val;
      const vo = checked ? (el.trueValue || { t: "decimal", v: 1 }) : (el.falseValue || { t: "decimal", v: 0 });
      if (el.valueName) out.push(valToEntry(key, el.valueName, vo));
      for (const i of (checked ? el.trueList : el.falseList) || []) out.push(valToEntry(i.key, i.valueName, i.value));
    } else if (el.type === "enum") {
      const idx = val == null ? el.defaultItem : Number(val);
      const it = el.items[idx] || el.items[0];
      if (it) {
        if (el.valueName) out.push(valToEntry(key, el.valueName, it.value));
        for (const i of it.list || []) out.push(valToEntry(i.key, i.valueName, i.value));
      }
    } else if (el.type === "list") {
      const items = Array.isArray(val) ? val : [];
      if (!el.additive) out.push({ key, name: "**delvals.", type: REG.SZ, data: " " });
      items.forEach((it, i) => {
        if (el.explicitValue) out.push({ key, name: String(it.name), type: el.expandable ? REG.EXPAND_SZ : REG.SZ, data: String(it.value) });
        else out.push({ key, name: (el.valuePrefix || "") + (i + 1), type: el.expandable ? REG.EXPAND_SZ : REG.SZ, data: String(it) });
      });
    } else if (el.type === "multiText") {
      const lines = Array.isArray(val) ? val.filter((x) => x !== "") : String(val || "").split(/\r?\n/).filter(Boolean);
      out.push({ key, name: el.valueName, type: REG.MULTI_SZ, data: lines });
    }
    return out;
  }

  /* state: "enabled" | "disabled" | "notconfigured"; values: {elementId: value}
     returns the NEW entries array (input is not modified). */
  function applyPolicy(entries, pol, state, values) {
    let out = removePolicy(entries, pol);
    values = values || {};
    if (state === "enabled") {
      if (pol.valueName) out.push(valToEntry(pol.key, pol.valueName, pol.enabledValue || { t: "decimal", v: 1 }));
      for (const i of pol.enabledList || []) out.push(valToEntry(i.key, i.valueName, i.value));
      for (const el of pol.elements) out.push(...elementEntries(pol, el, values[el.id]));
    } else if (state === "disabled") {
      if (pol.valueName) out.push(valToEntry(pol.key, pol.valueName, pol.disabledValue || { t: "decimal", v: 0 }));
      for (const i of pol.disabledList || []) out.push(valToEntry(i.key, i.valueName, i.value));
      for (const el of pol.elements) {
        if (el.type === "list") out.push({ key: ek(pol, el), name: "**delvals.", type: REG.SZ, data: " " });
        else if (el.valueName) out.push({ key: ek(pol, el), name: "**del." + el.valueName, type: REG.SZ, data: " " });
      }
    }
    return out;
  }

  function readElement(entries, pol, el) {
    const key = ek(pol, el);
    if (el.type === "list") {
      const items = entries.filter((e) => ieq(e.key, key) && !e.name.startsWith("**"));
      if (el.explicitValue) return items.map((e) => ({ name: e.name, value: String(e.data) }));
      items.sort((a, b) => (parseInt(a.name.replace(/\D/g, ""), 10) || 0) - (parseInt(b.name.replace(/\D/g, ""), 10) || 0));
      return items.map((e) => String(e.data));
    }
    const e = el.valueName ? findEntry(entries, key, el.valueName) : null;
    if (el.type === "decimal" || el.type === "longDecimal") return e ? Number(e.data) : el.defaultValue;
    if (el.type === "text") return e ? String(e.data) : el.defaultValue;
    if (el.type === "multiText") return e ? (Array.isArray(e.data) ? e.data : []) : [];
    if (el.type === "boolean") {
      if (e) return entryMatches(e, el.trueValue || { t: "decimal", v: 1 });
      return el.defaultChecked;
    }
    if (el.type === "enum") {
      if (e) { const i = el.items.findIndex((it) => entryMatches(e, it.value)); if (i >= 0) return i; }
      return el.defaultItem;
    }
    return undefined;
  }

  function getPolicyState(entries, pol) {
    let state = "notconfigured";
    const ev = pol.enabledValue || { t: "decimal", v: 1 };
    const dv = pol.disabledValue || { t: "decimal", v: 0 };
    if (pol.valueName) {
      const e = findEntry(entries, pol.key, pol.valueName);
      const del = findEntry(entries, pol.key, "**del." + pol.valueName);
      if (e) { if (entryMatches(e, ev)) state = "enabled"; else if (entryMatches(e, dv)) state = "disabled"; }
      else if (del) { if (ev.t === "delete") state = "enabled"; else if (dv.t === "delete") state = "disabled"; }
    } else {
      const all = (l) => l && l.length && l.every((i) => entryMatches(findEntry(entries, i.key, i.valueName), i.value));
      if (all(pol.enabledList)) state = "enabled";
      else if (all(pol.disabledList)) state = "disabled";
      else if (pol.elements.length) {
        const anyVal = pol.elements.some((el) => el.type === "list" ? entries.some((e) => ieq(e.key, ek(pol, el)) && !e.name.startsWith("**")) : (el.valueName && findEntry(entries, ek(pol, el), el.valueName)));
        const anyDel = pol.elements.some((el) => (el.valueName && findEntry(entries, ek(pol, el), "**del." + el.valueName)) || (el.type === "list" && findEntry(entries, ek(pol, el), "**delvals.")));
        if (anyVal) state = "enabled"; else if (anyDel) state = "disabled";
      }
    }
    const values = {};
    for (const el of pol.elements) values[el.id] = readElement(entries, pol, el);
    return { state, values };
  }

  /* ---------------- GptTmpl.inf (Security Settings) ---------------- */
  function parseInf(text) {
    const sections = []; let cur = null;
    for (let line of text.split(/\r?\n/)) {
      line = line.replace(/^\uFEFF/, "");
      if (!line.trim() || line.trim().startsWith(";")) continue;
      const m = /^\s*\[(.+?)\]\s*$/.exec(line);
      if (m) { cur = { name: m[1], items: [] }; sections.push(cur); continue; }
      if (!cur) continue;
      const i = line.indexOf("=");
      if (i < 0) { cur.items.push({ key: line.trim(), value: null }); continue; }
      cur.items.push({ key: line.slice(0, i).trim(), value: line.slice(i + 1).trim() });
    }
    return { sections };
  }
  function infSection(model, name, create) {
    let s = model.sections.find((x) => ieq(x.name, name));
    if (!s && create) { s = { name, items: [] }; model.sections.push(s); }
    return s || null;
  }
  function infGet(model, section, key) {
    const s = infSection(model, section); if (!s) return undefined;
    const it = s.items.find((i) => ieq(i.key, key)); return it ? it.value : undefined;
  }
  function infSet(model, section, key, value) {
    if (value === undefined || value === null) { const s = infSection(model, section); if (s) s.items = s.items.filter((i) => !ieq(i.key, key)); return; }
    const s = infSection(model, section, true);
    const it = s.items.find((i) => ieq(i.key, key));
    if (it) it.value = String(value); else s.items.push({ key, value: String(value) });
  }
  function serializeInf(model) {
    model = { sections: model.sections.filter((s) => s.items.length > 0 || ieq(s.name, "Unicode") || ieq(s.name, "Version")) };
    if (!infSection(model, "Unicode")) model.sections.unshift({ name: "Unicode", items: [{ key: "Unicode", value: "yes" }] });
    let ver = infSection(model, "Version");
    if (!ver) { ver = { name: "Version", items: [{ key: "signature", value: '"$CHICAGO$"' }, { key: "Revision", value: "1" }] }; model.sections.push(ver); }
    // Unicode first, Version last
    const order = [...model.sections.filter((s) => ieq(s.name, "Unicode")), ...model.sections.filter((s) => !ieq(s.name, "Unicode") && !ieq(s.name, "Version")), ...model.sections.filter((s) => ieq(s.name, "Version"))];
    // Match what Windows writes: no spaces around "=" in these sections, spaces everywhere else.
    const tight = (n) => /^(Unicode|Version|Registry Values|Registry Keys)$/i.test(n);
    return order.map((s) => "[" + s.name + "]\r\n" + s.items.map((i) => i.value === null ? i.key + "\r\n" : i.key + (tight(s.name) ? "=" : " = ") + i.value + "\r\n").join("")).join("");
  }
  /* "Registry Values" items look like  MACHINE\Path\Name=4,1 */
  function infGetRegValue(model, path) {
    const v = infGet(model, "Registry Values", path); if (v === undefined) return undefined;
    const i = v.indexOf(","); return { type: Number(v.slice(0, i)), value: v.slice(i + 1) };
  }
  function infSetRegValue(model, path, type, value) {
    if (type === null) { infSet(model, "Registry Values", path, null); return; }
    infSet(model, "Registry Values", path, type + "," + value);
  }
  function infGetPrivilege(model, priv) {
    const v = infGet(model, "Privilege Rights", priv); if (v === undefined) return undefined;
    return v.split(",").map((x) => x.trim()).filter(Boolean);
  }
  function infSetPrivilege(model, priv, list) {
    infSet(model, "Privilege Rights", priv, list === undefined ? null : list.join(","));
  }

  /* ---------------- scripts.ini / psscripts.ini ---------------- */
  function parseScriptsIni(text) {
    const m = parseInf(text); const out = {};
    for (const s of m.sections) {
      const list = []; const byIdx = {};
      for (const it of s.items) {
        const mm = /^(\d+)(CmdLine|Parameters)$/i.exec(it.key); if (!mm) continue;
        const idx = Number(mm[1]); byIdx[idx] = byIdx[idx] || { cmd: "", params: "" };
        if (/cmdline/i.test(mm[2])) byIdx[idx].cmd = it.value || ""; else byIdx[idx].params = it.value || "";
      }
      Object.keys(byIdx).map(Number).sort((a, b) => a - b).forEach((k) => list.push(byIdx[k]));
      out[s.name] = list;
    }
    return out;
  }
  function serializeScriptsIni(data) {
    let s = "";
    for (const sec of Object.keys(data)) {
      if (!data[sec].length) continue;
      s += "[" + sec + "]\r\n";
      data[sec].forEach((x, i) => { s += i + "CmdLine=" + x.cmd + "\r\n" + i + "Parameters=" + (x.params || "") + "\r\n"; });
    }
    return s;
  }

  /* ---------------- Group Policy Preferences XML ---------------- */
  const GPP = {
    drives: { clsidList: "{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}", clsidItem: "{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" },
    registry: { clsidList: "{A3CCFC41-DFDB-43a5-8D26-0FE8B954DA51}", clsidItem: "{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}" }
  };
  const ACTION_IMAGE = { C: 0, R: 1, U: 2, D: 3 };
  const nowStamp = () => new Date().toISOString().replace("T", " ").slice(0, 19);

  function buildDrivesXml(items) {
    const body = items.map((d) => {
      const name = d.letter + ":";
      return `<Drive clsid="${GPP.drives.clsidItem}" name="${xmlEscape(name)}" status="${xmlEscape(name)}" image="${ACTION_IMAGE[d.action] ?? 2}" changed="${d.changed || nowStamp()}" uid="${d.uid || guid()}">` +
        `<Properties action="${d.action}" thisDrive="${d.thisDrive || "NOCHANGE"}" allDrives="${d.allDrives || "NOCHANGE"}" userName="${xmlEscape(d.userName || "")}" path="${xmlEscape(d.path)}" label="${xmlEscape(d.label || "")}" persistent="${d.persistent ? 1 : 0}" useLetter="${d.useLetter === false ? 0 : 1}" letter="${xmlEscape(d.letter)}"/></Drive>`;
    }).join("");
    return `<?xml version="1.0" encoding="utf-8"?>\r\n<Drives clsid="${GPP.drives.clsidList}">${body}</Drives>`;
  }
  function parseDrivesXml(text) {
    const doc = parseXml(text);
    return Array.from(doc.getElementsByTagName("Drive")).map((d) => {
      const p = d.getElementsByTagName("Properties")[0]; const g = (a) => (p ? p.getAttribute(a) : null) || "";
      return { uid: d.getAttribute("uid"), changed: d.getAttribute("changed"), action: g("action") || "U", letter: g("letter") || (d.getAttribute("name") || "").replace(":", ""), path: g("path"), label: g("label"), userName: g("userName"), persistent: g("persistent") === "1", useLetter: g("useLetter") !== "0", thisDrive: g("thisDrive"), allDrives: g("allDrives") };
    });
  }
  const HIVES = ["HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER", "HKEY_CLASSES_ROOT", "HKEY_USERS"];
  function buildRegistryXml(items) {
    const body = items.map((r) => {
      let value = r.value;
      if (r.type === "REG_DWORD") value = (Number(r.value) >>> 0).toString(16).toUpperCase().padStart(8, "0");
      const label = r.name || "(Default)";
      return `<Registry clsid="${GPP.registry.clsidItem}" name="${xmlEscape(label)}" status="${xmlEscape(label)}" image="${ACTION_IMAGE[r.action] ?? 2 }" changed="${r.changed || nowStamp()}" uid="${r.uid || guid()}">` +
        `<Properties action="${r.action}" displayDecimal="${r.type === "REG_DWORD" ? 1 : 0}" default="${r.name ? 0 : 1}" hive="${r.hive}" key="${xmlEscape(r.key)}" name="${xmlEscape(r.name || "")}" type="${r.type}" value="${xmlEscape(value)}"/></Registry>`;
    }).join("");
    return `<?xml version="1.0" encoding="utf-8"?>\r\n<RegistrySettings clsid="${GPP.registry.clsidList}">${body}</RegistrySettings>`;
  }
  function parseRegistryXml(text) {
    const doc = parseXml(text);
    return Array.from(doc.getElementsByTagName("Registry")).map((r) => {
      const p = r.getElementsByTagName("Properties")[0]; const g = (a) => (p ? p.getAttribute(a) : null) || "";
      const type = g("type") || "REG_SZ";
      return { uid: r.getAttribute("uid"), changed: r.getAttribute("changed"), action: g("action") || "U", hive: g("hive") || "HKEY_LOCAL_MACHINE", key: g("key"), name: g("name"), type, value: type === "REG_DWORD" ? parseInt(g("value") || "0", 16) : g("value") };
    });
  }


  /* ---------------- Advanced Audit Policy (audit.csv) ---------------- */
  const AUDIT_LABEL = { 0: "No Auditing", 1: "Success", 2: "Failure", 3: "Success and Failure" };
  const AUDIT_HEADER = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value";
  function csvSplit(line) {
    const out = []; let cur = "", q = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (q) { if (c === '"') { if (line[i + 1] === '"') { cur += '"'; i++; } else q = false; } else cur += c; }
      else if (c === '"') q = true; else if (c === ",") { out.push(cur); cur = ""; } else cur += c;
    }
    out.push(cur); return out;
  }
  function parseAuditCsv(text) {
    const rows = [];
    const lines = text.replace(/^\uFEFF/, "").split(/\r?\n/).filter((l) => l.trim());
    for (const l of lines.slice(1)) {
      const c = csvSplit(l);
      if (c.length < 7) continue;
      rows.push({ machine: c[0], target: c[1], name: c[2], guid: c[3].toUpperCase(), inclusion: c[4], exclusion: c[5], value: Number(c[6]) || 0 });
    }
    return rows;
  }
  const csvQ = (v) => (/[",\r\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v);
  function buildAuditCsv(rows) {
    return [AUDIT_HEADER].concat(rows.map((r) => [r.machine || "", r.target || "System", r.name, r.guid, AUDIT_LABEL[r.value] || "No Auditing", r.exclusion || "", r.value].map((x) => csvQ(String(x))).join(","))).join("\r\n") + "\r\n";
  }

  /* ---------------- Windows Firewall rules (Registry.pol, REG_SZ "v2.31|Action=Allow|...|") ---------------- */
  const FW_KEY = "Software\\Policies\\Microsoft\\WindowsFirewall\\FirewallRules";
  const FW_PROTO = { 6: "TCP", 17: "UDP", 1: "ICMPv4", 58: "ICMPv6", 47: "GRE", 2: "IGMP", 50: "ESP", 51: "AH" };
  function parseFwRule(str) {
    const t = String(str).split("|").filter((x) => x !== "");
    const r = { version: /^v\d/.test(t[0] || "") ? t.shift() : "v2.31", action: "Allow", active: true, dir: "In", protocol: "", lport: [], rport: [], profiles: [], la4: [], ra4: [], app: "", svc: "", name: "", desc: "", group: "", extra: [] };
    for (const tok of t) {
      const i = tok.indexOf("="); if (i < 0) { r.extra.push(tok); continue; }
      const k = tok.slice(0, i), v = tok.slice(i + 1);
      switch (k.toLowerCase()) {
        case "action": r.action = v; break; case "active": r.active = /^true$/i.test(v); break; case "dir": r.dir = v; break;
        case "protocol": r.protocol = v; break; case "lport": r.lport.push(...v.split(",")); break; case "rport": r.rport.push(...v.split(",")); break;
        case "profile": r.profiles.push(v); break; case "la4": r.la4.push(v); break; case "ra4": r.ra4.push(v); break;
        case "app": r.app = v; break; case "svc": r.svc = v; break; case "name": r.name = v; break; case "desc": r.desc = v; break; case "embedctxt": r.group = v; break;
        default: r.extra.push(tok);
      }
    }
    return r;
  }
  const noPipe = (s) => String(s || "").replace(/\|/g, "/");
  function buildFwRule(r) {
    const t = [r.version || "v2.31", "Action=" + r.action, "Active=" + (r.active ? "TRUE" : "FALSE"), "Dir=" + r.dir];
    if (r.protocol) t.push("Protocol=" + r.protocol);
    for (const p of r.lport) if (p) t.push("LPort=" + p);
    for (const p of r.rport) if (p) t.push("RPort=" + p);
    for (const p of r.profiles) t.push("Profile=" + p);
    for (const a of r.la4) if (a) t.push("LA4=" + a);
    for (const a of r.ra4) if (a) t.push("RA4=" + a);
    if (r.app) t.push("App=" + noPipe(r.app));
    if (r.svc) t.push("Svc=" + noPipe(r.svc));
    t.push("Name=" + noPipe(r.name));
    if (r.desc) t.push("Desc=" + noPipe(r.desc));
    if (r.group) t.push("EmbedCtxt=" + noPipe(r.group));
    for (const e of r.extra) t.push(e);
    return t.join("|") + "|";
  }

  /* ---------------- fast pre-filter for thousands of policies ---------------- */
  function keySet(entries) { const s = new Set(); for (const e of entries) s.add(String(e.key).toLowerCase()); return s; }
  function policyMayBeConfigured(pol, keys) {
    if (keys.has(String(pol.key).toLowerCase())) return true;
    for (const l of [pol.enabledList, pol.disabledList]) if (l) for (const i of l) if (keys.has(String(i.key).toLowerCase())) return true;
    for (const el of pol.elements) {
      if (el.key && keys.has(String(el.key).toLowerCase())) return true;
      for (const l of [el.trueList, el.falseList]) if (l) for (const i of l) if (keys.has(String(i.key).toLowerCase())) return true;
      if (el.items) for (const it of el.items) if (it.list) for (const i of it.list) if (keys.has(String(i.key).toLowerCase())) return true;
    }
    return false;
  }

  /* CSE (client-side extension) + MMC tool GUIDs that must be registered on the GPO. */
  const CSE = {
    registry: { cse: "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}", machine: "{D02B1F72-3407-48AE-BA88-E8213C6761F1}", user: "{D02B1F73-3407-48AE-BA88-E8213C6761F1}" },
    security: { cse: "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}", machine: "{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}" },
    scripts: { cse: "{42B5FAAE-6536-11D2-AE5A-0000F87571E3}", machine: "{40B6664F-4972-11D1-A7CA-0000F87571E3}", user: "{40B66650-4972-11D1-A7CA-0000F87571E3}" },
    drives: { cse: "{5794DAFD-BE60-433f-88A2-1A31939AC01F}", user: "{2EA1A81B-48E5-45E9-8BB7-A6E3AC170006}" },
    prefRegistry: { cse: "{B087BE9D-ED37-454f-AF9C-04291E351182}", machine: "{BEE07A6A-EC9F-4659-B8C9-0B1937907C83}", user: "{BEE07A6A-EC9F-4659-B8C9-0B1937907C83}" },
    audit: { cse: "{F3CCC681-B74C-4060-9F26-CD84525DCA2A}", machine: "{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}" }
  };

  /* Parse the link/exts attribute into a readable "which extensions does this GPO use" list. */
  const CSE_NAMES = {
    "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}": "Administrative Templates (registry)",
    "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}": "Security Settings",
    "{42B5FAAE-6536-11D2-AE5A-0000F87571E3}": "Scripts",
    "{5794DAFD-BE60-433F-88A2-1A31939AC01F}": "Preferences: Drive Maps",
    "{B087BE9D-ED37-454F-AF9C-04291E351182}": "Preferences: Registry",
    "{F3CCC681-B74C-4060-9F26-CD84525DCA2A}": "Advanced Audit Policy"
  };
  function extNames(s) {
    const out = [];
    for (const m of String(s || "").matchAll(/\[((?:\{[0-9A-Fa-f-]+\})+)\]/g)) {
      const c = m[1].match(/\{[0-9A-Fa-f-]+\}/)[0].toUpperCase();
      out.push(CSE_NAMES[c] || c);
    }
    return out;
  }

  return {
    REG, b64ToBytes, bytesToB64, decodeText, encodeUtf16le, encodeUtf8, guid, xmlEscape,
    findEntry, valToEntry, parseAdml, parseAdmx, buildTree, applyPolicy, getPolicyState, removePolicy,
    parseInf, serializeInf, infGet, infSet, infGetRegValue, infSetRegValue, infGetPrivilege, infSetPrivilege,
    parseScriptsIni, serializeScriptsIni, buildDrivesXml, parseDrivesXml, buildRegistryXml, parseRegistryXml, HIVES,
    CSE, CSE_NAMES, extNames, AUDIT_LABEL, parseAuditCsv, buildAuditCsv, FW_KEY, FW_PROTO, parseFwRule, buildFwRule, keySet, policyMayBeConfigured
  };
});

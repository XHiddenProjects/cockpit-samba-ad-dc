const { JSDOM } = require("jsdom"); global.DOMParser = new JSDOM("").window.DOMParser;
const C = require("../gpo-core.js"); const B = require("../gpo-builtin.js");
const m = B.model; let bad = 0;
for (const p of m.policies) {
  const ids = new Set(); p.elements.forEach(e => { if (ids.has(e.id)) { bad++; console.log("dup element id", p.name); } ids.add(e.id); });
  const e = C.applyPolicy([], p, "enabled", {}); const d = C.applyPolicy([], p, "disabled");
  const s1 = C.getPolicyState(e, p).state, s2 = C.getPolicyState(d, p).state, s3 = C.applyPolicy(e, p, "notconfigured").length;
  if (s1 !== "enabled" || s2 !== "disabled" || s3 !== 0) { bad++; console.log("FAIL", p.name, s1, s2, s3); }
}
console.log("policies:", m.policies.length, "categories:", m.categories.length, "problems:", bad);
const cats = new Set(m.categories.map(c => c.id)); for (const p of m.policies) if (!cats.has(p.category)) console.log("missing category", p.name);
for (const cls of ["Machine","User"]) { const t = C.buildTree([m], cls); const cnt = (n) => n.policies.length + n.children.reduce((a,c)=>a+cnt(c),0); console.log(cls, "tree roots:", t.map(n => n.name + "(" + cnt(n) + ")").join(", ")); }
console.log(JSON.stringify(C.applyPolicy([], m.policies.find(p=>p.name==="AutoUpdateCfg"), "enabled", {AUOptions:2, ScheduledInstallDay:3, ScheduledInstallTime:22}).map(e=>[e.name,e.data])));

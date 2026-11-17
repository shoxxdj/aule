// Faux DOM minimal pour exécuter le script du rapport sous Node (pas de navigateur dans l'environnement de test).
// Avec --base : `fetch` est branché sur un VRAI serveur `aule serve` (test de bout en bout de l'interface).
const fs = require("fs");

class Node {}
class Text extends Node { constructor(t) { super(); this.textContent = t; } }
class El extends Node {
  constructor(tag) { super(); this.tag = tag; this.children = []; this.attrs = {}; this.listeners = {}; this.className = ""; this.value = ""; this.checked = false; this._text = null; }
  setAttribute(k, v) { this.attrs[k] = v; }
  addEventListener(t, f) { (this.listeners[t] ||= []).push(f); }
  append(...k) { this.children.push(...k); }
  replaceChildren(...k) { this.children = k; }
  get textContent() { return this._text ?? this.children.map(c => c.textContent).join(" "); }
  set textContent(v) { this._text = v; this.children = []; }
  all(pred, out = []) { if (pred(this)) out.push(this); for (const c of this.children) if (c instanceof El) c.all(pred, out); return out; }
  fire(type, ev = {}) { for (const f of this.listeners[type] || []) f({ stopPropagation() {}, target: this, ...ev }); }
}

function boot(htmlPath, { hash = "", base = null } = {}) {
  const html = fs.readFileSync(htmlPath, "utf8");
  const scripts = [...html.matchAll(/<script(?: [^>]*)?>([\s\S]*?)<\/script>/g)].map(m => m[1]);
  const ids = {};
  for (const id of ["title", "subtitle", "tabs", "project", "q", "view", "notices", "runwrap"]) ids[id] = new El("div");
  ids["audit-data"] = new El("script");
  ids["audit-data"].textContent = scripts[0];
  const document = { getElementById: id => ids[id], createElement: t => new El(t), createElementNS: (ns, t) => new El(t), createTextNode: t => new Text(t) };
  globalThis.__pending = [];
  const realFetch = globalThis.fetch;
  const fetchImpl = base ? (url, opts) => realFetch(base + url, opts) : () => { throw new Error("fetch indisponible hors mode live"); };
  new Function("document", "Node", "location", "history", "navigator", "fetch", "confirm", scripts[1])(
    document, Node, { hash }, { replaceState() {} }, {}, fetchImpl, () => true);
  return { ids, El, document };
}

async function settle() {  // attend les actions asynchrones lancées par la page (clics -> fetch -> re-rendu)
  while (globalThis.__pending.length) await Promise.allSettled(globalThis.__pending.splice(0));
}

module.exports = { boot, settle, El };

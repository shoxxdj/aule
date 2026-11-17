// Sollicite toute l'interface (onglets, tris, filtres, lignes dépliées) et renvoie le texte de chaque onglet en JSON.
const { boot, settle } = require("./dom_stub.js");
const args = process.argv.slice(2);
const file = args[0];
const hash = args.find(a => a.startsWith("#")) || "";
const base = (args.find(a => a.startsWith("http")) || null);

(async () => {
  const { ids } = boot(file, { hash, base });
  await settle();
  const out = { tabs: {}, tabsOpen: {}, clicks: 0 };
  const view = () => ids.view;
  const click = async el => { el.fire("click"); out.clicks++; await settle(); };
  const nTabs = ids.tabs.children.length;
  for (let i = 0; i < nTabs; i++) {
    const tab = ids.tabs.children[i];
    if (tab.textContent.trim().startsWith("Audit")) continue;      // lancer un audit n'est pas un « balayage » anodin
    await click(tab);
    const name = ids.tabs.children[i].textContent.trim();
    out.tabs[name] = view().textContent;                            // capturé AVANT toute interaction
    const count = pred => view().all(pred).length;
    const nth = (pred, n) => view().all(pred)[n];
    const sortable = e => e.tag === "th" && e.className.includes("sortable");
    for (let s = 0, n = count(sortable); s < n; s++) await click(nth(sortable, s));
    const clickable = e => e.tag === "tr" && e.className.includes("clickable");
    for (let r = 0, n = count(clickable); r < n; r++) await click(nth(clickable, r));
    out.tabsOpen[name] = view().textContent;                        // toutes les lignes détaillables sont dépliées
    const toggle = e => e.tag === "button" && e.className.includes("toggle");
    for (let b = 0, n = count(toggle); b < n; b++) { await click(nth(toggle, b)); await click(nth(toggle, b)); }   // actionné puis rétabli
    const select = e => e.tag === "select";
    for (let x = 0, n = count(select); x < n; x++) {
      const opts = nth(select, x).all(e => e.tag === "option");
      if (opts.length > 1) for (const o of [opts[1], opts[0]]) { nth(select, x).fire("change", { target: { value: o.value } }); out.clicks++; await settle(); }
    }
    const copy = e => e.tag === "button" && e.className.includes("copy");
    for (let c = 0, n = count(copy); c < n; c++) await click(nth(copy, c));
  }
  const proj = ids.project.children[1];
  if (proj) { ids.project.fire("change", { target: { value: proj.value } }); await settle(); out.projectFilter = proj.value; out.afterProject = view().textContent; }
  ids.q.fire("input", { target: { value: "zzz-no-match" } });
  await settle();
  out.afterSearch = view().textContent;
  out.title = ids.title.textContent;
  out.notices = ids.notices.textContent;
  process.stdout.write(JSON.stringify(out) + "\n", () => process.exit(0));  // vider le tube avant de quitter (gros JSON tronqué sinon)
})().catch(e => { console.error(e.stack || e); process.exit(1); });

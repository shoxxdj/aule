// Auditeur face aux doublons : une ligne par constat, triage du groupe entier, retour aux détections brutes, marge du code.
const { boot, settle } = require("./dom_stub.js");
const [file, base, mode] = process.argv.slice(2);
(async () => {
  const { ids } = boot(file, { base });
  await settle();
  const view = () => ids.view;
  const must = (el, what) => { if (!el) throw new Error("introuvable : " + what); return el; };
  const click = async (el, what) => { must(el, what).fire("click"); await settle(); };
  const tabEl = name => ids.tabs.children.find(t => t.textContent.trim().startsWith(name));
  const tab = async name => click(tabEl(name), "onglet " + name);
  const dataRows = () => view().all(e => e.tag === "tr" && e.className.startsWith("row"));
  const row = text => dataRows().find(e => e.textContent.includes(text));
  const btn = (text, root = view()) => root.all(e => e.tag === "button" && e.textContent.trim() === text)[0];
  const out = {};
  if (mode === "main") {
    out.synthese = view().textContent;                    // KPI : constats et détections recoupées
    await tab("Secrets");
    out.badge = tabEl("Secrets").textContent;
    out.rows = dataRows().length;
    out.settingsRow = row("settings.py").textContent;
    out.counts = view().textContent;
    await click(row("settings.py"), "ligne settings.py");
    out.detail = view().textContent;
    const box = must(view().all(e => e.className === "triagebox")[0], "boîte de triage");
    await click(btn("faux positif", box), "triage faux positif");
    out.afterTriage = row("settings.py") ? row("settings.py").textContent : null;
    await click(btn("regrouper les doublons"), "bouton regrouper");
    out.ungroupedRows = dataRows().length;
    out.ungroupedBadge = tabEl("Secrets").textContent;
    await click(btn("regrouper les doublons"), "bouton regrouper (retour)");
    out.regroupedRows = dataRows().length;
    await tab("Code (SAST)");
    out.sastBadge = tabEl("Code (SAST)").textContent;
    out.sastRows = dataRows().length;
    out.sqli = row("py/sql-injection").textContent;
    await click(row("py/sql-injection"), "ligne sql-injection");
    out.sastDetail = view().textContent;
    await click(btn("Voir dans le code"), "voir dans le code");
    out.markers = view().all(e => e.className.startsWith("mkb")).length;
    out.fileList = view().textContent;
  } else if (mode === "conflict") {
    await tab("Code (SAST)");
    out.sqli = row("py/sql-injection").textContent;
    await click(row("py/sql-injection"), "ligne sql-injection");
    out.detail = view().textContent;
  } else if (mode === "bulk") {   // « tout marquer » sur les lignes affichées = tous les groupes entiers
    await tab("Secrets");
    const bulk = must(view().all(e => e.className.includes("bulk"))[0], "barre en masse");
    globalThis.confirm = () => true;
    await click(btn("à revoir", bulk), "à revoir en masse");
    out.done = true;
  }
  process.stdout.write(JSON.stringify(out) + "\n", () => process.exit(0));
})().catch(e => { console.error(e.stack || e); process.exit(1); });

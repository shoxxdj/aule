// Auditeur dans l'onglet « Sorties brutes » (page live, vrai serveur) : arborescence, SARIF complet, JSON en tableau, texte, lien depuis un constat.
const { boot, settle } = require("./dom_stub.js");
const [file, base] = process.argv.slice(2);
(async () => {
  const { ids } = boot(file, { base });
  await settle();
  const view = () => ids.view;
  const must = (el, what) => { if (!el) throw new Error("introuvable : " + what); return el; };
  const btn = text => view().all(e => e.tag === "button" && e.textContent.trim() === text)[0];
  const btnStarts = text => view().all(e => e.tag === "button" && e.textContent.trim().startsWith(text))[0];
  const click = async (el, what) => { must(el, what).fire("click"); await settle(); };
  const tab = async name => click(ids.tabs.children.find(t => t.textContent.trim().startsWith(name)), "onglet " + name);
  const entryFile = (entry, name) => {   // plusieurs projets ont la même exécution : on vise celle de repo-git
    const e = view().all(x => x.className === "rawentry").find(x => x.textContent.includes(entry) && x.textContent.includes("repo-git"));
    return must(must(e, "entrée " + entry).all(x => x.className.includes("file")).find(x => x.textContent.includes(name)), `fichier ${name} de ${entry}`);
  };
  const out = {};
  await tab("Sorties brutes");
  out.tree = view().textContent;
  await click(entryFile("codeql/python", "rich.sarif"), "rich.sarif");
  out.header = view().textContent;
  await click(view().all(e => e.className === "rres")[0], "résultat 0");
  out.detail0 = view().textContent;
  const q = must(view().all(e => e.tag === "input" && (e.attrs.placeholder || "").startsWith("message"))[0], "filtre texte");
  q.value = "second"; q.fire("change", { target: q }); await settle();
  out.filtered = view().textContent;
  await click(btn("Règles (3)"), "sous-onglet Règles");
  out.rules = view().textContent;
  await click(btnStarts("Notifications"), "sous-onglet Notifications");
  out.notifs = view().textContent;
  await click(btn("Résumé"), "sous-onglet Résumé");
  out.summary = view().textContent;
  await click(btn("JSON brut"), "sous-onglet JSON brut");
  out.jsonRoot = view().textContent;
  await click(view().all(e => e.className === "jrow")[0], "racine JSON");
  out.jsonOpen = view().textContent;

  await click(entryFile("gitleaks/dir", "report.json"), "report.json gitleaks");
  out.table = view().textContent;                         // tableau par défaut pour un tableau JSON
  await click(view().all(e => e.tag === "tr" && e.className.includes("clickable"))[0], "ligne du tableau");
  out.tableRow = view().textContent;
  await click(entryFile("opengrep/scan", "cmd.txt"), "cmd.txt opengrep");
  out.cmd = view().textContent;

  await tab("Code (SAST)");
  const row = must(view().all(e => e.tag === "tr" && e.className.includes("clickable") && e.textContent.includes("py/sql-injection"))[0], "constat CodeQL");
  await click(row, "ligne du constat");
  await click(btn("Voir la sortie brute complète"), "lien vers la sortie brute");
  out.deep = view().textContent;
  process.stdout.write(JSON.stringify(out) + "\n", () => process.exit(0));
})().catch(e => { console.error(e.stack || e); process.exit(1); });

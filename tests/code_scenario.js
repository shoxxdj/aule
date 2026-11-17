// Auditeur dans l'onglet « Sources » (page live, vrai serveur) : du constat au code, chemin de données, recherches, historique, SARIF.
const fs = require("fs");
const { boot, settle } = require("./dom_stub.js");
const [file, base, mode, extra] = process.argv.slice(2);
(async () => {
  const { ids } = boot(file, { base });
  await settle();
  const view = () => ids.view;
  const must = (el, what) => { if (!el) throw new Error("introuvable : " + what); return el; };
  const btn = text => view().all(e => e.tag === "button" && e.textContent.trim() === text)[0];
  const click = async (el, what) => { must(el, what).fire("click"); await settle(); };
  const tab = async name => click(ids.tabs.children.find(t => t.textContent.trim().startsWith(name)), "onglet " + name);
  const row = text => view().all(e => e.tag === "tr" && e.className.includes("clickable") && e.textContent.includes(text))[0];
  const crow = text => view().all(e => e.className.split(" ").includes("crow") && e.textContent.includes(text))[0];
  const input = ph => view().all(e => e.tag === "input" && (e.attrs.placeholder || "").startsWith(ph))[0];
  const type = async (ph, value) => { const i = must(input(ph), "champ " + ph); i.value = value; i.fire("change"); await settle(); };
  const lines = () => view().all(e => e.className.split(" ").includes("cl"));
  const target = () => { const t = lines().find(e => e.className.includes("tgt")); return t ? t.textContent : null; };
  const out = {};

  if (mode === "main") {
    await tab("Code (SAST)");
    await click(row("py/sql-injection"), "constat CodeQL");
    await click(btn("Voir dans le code"), "lien vers le code");
    out.open = view().textContent;
    out.target = target();
    out.markers = view().all(e => e.className.startsWith("mkb")).length;
    out.rangeLines = lines().filter(e => e.className.includes("rng")).length;
    out.stepBadges = lines().flatMap(l => l.all(e => e.className === "stepn")).map(e => e.textContent);   // dans le code, pas dans le panneau
    await click(btn("étape suivante ›"), "étape suivante");
    out.step1 = { text: view().textContent, target: target() };
    await click(btn("étape suivante ›"), "étape suivante (2)");
    out.step2 = { text: view().textContent, target: target() };
    await click(btn("‹ étape précédente"), "étape précédente");
    out.back = view().textContent.includes("étape 1/2");
    await type("n°", "2");
    out.goto = target();
    await type("dans ce fichier", "execute");
    out.find = view().textContent;
    out.findTarget = target();
    await type("Aller au fichier", "service");
    await click(crow("service.py"), "résultat Aller au fichier");
    out.quick = view().textContent;
    out.quickMarkers = view().all(e => e.className.startsWith("mkb")).length;
    await type("Chercher dans le projet", "needle_here");
    out.searchResults = view().textContent;
    await click(crow("pkg/util.py:1"), "résultat de recherche");
    out.search = view().textContent;
    out.hot = view().textContent;
    const nodes = () => view().all(e => e.className.split(" ").includes("cnode")).map(e => e.textContent.trim());
    const pkg = () => view().all(e => e.className.split(" ").includes("cnode") && e.textContent.includes("pkg/"))[0];
    out.treeAuto = nodes();                                     // ouvrir util.py depuis la recherche a déplié pkg/ tout seul
    await click(pkg(), "dossier pkg (replier)");
    out.treeClosed = nodes();
    await click(pkg(), "dossier pkg (déplier)");
    out.treeReopened = nodes();
    const sel = view().all(e => e.tag === "select")[0];
    sel.value = "plain"; sel.fire("change"); await settle();
    out.plain = view().all(e => e.className.split(" ").includes("cnode")).map(e => e.textContent.trim());
  } else if (mode === "runswitch") {   // extra = identifiant du premier run (celui qui contient rich.sarif)
    await tab("Sorties brutes");
    out.latestTree = view().textContent;                   // run le plus récent : pas de rich.sarif
    await tab("Code (SAST)");
    await click(row("py/sql-injection"), "constat CodeQL");
    await click(btn("Voir dans le code"), "lien vers le code");
    out.opened = view().textContent.includes("cur.execute");
    const sel = must(ids.runwrap.all(e => e.tag === "select")[0], "sélecteur de run");
    sel.value = extra; sel.fire("change"); await settle();
    out.tabAfter = ids.tabs.children.filter(t => t.attrs["aria-selected"] === true || t.attrs["aria-selected"] === "true").map(t => t.textContent.trim().split(" ")[0]);
    await tab("Sources");
    out.sourcesAfter = view().textContent;                 // le fichier du run précédent ne doit pas rester ouvert
    await tab("Sorties brutes");
    out.firstTree = view().textContent;                    // arborescence relue pour le run choisi : rich.sarif présent
  } else if (mode === "drift") {
    await tab("Code (SAST)");
    await click(row("py/sql-injection"), "constat CodeQL");
    await click(btn("Voir dans le code"), "lien vers le code");
    out.text = view().textContent;
  } else if (mode === "history") {
    await tab("Secrets");
    await click(row("config.py"), "secret de config.py");
    await click(btn("Voir dans le code (au commit)"), "lien au commit");
    out.atCommit = view().textContent;
    await click(btn("voir l'état actuel"), "état actuel");
    out.now = view().textContent;
  } else if (mode === "sarif") {
    await tab("Sorties brutes");
    const e = view().all(x => x.className === "rawentry").find(x => x.textContent.includes("codeql/python") && x.textContent.includes("repo-git"));
    await click(must(e.all(x => x.className.includes("file")).find(x => x.textContent.includes("rich.sarif")), "rich.sarif"), "rich.sarif");
    await click(view().all(x => x.className === "rres")[0], "résultat 0");
    const codeButtons = () => view().all(x => x.tag === "button" && x.textContent.trim() === "code");
    out.codeButtons = codeButtons().length;
    await click(codeButtons()[0], "bouton code de l'emplacement");
    out.c1 = { text: view().textContent, target: target() };
    await tab("Sorties brutes");
    const li = must(view().all(x => x.tag === "li" && x.textContent.includes("web.py:9"))[0], "étape web.py");
    await click(must(li.all(x => x.tag === "button" && x.textContent.trim() === "code")[0], "bouton code de l'étape"), "étape web.py");
    out.c2 = view().textContent;
    await tab("Sorties brutes");
    await click(btn("Par fichier"), "sous-onglet Par fichier");
    out.files = view().textContent;
    await click(row("db.py"), "ligne db.py");
    out.filtered = view().textContent;
    const inp = must(view().all(x => x.tag === "input" && x.attrs.type === "file")[0], "champ d'import");
    inp.files = [{ name: "ci.sarif", text: async () => fs.readFileSync(extra, "utf8") }];
    inp.fire("change"); await settle();
    out.imported = view().textContent;
  }
  process.stdout.write(JSON.stringify(out) + "\n", () => process.exit(0));
})().catch(e => { console.error(e.stack || e); process.exit(1); });

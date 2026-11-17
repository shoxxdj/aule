// Scénario d'un auditeur dans l'interface live, contre un vrai serveur. Les effets en base sont vérifiés côté Python.
// usage : node live_scenario.js <page.html> <base-url> [mask]
const { boot, settle } = require("./dom_stub.js");
const [file, base, mode] = process.argv.slice(2);
const realFetch = globalThis.fetch;
const steps = {};

(async () => {
  const { ids } = boot(file, { base });
  await settle();
  const view = () => ids.view;
  const btn = (text, root = view()) => root.all(e => e.tag === "button" && e.textContent.trim() === text)[0];
  const must = (el, what) => { if (!el) throw new Error("introuvable : " + what); return el; };
  const click = async (el, what) => { must(el, what).fire("click"); await settle(); };
  const tab = async name => click(ids.tabs.children.find(t => t.textContent.trim().startsWith(name)), "onglet " + name);
  const openRow = async n => click(view().all(e => e.tag === "tr" && e.className.includes("clickable"))[n], "ligne " + n);
  const ensureOpen = async text => { if (!btn(text)) await openRow(0); };   // l'état « déplié » est conservé : ne pas refermer
  const setValue = (el, value, ev = "input") => { must(el, "champ").value = value; el.fire(ev, { target: el }); };
  const inputs = () => view().all(e => e.tag === "input" && e.attrs.type === "text");
  const textareas = () => view().all(e => e.tag === "textarea");

  // 1. Secrets : triage individuel (fiche dépliée)
  await tab("Secrets");
  await openRow(0);
  steps.liveBanner = ids.notices.textContent;
  if (mode === "mask") {
    steps.maskedBefore = view().textContent;
    await click(btn("révéler"), "révéler");
    steps.maskedAfter = view().textContent;
  }
  setValue(inputs()[0], "clé de démonstration");                       // le brouillon doit survivre au re-rendu
  ids.q.fire("input", { target: { value: "" } });                       // provoque un re-rendu complet
  steps.draftKept = inputs()[0].value;
  await click(btn("faux positif", view().all(e => e.className === "triagebox")[0]), "triage faux positif");
  steps.afterTriage = view().textContent;

  // 2. Triage en masse (confirmation acceptée par le faux DOM)
  const bulk = must(view().all(e => e.className.includes("bulk"))[0], "barre de triage en masse");
  steps.bulkLabel = bulk.textContent;
  await click(btn("à revoir", bulk), "masse à revoir");
  steps.afterBulk = view().textContent;

  // 3. Constat créé depuis un résultat
  await ensureOpen("Créer un constat à partir de ceci");
  await click(btn("Créer un constat à partir de ceci"), "créer un constat");
  steps.formTab = view().textContent;
  setValue(inputs()[0], "Secret AWS retrouvé en clair dans le dépôt");
  setValue(textareas()[0], "Constaté à la lecture du code.\nImpact : accès au compte cloud.");
  await click(btn("Enregistrer"), "enregistrer le constat");
  steps.findingsTable = view().textContent;
  const token = JSON.parse(ids["audit-data"].textContent).options.token;
  steps.findingsApi = (await (await realFetch(base + "/api/data", { headers: { "X-Audit-Token": token } })).json()).findings;

  // 4. Erreur serveur remontée à l'écran (titre vide)
  await click(btn("+ Nouveau constat"), "nouveau constat");
  setValue(inputs()[0], "   ");
  await click(btn("Enregistrer"), "enregistrer vide");
  steps.flash = view().textContent;
  await click(btn("Annuler"), "annuler");

  // 5. Modifier puis supprimer
  await ensureOpen("Modifier");
  await click(btn("Modifier"), "modifier");
  setValue(inputs()[0], "Titre modifié par l'auditeur");
  const statusSel = view().all(e => e.tag === "select").find(s => s.all(o => o.tag === "option").some(o => o.value === "dismissed"));
  setValue(statusSel, "confirmed", "change");
  await click(btn("Enregistrer"), "enregistrer la modification");
  steps.afterEdit = view().textContent;

  // 6. Note de projet
  await tab("Synthèse");
  await openRow(0);
  setValue(textareas()[0], "Application exposée sur Internet ; à confirmer avec le client.");
  await click(btn("Enregistrer la note"), "enregistrer la note");
  steps.noteValue = textareas()[0].value;   // le champ est reconstruit depuis les données rechargées

  // 7. Graphe des liens
  await tab("Liens");
  steps.graph = { circles: view().all(e => e.tag === "circle").length, lines: view().all(e => e.tag === "line").length, text: view().textContent };

  // 8. Comparaison avec un run antérieur
  await tab("Comparaison");
  const diffSel = must(view().all(e => e.tag === "select")[0], "sélecteur de run");
  const options = diffSel.all(o => o.tag === "option");
  setValue(diffSel, options[1].value, "change");
  await settle();
  steps.diff = view().textContent;

  // 9. Lancer un audit depuis l'interface, suivre sa progression
  steps.titleBefore = ids.title.textContent;
  await tab("Audit");
  steps.jobForm = view().textContent;
  await click(btn("Lancer l'audit"), "lancer l'audit");
  steps.jobDone = view().textContent;
  steps.titleAfter = ids.title.textContent;
  steps.runSelect = ids.runwrap.textContent;

  // 10. Suppression d'un constat
  await tab("Constats");
  await ensureOpen("Supprimer");
  await click(btn("Supprimer"), "supprimer");
  steps.afterDelete = view().textContent;

  process.stdout.write(JSON.stringify(steps) + "\n", () => process.exit(0));  // vider le tube avant de quitter (gros JSON tronqué sinon)
})().catch(e => { console.error(e.stack || e); process.exit(1); });

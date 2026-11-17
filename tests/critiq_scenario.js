// Auditeur dans l'onglet SAST : applique l'avis IA (faux positifs sûrs uniquement) depuis la page live.
const { boot, settle } = require("./dom_stub.js");
const [file, base] = process.argv.slice(2);
(async () => {
  const { ids } = boot(file, { base });
  await settle();
  const view = () => ids.view;
  const btnStarting = text => view().all(e => e.tag === "button" && e.textContent.trim().startsWith(text))[0];
  const tab = async name => { ids.tabs.children.find(t => t.textContent.trim().startsWith(name)).fire("click"); await settle(); };
  const out = {};
  await tab("Secrets");
  out.secretsHasApply = !!btnStarting("Appliquer l'avis IA");               // aucun faux positif sûr côté secrets (avis incertains)
  await tab("Code (SAST)");
  out.before = view().textContent;
  const apply = btnStarting("Appliquer l'avis IA");
  out.applyLabel = apply ? apply.textContent.trim() : null;
  if (apply) { apply.fire("click"); await settle(); }
  out.after = view().textContent;
  out.applyStillThere = !!btnStarting("Appliquer l'avis IA");
  process.stdout.write(JSON.stringify(out) + "\n", () => process.exit(0));  // vider le tube avant de quitter (gros JSON tronqué sinon)
})().catch(e => { console.error(e.stack || e); process.exit(1); });

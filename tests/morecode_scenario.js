// Page live : la case « autoriser le modèle à demander plus de code » (onglet Audit), cochée ou non, puis « Lancer la critique IA ».
const { boot, settle } = require("./dom_stub.js");
const [file, base, mode] = process.argv.slice(2);   // mode : toggle (inverse la case) | default (la laisse telle quelle)
(async () => {
  const { ids } = boot(file, { base });
  await settle();
  const view = () => ids.view;
  const tab = async name => { ids.tabs.children.find(t => t.textContent.trim().startsWith(name)).fire("click"); await settle(); };
  await tab("Audit");
  const label = view().all(e => e.tag === "label" && e.textContent.includes("plus de code"))[0];
  const out = { found: !!label };
  if (label) {
    const input = label.all(e => e.tag === "input")[0];
    out.text = label.textContent;
    out.initial = !!input.checked;
    if (mode === "toggle") { input.checked = !input.checked; input.fire("change", { target: input }); await settle(); }
    const start = view().all(e => e.tag === "button" && e.textContent.trim().startsWith("Lancer la critique IA"))[0];
    start.fire("click"); await settle();
  }
  process.stdout.write(JSON.stringify(out) + "\n", () => process.exit(0));
})().catch(e => { console.error(e.stack || e); process.exit(1); });

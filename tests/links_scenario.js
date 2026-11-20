// Utilisateur face au graphe des liens (page statique, faux DOM) : sélection, filtres, isolement, recherche, glisser, zoom, épinglage, plafond.
const { boot, settle } = require("./dom_stub.js");
const [file] = process.argv.slice(2);
(async () => {
  const { ids } = boot(file);
  await settle();
  const view = () => ids.view;
  const must = (el, what) => { if (!el) throw new Error("introuvable : " + what); return el; };
  const cls = (e, c) => (e.attrs && e.attrs.class || e.className || "").split(" ").includes(c);
  const nodes = () => view().all(e => cls(e, "lg-node"));
  const edges = () => view().all(e => cls(e, "lg-edge"));
  const btn = text => view().all(e => e.tag === "button" && e.textContent.trim().startsWith(text))[0];
  const node = label => must(nodes().find(n => n.textContent.includes(label)), "nœud " + label);
  const click = async (el, what) => { must(el, what).fire("click"); await settle(); };
  const tab = async name => click(ids.tabs.children.find(t => t.textContent.trim().startsWith(name)), "onglet " + name);
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const root = () => must(view().all(e => cls(e, "lgsvg"))[0], "svg du graphe");
  const viewport = () => must(view().all(e => cls(e, "lg-viewport"))[0], "viewport");
  const scale = () => parseFloat(/scale\(([\d.]+)\)/.exec(viewport().attrs.transform)[1]);
  const pin = n => { const v = n.all(e => e.tag === "circle")[0].attrs["stroke-dasharray"]; return v && v !== "none" ? v : null; };
  const at = n => /translate\(([-\d.]+) ([-\d.]+)\)/.exec(n.attrs.transform).slice(1).map(Number);
  const out = {}, mode = process.argv[3] || "main";
  const finish = obj => process.stdout.write(JSON.stringify(obj) + "\n", () => process.exit(0));
  if (mode === "cap" || mode === "solo") {  // plafond de lisibilité ; projet choisi dans le filtre global mais sans aucun lien
    if (mode === "solo") { ids.project.fire("change", { target: { value: "solo" } }); await settle(); }
    await tab("Liens");
    return finish({ nodes: nodes().length, edges: edges().length, text: view().textContent });
  }

  await tab("Liens");
  out.initial = { nodes: nodes().length, edges: edges().length, circles: view().all(e => e.tag === "circle").length, text: view().textContent, labels: view().all(e => cls(e, "lg-el")).map(e => e.textContent) };

  await click(node("plain"), "nœud plain");
  out.project = { text: view().textContent, selected: nodes().filter(n => cls(n, "sel")).length, dimNodes: nodes().filter(n => cls(n, "dim")).length, dimEdges: view().all(e => cls(e, "lg-edge-g") && cls(e, "dim")).length };

  await click(node("gh••••R8"), "nœud secret");
  out.secret = { text: view().textContent };
  await click(btn("Chercher dans les secrets"), "chercher dans les secrets");
  out.afterSearch = { q: ids.q.value, secretsTab: view().textContent.includes("Secrets") || view().textContent.includes("secret") };
  await tab("Liens");
  out.selectionKept = nodes().filter(n => cls(n, "sel")).length;

  await click(btn("Secret partagé"), "légende secrets");
  out.noSecrets = { nodes: nodes().length, edges: edges().length };
  await click(btn("Secret partagé"), "légende secrets (retour)");
  await click(btn("dépend de"), "légende dépend de");
  out.noDepends = { edges: edges().length, nodes: nodes().length };
  await click(btn("dépend de"), "légende dépend de (retour)");

  await click(node("plain"), "nœud plain");
  out.focusLabel0 = btn("Isoler").textContent.trim();
  await click(btn("Isoler"), "isoler");
  out.focus1 = { label: btn("Isoler").textContent.trim(), nodes: nodes().length };
  await click(btn("Isoler"), "isoler 2");
  out.focus2 = { label: btn("Isoler").textContent.trim(), nodes: nodes().length };
  await click(btn("Isoler"), "isoler (retour)");

  const search = must(view().all(e => e.tag === "input" && (e.attrs.placeholder || "").startsWith("Chercher un nœud"))[0], "recherche");
  search.value = "api"; search.fire("change"); await settle();
  out.search = { text: view().textContent, selected: nodes().filter(n => cls(n, "sel")).map(n => n.textContent) };

  // glisser un nœud : il suit le pointeur, reste épinglé, entraîne ses voisins ; le « click » qui suit est ignoré
  await click(root(), "fond (désélection)");
  const target = node("repo-git"), neighbor = node("plain"), before = at(target), nBefore = at(neighbor);
  target.fire("pointerdown", { clientX: 200, clientY: 200 });
  root().fire("pointermove", { clientX: 320, clientY: 260 });
  root().fire("pointerup", {});
  const after = at(node("repo-git")), nAfter = at(node("plain"));
  out.drag = { moved: Math.hypot(after[0] - before[0], after[1] - before[1]), neighborMoved: Math.hypot(nAfter[0] - nBefore[0], nAfter[1] - nBefore[1]),
    pinned: pin(node("repo-git")), button: btn("Libérer les nœuds").textContent.trim() };
  node("repo-git").fire("click"); await settle();
  out.dragClick = { selected: nodes().filter(n => cls(n, "sel")).length };       // ignoré : pas de sélection fantôme
  await sleep(10);
  node("repo-git").fire("dblclick"); await settle();
  out.dblclick = { pinned: pin(node("repo-git")), button: btn("Libérer les nœuds").textContent.trim() };

  // zoom et panoramique
  const k0 = scale();
  root().fire("wheel", { clientX: 500, clientY: 310, deltaY: -100, preventDefault() {} });
  const k1 = scale();
  root().fire("wheel", { clientX: 500, clientY: 310, deltaY: 100, preventDefault() {} });
  root().fire("wheel", { clientX: 500, clientY: 310, deltaY: 100, preventDefault() {} });
  out.zoom = { in: k1 > k0, out: scale() < k1 };
  const t0 = viewport().attrs.transform;
  root().fire("pointerdown", { clientX: 10, clientY: 10 }); root().fire("pointermove", { clientX: 90, clientY: 50 }); root().fire("pointerup", {});
  out.pan = { changed: viewport().attrs.transform !== t0 };
  root().fire("dblclick", {});
  out.fit = { k: scale() };

  // relation : un clic sur une arête
  await click(view().all(e => cls(e, "lg-hit"))[0], "arête");
  out.edge = { text: view().textContent };
  await click(btn("Ajuster"), "ajuster");
  out.adjust = { selectedEdge: view().all(e => cls(e, "lg-edge") && cls(e, "sel")).length };

  process.stdout.write(JSON.stringify(out) + "\n", () => process.exit(0));
})().catch(e => { console.error(e.stack || e); process.exit(1); });

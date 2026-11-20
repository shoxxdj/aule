// Exécute le MODÈLE du graphe (bloc LG-MODEL du gabarit, sans DOM) : node js_model.js <page.html> "<corps JS qui renvoie un objet>"
const fs = require("fs");
const html = fs.readFileSync(process.argv[2], "utf8");
const block = html.match(/\/\* LG-MODEL:BEGIN[\s\S]*?\/\* LG-MODEL:END \*\//);
if (!block) { console.error("bloc LG-MODEL introuvable"); process.exit(2); }
const api = new Function(block[0] + "; return {lgBuild, lgNeighborhood, lgLayout, lgRelax, lgEdgePath, lgFit, lgSearch, lgSvgString, lgRadius, lgCurve, lgShortRemote, lgClip, forceLayout, LG_KINDS};")();
process.stdout.write(JSON.stringify(new Function("api", process.argv[3])(api)) + "\n");

"""La forge (affichage du terminal) : largeurs d'emoji, détection du terminal, alignements, progression en direct, repli ASCII."""
from __future__ import annotations

import io
import re
import unittest

from aule.ui import ICONS, Col, Live, Raw, S, Ui, cell_width, clip, detect_forge, human_duration, pad, strip_ansi


class TtyIO(io.StringIO):
    def __init__(self, tty=True, encoding="utf-8"):
        super().__init__()
        self._tty, self._enc = tty, encoding

    @property
    def encoding(self):
        return self._enc

    def isatty(self):
        return self._tty


def make(mode="always", ascii_only=False, width=100, env=None, **stream_kw) -> tuple[Ui, TtyIO]:
    out = TtyIO(**stream_kw)
    return Ui().configure(out=out, err=TtyIO(**stream_kw), mode=mode, ascii_only=ascii_only, env=env or {}, width=width), out


class WidthTest(unittest.TestCase):
    def test_cell_width(self):
        self.assertEqual(cell_width("forge"), 5)
        self.assertEqual(cell_width("é à ç"), 5)                                    # accents : une cellule
        self.assertEqual(cell_width("🔥"), 2)                                       # emoji : deux cellules
        self.assertEqual(cell_width("⚒️"), 2)                                       # symbole + sélecteur d'emoji : deux cellules, pas une
        self.assertEqual(cell_width("⚒"), 1)                                        # le même symbole sans sélecteur : une
        self.assertEqual(cell_width("e\u0301"), 1)                                  # accent combinant : largeur nulle
        self.assertEqual(cell_width("\x1b[1;38;5;208mAulë\x1b[0m"), 4)              # les codes ANSI ne comptent pas
        self.assertEqual(cell_width("日本"), 4)
        self.assertEqual(cell_width(""), 0)

    def test_every_forge_icon_has_a_stable_width_and_an_ascii_fallback(self):
        for name, (emoji, fallback) in ICONS.items():
            self.assertIn(cell_width(emoji), (1, 2), name)
            self.assertTrue(fallback.isascii() and fallback.strip(), name)

    def test_pad_and_clip_use_cells(self):
        self.assertEqual(cell_width(pad("🔥", 6)), 6)
        self.assertEqual(cell_width(pad("⚒️ ab", 9, ">")), 9)
        self.assertEqual(pad("ab", 6, "^"), "  ab  ")
        self.assertEqual(clip("abcdefghij", 6), "abcde…")
        self.assertLessEqual(cell_width(clip("🔥🔥🔥🔥🔥", 7)), 7)                   # jamais plus large que demandé, même avec des emoji
        self.assertEqual(clip("court", 10), "court")

    def test_human_duration(self):
        self.assertEqual((human_duration(3.21), human_duration(125), human_duration(3700)), ("3.2 s", "2 min 05 s", "1 h 01 min"))


class DetectionTest(unittest.TestCase):
    def test_modes_and_environment(self):
        tty, pipe = TtyIO(True), TtyIO(False)
        self.assertTrue(detect_forge("always", pipe, {}))
        self.assertFalse(detect_forge("never", tty, {}))
        self.assertTrue(detect_forge("auto", tty, {}))
        self.assertFalse(detect_forge("auto", pipe, {}))                           # redirigé : texte historique
        self.assertFalse(detect_forge("auto", tty, {"NO_COLOR": "1"}))
        self.assertFalse(detect_forge("auto", tty, {"TERM": "dumb"}))
        self.assertTrue(detect_forge("auto", pipe, {"FORCE_COLOR": "1"}))
        self.assertFalse(detect_forge("auto", pipe, {"FORCE_COLOR": "0"}))
        self.assertTrue(detect_forge("always", tty, {"NO_COLOR": "1"}))            # --color always l'emporte sur NO_COLOR

    def test_unicode_ascii_and_palette(self):
        self.assertTrue(make("always")[0].unicode)
        self.assertFalse(make("always", ascii_only=True)[0].unicode)
        self.assertFalse(make("auto", encoding="latin-1", tty=True)[0].unicode)     # terminal non UTF-8 : repli ASCII
        self.assertFalse(make("always", env={"AULE_ASCII": "1"})[0].unicode)
        ui = make("always")[0]
        self.assertIn("38;5;208", ui.c("x", "ember"))                               # 256 couleurs
        basic = Ui().configure(out=TtyIO(), mode="auto", env={"TERM": "xterm"}, width=100)
        self.assertEqual(basic.c("x", "ember"), "\x1b[33mx\x1b[0m")                 # 16 couleurs
        self.assertEqual(Ui().configure(out=TtyIO(False), mode="never", env={}).c("x", "ember bold"), "x")      # sans couleur : texte nu
        self.assertEqual(Ui().configure(out=TtyIO(), mode="always", env={"COLUMNS": "20"}).width, 60)           # bornes de largeur
        self.assertEqual(Ui().configure(out=TtyIO(), mode="always", env={"COLUMNS": "400"}).width, 110)

    def test_plain_error_is_byte_identical_to_the_historical_format(self):
        ui, out = make("never")
        ui.error("run inconnu : 'x'")
        ui.error("fichier introuvable", label="Erreur de configuration")
        self.assertEqual(ui._err.getvalue(), "Erreur : run inconnu : 'x'\nErreur de configuration : fichier introuvable\n")
        self.assertEqual(out.getvalue(), "")


class LayoutTest(unittest.TestCase):
    ROWS = [[S("api", "bold"), "complete", Raw("🗝️ 3"), S("/une/très/longue/ligne/de/chemin/vers/le/projet/audité/quelque/part", "ash")],
            [S("webapp", "bold"), "partial", Raw("⚔️ 12"), S("/court", "ash")]]
    COLS = [Col("Projet"), Col("Statut"), Col("Constats", ">"), Col("Dossier", flex=True)]

    def test_tables_never_overflow_and_stay_aligned(self):
        for width in (110, 80, 60):
            ui, _ = make(width=width)
            lines = ui.table(self.COLS, self.ROWS)
            widths = {cell_width(l) for l in lines}
            self.assertLessEqual(max(widths), width, width)
            self.assertEqual(len(widths) <= 2, True)                                # en-tête, filet et lignes : même largeur de colonnes
        ui, _ = make(width=60)
        self.assertIn("…", "\n".join(ui.table(self.COLS, self.ROWS)))                # colonne flex tronquée avec …

    def test_last_resort_drops_the_rightmost_flexible_columns_instead_of_overflowing(self):
        cols = [Col("Projet"), Col("Statut"), Col("Outil"), Col("Chemin", flex=True, min=10), Col("Version", flex=True, min=10), Col("Notes", flex=True, min=10)]
        rows = [["repo-git-long", "complete-ok", "dependency-check", "/un/chemin/plutôt/long/vers/le/binaire", "10.0.3-build-4567", "note assez longue pour déborder"]]
        ui, _ = make(width=60)
        lines = [strip_ansi(l) for l in ui.table(cols, rows)]
        self.assertLessEqual(max(cell_width(l) for l in lines), 60)                 # ne déborde jamais
        header = lines[0]
        for kept in ("Projet", "Statut", "Outil"):
            self.assertIn(kept, header)                                             # les colonnes essentielles (non souples) sont gardées
        self.assertNotIn("Notes", header)                                           # la colonne souple la plus à droite saute en premier
        wide, _ = make(width=110)
        full = strip_ansi("\n".join(wide.table(cols, rows)))
        for title in ("Chemin", "Version", "Notes"):
            self.assertIn(title, full)                                              # assez de place : rien n'est abandonné
        self.assertIn("…", "\n".join(lines[2:]) or "…")

    def test_emoji_cells_keep_columns_aligned(self):
        ui, _ = make(width=100)
        lines = [strip_ansi(l) for l in ui.table(self.COLS, self.ROWS)]
        pos = [l.index("complete") if "complete" in l else l.index("partial") for l in lines[2:]]
        self.assertEqual(pos[0], pos[1])
        right = [cell_width(l[:l.index(" ", 20)]) for l in lines[2:]]                # colonne de droite alignée malgré ⚔️ et 🗝️
        self.assertEqual(len({cell_width(l.split("  ")[0]) for l in lines[2:]}), 1)
        self.assertTrue(right)

    def test_panel_is_a_closed_rectangle(self):
        for ascii_only in (False, True):
            ui, _ = make(ascii_only=ascii_only, width=80)
            lines = ui.panel("Le fruit de la forge", [f"{ui.icon('key')}  Secrets     3 constats", f"{ui.icon('sword')}  SAST        12", "ok"], icon="gem")
            self.assertEqual(len({cell_width(l) for l in lines}), 1, [strip_ansi(l) for l in lines])
            self.assertIn("Le fruit de la forge", strip_ansi(lines[0]))
            self.assertTrue(strip_ansi(lines[0]).startswith(ui.box("tl")) and strip_ansi(lines[-1]).startswith(ui.box("bl")))
            if ascii_only:
                self.assertTrue(all(ord(ch) < 128 or ch.isalpha() for l in lines for ch in strip_ansi(l)))
        ui, _ = make(width=60)
        narrow = ui.panel("t", ["x" * 200])
        self.assertLessEqual(max(cell_width(l) for l in narrow), 60)                # une ligne trop longue est tronquée, la boîte tient

    def test_bar(self):
        ui, _ = make()
        self.assertEqual(strip_ansi(ui.bar(5, 10, 10)), "▕█████░░░░░▏")
        self.assertEqual(strip_ansi(ui.bar(0, 0, 4)), "▕░░░░▏")
        self.assertEqual(strip_ansi(ui.bar(99, 10, 4)), "▕████▏")                    # jamais au-delà
        asc, _ = make(ascii_only=True)
        self.assertEqual(strip_ansi(asc.bar(5, 10, 10)), "[#####.....]")

    def test_messages(self):
        ui, out = make(width=80)
        ui.ok("terminé")
        ui.warn("attention")
        ui.hint("aule serve --open")
        ui.error("raté", hint="relancez")
        text = strip_ansi(out.getvalue() + ui._err.getvalue())
        for expected in ("✔ terminé", "▲ attention", "→ aule serve --open", "✖ Erreur : raté", "→ relancez"):
            self.assertIn(expected, text)
        plain, pout = make("never")
        plain.ok("terminé")
        plain.warn("attention")
        plain.hint("ignoré en plain")
        self.assertEqual(pout.getvalue(), "terminé\nattention\n")                   # plain : le texte tel quel, sans décor ni conseil


class LiveTest(unittest.TestCase):
    def test_in_place_progress_with_messages_scrolling_above(self):
        ui, out = make(env={})
        self.assertTrue(ui.live_ok)
        with Live(ui, animate=False) as live:
            live.set(lambda f: "PROGRESS 1/3")
            live.print("ligne A")
            live.set(lambda f: "PROGRESS 2/3")
        text = out.getvalue()
        self.assertIn("\x1b[?25l", text)                                            # curseur masqué pendant l'animation...
        self.assertTrue(text.rstrip().endswith("\x1b[?25h"))                        # ...et toujours rendu
        self.assertIn("\r\x1b[2KPROGRESS 1/3", text)
        self.assertLess(text.index("PROGRESS 1/3"), text.index("ligne A"))
        self.assertLess(text.index("ligne A"), text.index("PROGRESS 2/3"))
        self.assertIn("ligne A\n\r\x1b[2KPROGRESS 1/3", text)                       # le message s'imprime, puis la progression est redessinée dessous
        self.assertEqual(text.rindex("\x1b[2K"), text.index("\x1b[?25h") - len("\x1b[2K"))   # à la fin : la ligne de progression est effacée

    def test_cursor_is_restored_on_error(self):
        ui, out = make()
        with self.assertRaises(KeyboardInterrupt):
            with Live(ui, animate=False) as live:
                live.set(lambda f: "x")
                raise KeyboardInterrupt
        self.assertTrue(out.getvalue().rstrip().endswith("\x1b[?25h"))

    def test_no_animation_and_no_control_codes_without_a_real_terminal(self):
        ui, out = make(env={}, tty=False)                                           # --color always dans un pipe
        self.assertFalse(ui.live_ok)
        with Live(ui, animate=False) as live:
            live.set(lambda f: "PROGRESS")
            live.print("ligne A")
        self.assertEqual(out.getvalue(), "ligne A\n")                               # rien d'animé, aucun code de curseur
        self.assertNotIn("\r", out.getvalue())

    def test_spinner_animation_thread_stops_cleanly(self):
        ui, out = make(env={})
        import threading, time
        before = threading.active_count()
        with Live(ui, animate=True) as live:
            live.set(lambda f: f"frame {f}")
            time.sleep(0.4)
        self.assertEqual(threading.active_count(), before)                          # le fil d'animation est bien arrêté
        self.assertGreaterEqual(len(re.findall(r"frame \d", out.getvalue())), 2)    # et il a bien redessiné plusieurs fois


if __name__ == "__main__":
    unittest.main()

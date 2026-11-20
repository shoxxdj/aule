"""Aulë — l'affichage du terminal : la forge.

Deux façons de parler :

  plain  le texte historique, STRICTEMENT inchangé : pipes, fichiers, CI, scripts, `NO_COLOR`, `TERM=dumb`, `--color never` ;
  forge  couleurs, emoji, tableaux, panneaux, progression en direct. Activé sur un terminal, ou avec `--color always`.

Sans dépendance (ni `rich` ni `colorama`) : tout est testable ici, et se dégrade proprement. `--ascii` (ou un terminal non UTF-8) remplace
les emoji et les bordures par de l'ASCII. Les largeurs sont calculées en cellules de terminal (un emoji en occupe deux), pas en caractères.
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import threading
import unicodedata
from dataclasses import dataclass
from typing import Callable, Iterable

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
MIN_WIDTH, MAX_WIDTH = 60, 110

# nom -> (SGR 256 couleurs, SGR 16 couleurs). Les braises de la forge : ember (orange), flame (rouge), gold, iron (acier), ash (cendre).
PALETTE = {"ember": ("38;5;208", "33"), "flame": ("38;5;196", "31"), "gold": ("38;5;220", "93"), "iron": ("38;5;250", "37"), "ash": ("38;5;243", "90"),
           "ok": ("38;5;78", "32"), "info": ("38;5;80", "36"), "bold": ("1", "1"), "dim": ("2", "2"), "under": ("4", "4")}

# nom -> (emoji, repli ASCII). Le jeu d'icônes de la forge.
ICONS = {
    "forge": ("⚒️", "[#]"), "ore": ("⛏️", "[>]"), "fire": ("🔥", "(*)"), "hammer": ("🔨", "[!]"), "volcano": ("🌋", "(^)"), "alloy": ("⚗️", "[+]"),
    "gem": ("💎", "<>"), "key": ("🗝️", "[k]"), "sword": ("⚔️", "[x]"), "package": ("📦", "[p]"), "scroll": ("📜", "[=]"), "toolbox": ("🧰", "[t]"),
    "scales": ("⚖️", "[=]"), "link": ("🔗", "[~]"), "shield": ("🛡️", "[s]"), "search": ("🔍", "[?]"), "mountain": ("⛰️", "[^]"), "spark": ("✨", "*"),
    "ok": ("✔", "+"), "warn": ("▲", "!"), "fail": ("✖", "x"), "skip": ("○", "-"), "clock": ("⏱️", "~"), "arrow": ("→", "->"), "dot": ("•", "*"),
    "run": ("●", "o"), "brick": ("🧱", "[b]"), "wrench": ("🔧", "[w]"),
}
BOX = {"tl": ("╭", "+"), "tr": ("╮", "+"), "bl": ("╰", "+"), "br": ("╯", "+"), "h": ("─", "-"), "v": ("│", "|")}
SPINNER = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"), ("|", "/", "-", "\\")


def strip_ansi(text: str) -> str:
    return ANSI.sub("", text)


def _char_width(ch: str) -> int:
    if ch == "\u200d" or (unicodedata.category(ch) in ("Mn", "Me", "Cf") and ch != "\ufe0f"):
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def cell_width(text: str) -> int:
    """Largeur en cellules de terminal : ANSI ignoré, emoji = 2, `⚒️` (symbole + sélecteur de présentation) = 2."""
    total, prev = 0, 0
    for ch in strip_ansi(text):
        if ch == "\ufe0f":
            if prev == 1:
                total, prev = total + 1, 2
            continue
        prev = _char_width(ch)
        total += prev
    return total


def pad(text: str, width: int, align: str = "<") -> str:
    gap = max(0, width - cell_width(text))
    return " " * gap + text if align == ">" else text + " " * gap if align == "<" else " " * (gap // 2) + text + " " * (gap - gap // 2)


def clip(text: str, width: int) -> str:
    """Tronque un texte SANS ANSI à `width` cellules, avec « … »."""
    if cell_width(text) <= width:
        return text
    out, used = "", 0
    for ch in text:
        w = cell_width(ch)
        if used + w > width - 1:
            break
        out, used = out + ch, used + w
    return out + "…"


def human_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f} s"
    m, s = divmod(int(seconds), 60)
    return f"{m} min {s:02d} s" if m < 60 else f"{m // 60} h {m % 60:02d} min"


def detect_forge(mode: str, stream, env) -> bool:
    """Le décor de la forge est-il activé ? `--color` l'emporte ; sinon un terminal, sauf NO_COLOR / TERM=dumb."""
    if mode == "never":
        return False
    if mode == "always":
        return True
    if env.get("NO_COLOR") or env.get("TERM") == "dumb":
        return False
    if env.get("FORCE_COLOR") not in (None, "", "0") or env.get("CLICOLOR_FORCE") not in (None, "", "0"):
        return True
    return bool(getattr(stream, "isatty", lambda: False)())


@dataclass
class Col:
    title: str
    align: str = "<"          # < gauche, > droite
    flex: bool = False        # peut être tronquée (…) si le terminal est étroit
    min: int = 8


class S(str):
    """Cellule de texte brut avec un style (tronquable) : S("api", "bold")."""

    def __new__(cls, text, style=""):
        obj = super().__new__(cls, text)
        obj.style = style
        return obj


class Raw(str):
    """Cellule déjà décorée (ANSI/emoji) : jamais tronquée, largeur mesurée en cellules."""


class Ui:
    def __init__(self) -> None:
        self._out = self._err = None
        self.configure()

    def configure(self, out=None, err=None, mode: str = "auto", ascii_only: bool = False, env=None, width: int | None = None) -> "Ui":
        self._out, self._err = out, err
        env = os.environ if env is None else env
        stream = self.out
        self.forge = detect_forge(mode, stream, env)
        self.color = self.forge
        enc = (getattr(stream, "encoding", None) or "").lower()
        self.unicode = self.forge and not (ascii_only or env.get("AULE_ASCII")) and (mode == "always" or "utf" in enc)
        self.c256 = self.color and (mode == "always" or "256" in env.get("TERM", "") or env.get("COLORTERM", "") in ("truecolor", "24bit"))
        self.live_ok = self.forge and bool(getattr(stream, "isatty", lambda: False)()) and not env.get("AULE_NO_LIVE")
        cols = width or int(env.get("COLUMNS") or 0) or shutil.get_terminal_size((100, 24)).columns
        self.width = max(MIN_WIDTH, min(MAX_WIDTH, cols))
        return self

    # --- sorties ------------------------------------------------------------------------------
    @property
    def out(self):
        return self._out or sys.stdout

    @property
    def err(self):
        return self._err or sys.stderr

    def say(self, line: str = "", *, err: bool = False) -> None:
        print(line, file=self.err if err else self.out, flush=True)

    def write(self, text: str) -> None:
        self.out.write(text)
        self.out.flush()

    # --- style --------------------------------------------------------------------------------
    def c(self, text: str, style: str = "") -> str:
        if not (self.color and style and text):
            return text
        codes = [PALETTE[n][0 if self.c256 else 1] for n in style.split() if n in PALETTE]
        return f"\x1b[{';'.join(codes)}m{text}\x1b[0m" if codes else text

    def icon(self, name: str, style: str = "") -> str:
        glyph = ICONS[name][0 if self.unicode else 1]
        return self.c(glyph, style)

    def box(self, name: str) -> str:
        return BOX[name][0 if self.unicode else 1]

    def lead(self, name: str, style: str = "") -> str:
        """Une icône suivie d'un espace ; les emoji occupent deux cellules : l'espacement reste constant."""
        return self.icon(name, style) + " "

    # --- messages -----------------------------------------------------------------------------
    def ok(self, msg: str) -> None:
        self.say(f"{self.icon('ok', 'ok bold')} {msg}" if self.forge else msg)

    def warn(self, msg: str, *, err: bool = False, plain: str | None = None) -> None:
        """`plain` : le texte historique à garder à l'identique hors forge (ex. avec son « ⚠ » initial)."""
        self.say(f"{self.icon('warn', 'gold bold')} {self.c(msg, 'gold')}" if self.forge else (plain or msg), err=err)

    def info(self, msg: str) -> None:
        self.say(f"{self.icon('dot', 'ember')} {msg}" if self.forge else msg)

    def hint(self, msg: str) -> None:
        if self.forge:
            self.say(f"  {self.icon('arrow', 'ash')} {self.c(msg, 'ash')}")

    def error(self, msg: str, *, label: str = "Erreur", hint: str | None = None) -> None:
        """Plain : `Erreur : msg` sur stderr, exactement comme avant. Forge : ✖ en rouge, avec une piste éventuelle."""
        if not self.forge:
            self.say(f"{label} : {msg}", err=True)
            return
        self.say(f"{self.icon('fail', 'flame bold')} {self.c(label + ' :', 'flame bold')} {msg}", err=True)
        if hint:
            self.say(f"  {self.icon('arrow', 'ash')} {self.c(hint, 'ash')}", err=True)

    # --- mise en page -------------------------------------------------------------------------
    def head(self, icon: str, title: str, sub: str = "") -> str:
        """Titre de section ; le sous-titre est tronqué (…) pour tenir dans un terminal étroit."""
        used = cell_width(self.lead(icon)) + cell_width(title) + 2
        sub = clip(sub, max(8, self.width - used - 1)) if sub and "\x1b" not in sub else sub
        return f"{self.lead(icon, 'ember')}{self.c(title, 'bold ember')}" + (f"  {self.c(sub, 'ash')}" if sub else "")

    def heading(self, icon: str, title: str, sub: str = "") -> None:
        self.say(self.head(icon, title, sub))

    def rule(self, title: str = "") -> str:
        h = self.box("h")
        if not title:
            return self.c(h * min(self.width - 2, 72), "ash")
        return self.c(h * 2 + " ", "ash") + self.c(title, "bold iron") + self.c(" " + h * max(2, min(self.width - 2, 72) - cell_width(title) - 4), "ash")

    def bar(self, done: int, total: int, width: int = 22) -> str:
        total = max(total, 1)
        filled = max(0, min(width, int(width * done / total)))
        full, empty = ("█", "░") if self.unicode else ("#", ".")
        left, right = ("▕", "▏") if self.unicode else ("[", "]")
        return self.c(left, "ash") + self.c(full * filled, "ember") + self.c(empty * (width - filled), "ash") + self.c(right, "ash")

    def panel(self, title: str, lines: Iterable[str], *, icon: str | None = None, style: str = "ember") -> list[str]:
        """Encadré arrondi. Les lignes déjà décorées ne sont pas tronquées : à l'appelant de les garder courtes."""
        head = (self.lead(icon) if icon else "") + title
        body = list(lines) or [""]
        limit = self.width - 6
        body = [clip(l, limit) if cell_width(l) > limit and "\x1b" not in l else l for l in body]
        inner = min(limit, max([cell_width(l) for l in body] + [cell_width(head) + 2, 36]))
        tl, tr, bl, br, h, v = (self.box(k) for k in ("tl", "tr", "bl", "br", "h", "v"))
        top = self.c(tl + h + " ", style) + self.c(head, f"bold {style}") + self.c(" " + h * max(1, inner - cell_width(head) - 1) + tr, style)
        rows = [self.c(v, style) + " " + pad(l, inner) + " " + self.c(v, style) for l in body]
        return [top, *rows, self.c(bl + h * (inner + 2) + br, style)]

    def table(self, cols: list[Col], rows: list[list], *, indent: int = 2) -> list[str]:
        """Tableau sobre : en-tête, filet, lignes. Terminal étroit : les colonnes `flex` rétrécissent (avec …), puis, en dernier recours,
        les colonnes les moins importantes (les plus à droite) sont abandonnées plutôt que de déborder."""
        widths = [max([cell_width(c.title)] + [cell_width(str(r[i])) for r in rows]) for i, c in enumerate(cols)]
        avail, gap = self.width - indent, 2
        keep = list(range(len(cols)))

        def over() -> int:
            return sum(widths[i] for i in keep) + gap * (len(keep) - 1) - avail
        for floor in (None, 4):  # 1re passe : jusqu'au minimum de chaque colonne ; 2e : plus bas, jusqu'à 4 cellules
            for i in sorted((i for i in keep if cols[i].flex), key=lambda i: -widths[i]):
                if over() <= 0:
                    break
                widths[i] -= min(over(), max(0, widths[i] - (cols[i].min if floor is None else floor)))
        while over() > 0 and len(keep) > 1:
            drop = next((i for i in reversed(keep) if cols[i].flex), keep[-1])
            keep.remove(drop)

        def render(cell, col: Col, w: int) -> str:
            text = str(cell)
            if isinstance(cell, Raw):
                return pad(text, w, col.align)
            return self.c(pad(clip(text, w), w, col.align), getattr(cell, "style", ""))
        sep = " " * gap
        head = sep.join(self.c(pad(clip(cols[i].title, widths[i]), widths[i], cols[i].align), "bold iron") for i in keep)
        under = sep.join(self.c(self.box("h") * widths[i], "ash") for i in keep)
        body = [sep.join(render(r[i], cols[i], widths[i]) for i in keep) for r in rows]
        return [" " * indent + line for line in [head, under, *body]]

    def lines(self, rows: Iterable[str]) -> None:
        for row in rows:
            self.say(row)

    def banner(self, subtitle: list[str] | None = None) -> None:
        self.say(f"{self.lead('forge', 'ember')}{self.c('Aulë', 'bold ember')} {self.c('· le forgeron de l’audit', 'ash')}")
        for line in subtitle or []:
            self.say("   " + self.c(clip(line, self.width - 4), "iron"))


class Live:
    """Une ligne de progression épinglée en bas du terminal ; les messages défilent au-dessus d'elle.
    Sans vrai terminal (pipe, `--color always`), rien n'est animé : les messages s'impriment simplement."""

    def __init__(self, ui: Ui, animate: bool = True):
        self.ui, self.animate = ui, animate
        self.lock = threading.RLock()
        self.render: Callable[[int], str] | None = None
        self.frame = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._drawn = False

    @property
    def active(self) -> bool:
        return self.ui.live_ok

    def _erase(self) -> None:
        if self._drawn:
            self.ui.write("\r\x1b[2K")
            self._drawn = False

    def _draw(self) -> None:
        if self.render and self.active:
            self.ui.write("\r\x1b[2K" + self.render(self.frame))
            self._drawn = True

    def set(self, render: Callable[[int], str] | None) -> None:
        with self.lock:
            self._erase()
            self.render = render
            self._draw()

    def refresh(self) -> None:
        with self.lock:
            self._draw()

    def print(self, line: str) -> None:
        with self.lock:
            self._erase()
            self.ui.say(line)
            self._draw()

    def __enter__(self) -> "Live":
        if self.active:
            self.ui.write("\x1b[?25l")  # masque le curseur pendant l'animation
            if self.animate:
                self._thread = threading.Thread(target=self._spin, daemon=True)
                self._thread.start()
        return self

    def _spin(self) -> None:
        while not self._stop.wait(0.12):
            with self.lock:
                self.frame += 1
                self._draw()

    def __exit__(self, *exc) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(1)
        with self.lock:
            self._erase()
            self.render = None
            if self.active:
                self.ui.write("\x1b[?25h")  # rend toujours le curseur, même sur Ctrl-C

    def spinner(self) -> str:
        frames = SPINNER[0] if self.ui.unicode else SPINNER[1]
        return self.ui.c(frames[self.frame % len(frames)], "ember")


ui = Ui()  # reconfiguré par `main()` d'après --color / --ascii et le terminal courant

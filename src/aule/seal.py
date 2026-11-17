"""Chiffrement de data/ par gpg (chiffrement symétrique AES-256, intégrité vérifiée au déchiffrement).

On enveloppe gpg, outil éprouvé, plutôt que d'inventer un format. POSIX uniquement (le secret est passé à gpg par
un tube, jamais sur la ligne de commande ni dans un fichier). Limites assumées : l'effacement du dossier d'origine
n'est pas sécurisé (SSD, journalisation, sauvegardes) ; pour une vraie protection, chiffrez le disque ou le volume
qui héberge data/ (LUKS, FileVault, BitLocker, VeraCrypt).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tarfile
from pathlib import Path

WRONG = "phrase secrète incorrecte ou archive corrompue"


class SealError(Exception):
    pass


def _gpg() -> str:
    if os.name != "posix":
        raise SealError("seal/unseal : POSIX uniquement. Sous Windows, chiffrez le volume (BitLocker, VeraCrypt) ou utilisez WSL.")
    gpg = shutil.which("gpg")
    if not gpg:
        raise SealError("gpg introuvable : installez GnuPG (apt install gnupg, brew install gnupg)")
    return gpg


def _spawn(cmd: list[str], passphrase: str, **kw) -> subprocess.Popen:
    r, w = os.pipe()
    try:
        proc = subprocess.Popen([cmd[0], "--passphrase-fd", str(r), *cmd[1:]], pass_fds=(r,), stderr=subprocess.PIPE, **kw)
    finally:
        os.close(r)
    with os.fdopen(w, "w") as pipe:
        pipe.write(passphrase + "\n")
    return proc


def _reap(proc: subprocess.Popen) -> str:
    """Arrête le processus s'il tourne encore, ferme ses tubes, le récupère ; retourne la dernière ligne de stderr."""
    if proc.poll() is None:
        proc.kill()
    err = ""
    try:
        if proc.stderr:
            lines = proc.stderr.read().decode("utf-8", "replace").strip().splitlines()
            err = lines[-1] if lines else ""
    except OSError:
        pass
    for stream in (proc.stdin, proc.stdout, proc.stderr):
        try:
            if stream:
                stream.close()
        except OSError:
            pass
    proc.wait()
    return err


def _fail(message: str, detail: str) -> SealError:
    return SealError(message + (f" ({detail})" if detail else ""))


def seal(data_dir: Path, out: Path, passphrase: str) -> Path:
    if not data_dir.is_dir():
        raise SealError(f"{data_dir} n'est pas un dossier")
    if not passphrase:
        raise SealError("phrase secrète vide")
    out = out.resolve()
    if out.exists():
        raise SealError(f"{out} existe déjà (refus d'écraser)")
    if out.is_relative_to(data_dir.resolve()):
        raise SealError("le fichier chiffré ne peut pas être dans le dossier chiffré")
    proc = _spawn([_gpg(), "--batch", "--yes", "--quiet", "--symmetric", "--cipher-algo", "AES256",
                   "--pinentry-mode", "loopback", "--output", str(out)], passphrase, stdin=subprocess.PIPE)
    ok, problem = False, "chiffrement interrompu"
    try:
        with tarfile.open(fileobj=proc.stdin, mode="w|gz") as tar:
            tar.add(data_dir, arcname=data_dir.name)
        proc.stdin.close()
        ok = proc.wait() == 0 and out.exists()
        problem = "gpg a échoué"
    except (OSError, tarfile.TarError):
        pass
    detail = _reap(proc)
    if not ok:
        out.unlink(missing_ok=True)
        raise _fail(problem, detail)
    out.chmod(0o600)
    return out


def _open_decrypted(archive: Path, passphrase: str) -> subprocess.Popen:
    return _spawn([_gpg(), "--batch", "--quiet", "--decrypt", "--pinentry-mode", "loopback", str(archive)],
                  passphrase, stdout=subprocess.PIPE)


def verify(archive: Path, passphrase: str) -> int:
    """Déchiffre en flux et parcourt toute l'archive : nombre de fichiers, ou SealError."""
    proc = _open_decrypted(archive, passphrase)
    count, ok = 0, False
    try:
        with tarfile.open(fileobj=proc.stdout, mode="r|gz") as tar:
            count = sum(1 for m in tar if m.isfile())
        while proc.stdout.read(1 << 16):
            pass
        ok = proc.wait() == 0
    except (tarfile.TarError, EOFError, OSError):
        pass
    detail = _reap(proc)
    if not ok:
        raise _fail(WRONG, detail)
    return count


def unseal(archive: Path, dest: Path, passphrase: str) -> Path:
    if not archive.is_file():
        raise SealError(f"{archive} introuvable")
    dest.mkdir(parents=True, exist_ok=True)
    proc = _open_decrypted(archive, passphrase)
    ok, clash = False, None
    try:
        with tarfile.open(fileobj=proc.stdout, mode="r|gz") as tar:
            first = True
            for m in tar:
                if first:  # refus d'écraser : vérifié AVANT d'extraire quoi que ce soit
                    first = False
                    if (dest / m.name.split("/")[0]).exists():
                        clash = dest / m.name.split("/")[0]
                        break
                try:
                    tar.extract(m, dest, filter="data")
                except TypeError:  # Python < 3.11.4
                    tar.extract(m, dest)
        ok = clash is None and proc.wait() == 0
    except (tarfile.TarError, EOFError, OSError):
        pass
    detail = _reap(proc)
    if clash:
        raise SealError(f"{clash} existe déjà (refus d'écraser) : choisissez un autre dossier avec --to")
    if not ok:
        raise _fail(WRONG, detail)
    return dest

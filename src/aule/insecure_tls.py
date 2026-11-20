"""Désactivation EXPLICITE de la vérification TLS (`critiq.verify_tls: false`, l'équivalent de `curl --insecure` / `verify=False`).

Ce module n'est importé que dans ce cas précis, et seulement pour le fournisseur `custom` : llm.py ne contient aucun contournement, et le
fournisseur LibreChat reste strict. Sans vérification, l'identité du serveur n'est pas contrôlée : la clé d'API et le code audité peuvent être interceptés."""
import ssl


def unverified_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

#!/usr/bin/env python3
"""
detect_secrets pre-commit hook (re-escrito)

Objetivo: detectar claves y secretos que no deben ir en el código fuente, con foco en
.NET, React y Go. Funciona como hook de pre-commit leyendo los archivos staged desde
el índice de Git (no desde disco) para evitar falsos negativos.

Uso (pre-commit lo maneja):
  - Sin argumentos: inspecciona archivos staged (ACMR) en Git.
  - Con lista de archivos como argumentos: inspecciona esos archivos desde disco.

Salida: lista de hallazgos con nombre de archivo y línea, contenido enmascarado.
Devuelve código 1 si hay hallazgos, 0 si no hay.
"""

import argparse
import base64
import os
import re
import subprocess
import sys
from typing import Iterable, List, Optional, Sequence, Tuple


# Extensiones y nombres relevantes para .NET, React y Go
INCLUDE_EXTS = {
    ".cs", ".csproj", ".props", ".targets",
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".json", ".yml", ".yaml", ".toml", ".ini", ".xml",
    ".go", ".env", ".env.local", ".env.production", ".env.development",
}

INCLUDE_FILENAMES = {
    "appsettings.json",
    "appsettings.Development.json",
    "appsettings.Production.json",
    "secrets.json",
    "package.json",
    "vite.config.ts",
    "vite.config.js",
}

# Rutas a excluir comunes
EXCLUDED_DIR_PARTS = {
    "node_modules", "dist", "build", "out", "bin", "obj", ".git"
}

# Líneas que parecen ser sólo comentario en los lenguajes objetivo
COMMENT_LINE = re.compile(r"^\s*(//|/\*|\*|#|;|--|'|\\s*\*\s)\s*")


def _c(name: str, pattern: str, flags: int = 0) -> Tuple[str, re.Pattern]:
    return name, re.compile(pattern, flags)


# Conjunto curado de patrones relevantes
PATTERNS: Sequence[Tuple[str, re.Pattern]] = (
    # Claves genéricas en asignaciones o JSON
    _c("generic_api_key",
       r"(?i)\b(api[_-]?key|auth[_-]?key|x-api-key|access[_-]?key|client[_-]?secret|client[_-]?id|token|secret|password)\b\s*(=|:)?\s*[\"']?[A-Za-z0-9_\-]{6,}[\"']?"),

    # AWS
    _c("aws_access_key_id", r"\bAKIA[0-9A-Z]{16}\b"),
    _c("aws_secret_access_key", r"(?i)aws_secret_access_key\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{40}[\"']?"),

    # GCP / Google API
    _c("google_api_key", r"\bAIza[0-9A-Za-z\-_]{35}\b"),

    # GitHub tokens
    _c("github_token", r"\bgh[pous]_[A-Za-z0-9]{36,}\b"),

    # GitLab personal access token
    _c("gitlab_token", r"\bglpat-[A-Za-z0-9\-_]{20,}\b"),

    # Slack tokens
    _c("slack_token", r"\bxox[baprs]-[A-Za-z0-9]{10,48}\b"),

    # Stripe secret keys
    _c("stripe_secret", r"\bsk_live_[A-Za-z0-9]{24}\b"),

    # SendGrid
    _c("sendgrid_key", r"\bSG\.[A-Za-z0-9\._-]{22}\.[A-Za-z0-9\._-]{43}\b"),

    # JWT (larga base64url con puntos)
    _c("jwt", r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),

    # Claves privadas
    _c("private_key_block", r"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |DSA |EC )?PRIVATE KEY-----"),

    # Cadenas de conexión comunes (.NET, Go, etc.)
    _c("connection_string_uri", r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|mssql|sqlserver|jdbc:(?:mysql|postgresql|sqlserver))://[^\s'\"]+:[^\s'\"]+@"),
    _c("connection_string_kv", r"(?i)\bServer=[^;]+;Database=[^;]+;(?:User(?:\s*Id)?|Uid)=[^;]+;(?:Password|Pwd)=[^;]+;"),
    _c("connection_string_json", r"(?i)\b(ConnectionStrings|ConnectionString|DataSource)\b\s*[:=]\s*[\"'][^\"']*password=[^\"']*[\"']"),

    # Firebase
    _c("firebase_key", r"\bAAAA[A-Za-z0-9_\-]{7,}:[A-Za-z0-9_\-]{140,}\b"),
)


def is_binary(data: bytes) -> bool:
    if not data:
        return False
    text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)))
    return bool(data.translate(None, text_chars))


def mask(s: str, keep: int = 2) -> str:
    s = s.strip()
    if len(s) <= keep * 2:
        return "*" * len(s)
    return f"{s[:keep]}***{s[-keep:]}"


def _should_include(path: str) -> bool:
    base = os.path.basename(path)
    if any(part in EXCLUDED_DIR_PARTS for part in path.replace("\\", "/").split("/")):
        return False
    if base in INCLUDE_FILENAMES:
        return True
    _, ext = os.path.splitext(base)
    if ext.lower() in INCLUDE_EXTS:
        return True
    # Permitir archivos sin extensión que parezcan .env
    if base.startswith(".env"):
        return True
    return False


def _git_staged_files() -> List[str]:
    res = subprocess.run(
        [
            "git",
            "diff",
            "--cached",
            "--name-only",
            "--diff-filter=ACMR",
            "-z",
        ],
        capture_output=True,
        check=False,
    )
    out = res.stdout
    if not out:
        return []
    parts = out.split(b"\x00")
    files = [p.decode("utf-8", "ignore") for p in parts if p]
    return [f for f in files if _should_include(f)]


def _git_show_index(path: str) -> Optional[bytes]:
    # Leer contenido staged desde el índice
    res = subprocess.run(["git", "show", f":{path}"], capture_output=True, check=False)
    if res.returncode != 0:
        return None
    return res.stdout


def _read_disk(path: str) -> Optional[bytes]:
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError:
        return None


def _decode(content: bytes) -> Optional[str]:
    if is_binary(content):
        return None
    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return content.decode(enc)
        except UnicodeDecodeError:
            continue
    return None


def _iter_matches(line: str) -> Iterable[Tuple[str, str]]:
    for name, rx in PATTERNS:
        for m in rx.finditer(line):
            val = m.group(0)
            # Evitar puramente comentarios
            if COMMENT_LINE.match(line):
                continue
            yield name, val


def scan_text(text: str) -> List[Tuple[int, str, str]]:
    findings: List[Tuple[int, str, str]] = []
    for i, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        for name, value in _iter_matches(line):
            findings.append((i, name, value))
    return findings


def scan_file_from_index(path: str) -> List[Tuple[int, str, str]]:
    data = _git_show_index(path)
    if data is None:
        return []
    text = _decode(data)
    if text is None:
        return []
    return scan_text(text)


def scan_file_from_disk(path: str) -> List[Tuple[int, str, str]]:
    data = _read_disk(path)
    if data is None:
        return []
    text = _decode(data)
    if text is None:
        return []
    return scan_text(text)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Detecta secretos en archivos.")
    parser.add_argument("files", nargs="*", help="Archivos a analizar (lee de disco). Si se omite, se usa el índice de Git.")
    args = parser.parse_args(argv)

    findings_total: List[Tuple[str, int, str, str]] = []  # (file, line, name, value)

    if args.files:
        for f in args.files:
            if not _should_include(f):
                continue
            for line, name, value in scan_file_from_disk(f):
                findings_total.append((f, line, name, value))
    else:
        for f in _git_staged_files():
            for line, name, value in scan_file_from_index(f):
                findings_total.append((f, line, name, value))

    if findings_total:
        print("Se detectaron posibles secretos expuestos:")
        for file, line, name, value in findings_total:
            masked = mask(value, keep=3)
            print(f"  - {file}:{line} [{name}] => {masked}")
        print("\nBloqueando el commit. Revise y elimine/oculte estos valores.")
        return 1

    print("No se detectaron credenciales expuestas.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
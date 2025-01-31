#!/usr/bin/env python3
import sys
import re
import subprocess

# Patrones de expresiones regulares para detectar información sensible
SENSITIVE_PATTERNS = [
    r'client_?id(=|:|\s+)(["\'])?\w+(["\'])?',  # client_id, client-id, clientId
    r'client_?secret(=|:|\s+)(["\'])?\w+(["\'])?',
    r'api_?key(=|:|\s+)(["\'])?\w+(["\'])?',
    r'token(=|:|\s+)(["\'])?\w+(["\'])?',
    r'password(=|:|\s+)(["\'])?\w+(["\'])?',
    r'secret(=|:|\s+)(["\'])?\w+(["\'])?',
    r'(?i)aws_access_key_id(=|:|\s+)(["\'])?AKIA[0-9A-Z]{16}(["\'])?',
    r'(?i)aws_secret_access_key(=|:|\s+)(["\'])?\w{40}(["\'])?',
    r'postgres(ql)?://\w+:\w+@',  # URLs con usuario y contraseña
]

# Archivos o directorios a excluir (ej: .env, configs permitidas)
EXCLUDED_PATHS = [
    '*.env',
    'config/local.yaml'
]

def get_staged_files():
    """Obtiene la lista de archivos en staging."""
    result = subprocess.run(
        ['git', 'diff', '--cached', '--name-only'],
        capture_output=True,
        text=True
    )
    return result.stdout.splitlines()

def is_excluded(file_path):
    """Verifica si el archivo está en la lista de excluidos."""
    from fnmatch import fnmatch
    return any(fnmatch(file_path, pattern) for pattern in EXCLUDED_PATHS)

def scan_file(file_path):
    """Escanea un archivo en busca de patrones sensibles."""
    try:
        with open(file_path, 'r') as f:
            content = f.read()
    except UnicodeDecodeError:
        return []  # Saltar archivos binarios
    
    findings = []
    for pattern in SENSITIVE_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            findings.append(pattern)
    return findings

def main():
    staged_files = get_staged_files()
    has_errors = False

    for file_path in staged_files:
        if is_excluded(file_path):
            continue

        findings = scan_file(file_path)
        if findings:
            print(f"Error: Archivo '{file_path}' contiene patrones sensibles:")
            for pattern in findings:
                print(f"  - Patrón detectado: {pattern}")
            has_errors = True

    if has_errors:
        sys.exit(1)
    else:
        print("No se detectaron credenciales expuestas.")
        sys.exit(0)

if __name__ == "__main__":
    main()
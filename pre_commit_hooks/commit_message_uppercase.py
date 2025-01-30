#!/usr/bin/env python3
import sys

def check_commit_message(commit_msg_file):
    """Verifica si el mensaje de commit comienza con mayúscula."""
    with open(commit_msg_file, "r", encoding="utf-8") as f:
        first_line = f.readline().strip()

    if not first_line:
        print("❌ Error: El mensaje de commit está vacío.")
        return 1  # Retorna error si el mensaje está vacío.

    if not first_line[0].isupper():
        print(f"❌ Error: El mensaje de commit debe comenzar con mayúscula. 📝 '{first_line}'")
        return 1  # Retorna error si no empieza con mayúscula.

    print("✅ Commit message válido.")
    return 0  # Éxito

if __name__ == "__main__":
    commit_msg_file = sys.argv[1]  # El archivo con el mensaje del commit
    sys.exit(check_commit_message(commit_msg_file))

import subprocess
import sys

# def get_commit_message():
#     """Obtiene el mensaje del último commit."""
#     try:
#         result = subprocess.run(
#             ["git", "log", "-1", "--pretty=%B"],
#             capture_output=True,
#             text=True,
#             check=True
#         )
#         return result.stdout.strip()
#     except subprocess.CalledProcessError:
#         print("Error al obtener el mensaje de commit.")
#         sys.exit(1)

import sys

def main():
    commit_msg_file = sys.argv[1]
    
    with open(commit_msg_file, "r", encoding="utf-8") as f:
        commit_msg = f.readline().strip()

    print(f"{commit_msg_file} --> commit_msg_file")
    print(f"{commit_msg} --> mensaje")
    if not commit_msg or not commit_msg[0].isupper():
        print("El mensaje de commit debe empezar con una letra mayuscula.")
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())


# import sys

# def check_commit_message(commit_msg_file):
#     """Verifica si el mensaje de commit comienza con mayúscula."""
#     with open(commit_msg_file, "r", encoding="utf-8") as f:
#         first_line = f.readline().strip()

#     if not first_line:
#         print("❌ Error: El mensaje de commit está vacío.")
#         return 1  # Retorna error si el mensaje está vacío.

#     if not first_line[0].isupper():
#         print(f"❌ Error: El mensaje de commit debe comenzar con mayúscula. 📝 '{first_line}'")
#         return 1  # Retorna error si no empieza con mayúscula.

#     print("✅ Commit message válido.")
#     return 0  # Éxito

# if __name__ == "__main__":
#     commit_msg_file = sys.argv[1]  # El archivo con el mensaje del commit
#     sys.exit(check_commit_message(commit_msg_file))

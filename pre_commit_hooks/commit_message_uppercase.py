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
def get_commit_message():
    """Obtiene el mensaje del commit actual."""
    try:
        # Verifica si existe HEAD (para saber si hay commits previos)
        subprocess.run(["git", "rev-parse", "--verify", "HEAD"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        # Si HEAD existe, obtenemos el mensaje del commit actual
        result = subprocess.run(
            ["git", "show", "-s", "--format=%B", "HEAD"],
            capture_output=True,
            text=True,
            check=True
        )
    except subprocess.CalledProcessError:
        # Si no existe HEAD (primer commit), obtenemos el mensaje en preparación
        result = subprocess.run(
            ["git", "var", "GIT_COMMITTER_EMAIL"],  # Comprobamos si estamos en un entorno git
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print("❌ No se pudo obtener el mensaje de commit.")
            sys.exit(1)
        
        print("ℹ️ Primer commit detectado. Validando mensaje...")
        result = subprocess.run(
            ["git", "commit", "--verbose"],
            capture_output=True,
            text=True,
        )

    return result.stdout.strip()

def main():
    commit_msg = get_commit_message()
    print(f"{commit_msg} -- commit_msg")
    if not commit_msg or not commit_msg[0].isupper():
        print("El mensaje de commit debe empezar con una letra mayúscula.")
        print("Usa `git commit --amend` para corregir el mensaje.")
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()


# import sys

# def main():
#     commit_msg_file = sys.argv[1]
    
#     with open(commit_msg_file, "r", encoding="utf-8") as f:
#         commit_msg = f.readline().strip()

#     print(f"{commit_msg_file} --> commit_msg_file")
#     print(f"{commit_msg} --> mensaje")
#     if not commit_msg or not commit_msg[0].isupper():
#         print("El mensaje de commit debe empezar con una letra mayuscula.")
#         return 1

#     return 0

# if __name__ == "__main__":
#     sys.exit(main())





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

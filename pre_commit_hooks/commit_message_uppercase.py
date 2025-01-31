import sys

def main():
    """
    Valida que el mensaje inicie con una letra mayuscula
    """
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

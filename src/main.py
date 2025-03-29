import termcolor
import os
from datetime import datetime

from helpers import generateKeys, encrypt, decrypt, clear
from constants import KEYS_DIR, MESSAGES_DIR

def main() -> None:
    while True:
        print("What would you like to do? (Generate Keys, Encrypt, Decrypt, or Exit)")
        print("1. Generate Keys")
        print("2. Encrypt")
        print("3. Decrypt")
        print("4. Exit")

        option: str = input("> ")

        match option.strip():
            case "1":
                clear()
                user1: str = input("Enter the first user's name: ")
                user2: str = input("Enter the second user's name: ")
                clear()
                generateKeys(user1, user2)
                print(termcolor.colored("Keys generated successfully\n", "green"))

            case "2":
                clear()
                print("Enter the key you want to use to encrypt a message: ")

                keyFiles: dict[int, str] = {index: file for index, file in enumerate(os.listdir(KEYS_DIR))}
                for fileIndex, fileName in keyFiles.items():
                    print(f"{fileIndex}. {fileName}")
                choice: str = input("> ")

                try:
                    intChoice: int = int(choice)
                    if intChoice not in keyFiles:
                        clear()
                        print(termcolor.colored("Invalid choice\n", "red"))
                        continue
                except ValueError:
                    clear()
                    print(termcolor.colored("Invalid choice\n", "red"))
                    continue

                keyFilename: str = keyFiles[intChoice]
                keyFilePath: str = f"{KEYS_DIR}/{keyFilename}"

                message: str = input("Enter the message you want to encrypt: ")

                encryptedMessage: bytes = encrypt(keyFilePath, message)
                encryptedMessageFilePath: str = f"{MESSAGES_DIR}/encrypted_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.bin"

                with open(encryptedMessageFilePath, "wb") as f:
                    f.write(encryptedMessage)

                clear()
                print(termcolor.colored("Message encrypted successfully\n", "green"))

            case "3":
                clear()
                print("Enter the key you want to use to decrypt a message: ")

                keyFiles = {index: file for index, file in enumerate(os.listdir(KEYS_DIR))}
                for fileIndex, fileName in keyFiles.items():
                    print(f"{fileIndex}. {fileName}")
                choice = input("> ")

                try:
                    intChoice = int(choice)
                    if intChoice not in keyFiles:
                        clear()
                        print(termcolor.colored("Invalid choice\n", "red"))
                        continue
                except ValueError:
                    clear()
                    print(termcolor.colored("Invalid choice\n", "red"))
                    continue

                keyFilename = keyFiles[intChoice]
                keyFilePath = f"{KEYS_DIR}/{keyFilename}"

                clear()
                print("Enter the encrypted message you want to decrypt: ")
                encryptedMessages: dict[int, str] = {index: file for index, file in enumerate(os.listdir(MESSAGES_DIR)) if file.startswith("encrypted_")}
                for fileIndex, fileName in encryptedMessages.items():
                    print(f"{fileIndex}. {fileName}")
                choice = input("> ")

                try:
                    intChoice = int(choice)
                    if intChoice not in encryptedMessages:
                        clear()
                        print(termcolor.colored("Invalid choice\n", "red"))
                        continue
                except ValueError:
                    clear()
                    print(termcolor.colored("Invalid choice\n", "red"))
                    continue

                encryptedMessageFilePath = f"{MESSAGES_DIR}/{encryptedMessages[intChoice]}"

                with open(encryptedMessageFilePath, "rb") as f:
                    encryptedMessage = f.read()

                decryptedMessage: str = decrypt(keyFilePath, encryptedMessage)

                with open(f'{encryptedMessageFilePath.replace("encrypted_", "decrypted_").replace(".bin", ".txt")}', "w") as f:
                    f.write(decryptedMessage)

                clear()
                print(termcolor.colored("Message decrypted successfully\n", "green"))

            case "4":
                exit(0)
            case "clear":
                clear()
            case _:
                print(termcolor.colored("\nInvalid option\n", "red"))

if __name__ == "__main__":
    main()

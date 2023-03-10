import hashlib
from Crypto.Cipher import AES
import getpass


def encrypt(text, password):
    key = hashlib.sha256(password.encode()).digest()
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())
    return (nonce + ciphertext + tag)


def decrypt(ciphertext, password):
    key = hashlib.sha256(password.encode()).digest()
    nonce = ciphertext[:16]
    tag = ciphertext[-16:]
    ciphertext = ciphertext[16:-16]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()


def main():
    choice = input("Do you want to encrypt (e) or decrypt (d) the text? ")
    print(choice)
    if choice == 'e':
        text = input("Enter the text: ")
    password = getpass.getpass("Enter your password: ")

    if choice == 'e':
        description = input("Enter the description: ")
        encrypted_text = encrypt(text, password)
        encrypted_text_hex = encrypted_text.hex()
        print(f"Encrypted text: {description}: {encrypted_text_hex}")
        with open("data.txt", "a") as f:
            f.write(f"{description}: {encrypted_text_hex}\n")
    elif choice == 'd':
        encrypted_text_hex = input(
            "Enter the encrypted text in hexadecimal format: ")
        encrypted_text = bytes.fromhex(encrypted_text_hex)
        decrypted_text = decrypt(encrypted_text, password)
        print(f"Decrypted text: {decrypted_text}")
    else:
        print("Invalid choice. Please enter 'e' to encrypt or 'd' to decrypt.")


if __name__ == '__main__':
    main()

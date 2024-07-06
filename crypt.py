#!/usr/bin/env python3
import os
import base64
import getpass
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hmac import HMAC
from typing import Tuple

class AdvancedEncryptionTool:
    def __init__(self):
        self.backend = default_backend()

    def generate_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(password.encode())

    def encrypt(self, plaintext: str, password: str) -> Tuple[bytes, bytes, bytes, bytes]:
        salt = os.urandom(16)
        key = self.generate_key(password, salt)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        padded_data = self._pad(plaintext.encode())
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        h = HMAC(key, hashes.SHA256(), backend=self.backend)
        h.update(salt + iv + ciphertext)
        hmac_value = h.finalize()

        return ciphertext, iv, salt, hmac_value

    def decrypt(self, ciphertext: bytes, iv: bytes, salt: bytes, hmac_value: bytes, password: str) -> str:
        key = self.generate_key(password, salt)
        h = HMAC(key, hashes.SHA256(), backend=self.backend)
        h.update(salt + iv + ciphertext)
        h.verify(hmac_value)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = self._unpad(padded_plaintext)
        return plaintext.decode()

    def _pad(self, data: bytes) -> bytes:
        padding_length = 16 - (len(data) % 16)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def _unpad(self, padded_data: bytes) -> bytes:
        padding_length = padded_data[-1]
        return padded_data[:-padding_length]

    def encrypt_file(self, file_path: str, password: str) -> str:
        with open(file_path, 'rb') as file:
            plaintext = file.read()
        ciphertext, iv, salt, hmac_value = self.encrypt(plaintext.decode(), password)
        encrypted_file_path = file_path + '.enc'
        with open(encrypted_file_path, 'wb') as file:
            file.write(salt + iv + hmac_value + ciphertext)
        return encrypted_file_path

    def decrypt_file(self, file_path: str, password: str) -> str:
        with open(file_path, 'rb') as file:
            data = file.read()
        salt, iv, hmac_value, ciphertext = data[:16], data[16:32], data[32:64], data[64:]
        plaintext = self.decrypt(ciphertext, iv, salt, hmac_value, password)
        decrypted_file_path = file_path[:-4]  # Remove '.enc'
        with open(decrypted_file_path, 'wb') as file:
            file.write(plaintext.encode())
        return decrypted_file_path

def get_password() -> str:
    while True:
        password = getpass.getpass("Enter password: ")
        if len(password) < 8:
            print("Password must be at least 8 characters long. Please try again.")
            continue
        password_confirm = getpass.getpass("Confirm password: ")
        if password == password_confirm:
            return password
        print("Passwords do not match. Please try again.")

def main():
    tool = AdvancedEncryptionTool()

    while True:
        print("\nAdvanced Encryption Tool")
        print("1. Encrypt text")
        print("2. Decrypt text")
        print("3. Encrypt file")
        print("4. Decrypt file")
        print("5. Exit")

        choice = input("Enter your choice (1-5): ")

        if choice == '1':
            plaintext = input("Enter text to encrypt: ")
            password = get_password()
            ciphertext, iv, salt, hmac_value = tool.encrypt(plaintext, password)
            print("Encrypted text (base64):")
            print(base64.b64encode(salt + iv + hmac_value + ciphertext).decode())

        elif choice == '2':
            encrypted_data = input("Enter encrypted text (base64): ")
            password = getpass.getpass("Enter password: ")
            try:
                data = base64.b64decode(encrypted_data)
                salt, iv, hmac_value, ciphertext = data[:16], data[16:32], data[32:64], data[64:]
                plaintext = tool.decrypt(ciphertext, iv, salt, hmac_value, password)
                print("Decrypted text:", plaintext)
            except Exception as e:
                print("Decryption failed:", str(e))

        elif choice == '3':
            file_path = input("Enter file path to encrypt: ")
            password = get_password()
            try:
                encrypted_file = tool.encrypt_file(file_path, password)
                print(f"File encrypted successfully. Encrypted file: {encrypted_file}")
            except Exception as e:
                print("Encryption failed:", str(e))

        elif choice == '4':
            file_path = input("Enter file path to decrypt: ")
            password = getpass.getpass("Enter password: ")
            try:
                decrypted_file = tool.decrypt_file(file_path, password)
                print(f"File decrypted successfully. Decrypted file: {decrypted_file}")
            except Exception as e:
                print("Decryption failed:", str(e))

        elif choice == '5':
            print("Exiting the program. Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()

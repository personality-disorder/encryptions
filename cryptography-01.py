#!/usr/bin/env python3
import os
import base64
import getpass
import logging
import concurrent.futures
from typing import Tuple
from tqdm import tqdm
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AdvEncTool:
    def __init__(self, algorithm='AES'):
        self.bknd = default_backend()
        self.algorithm = algorithm

    def gen_k(self, pwd: str, slt: bytes, length: int = 32) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=slt,
            iterations=100000,
            backend=self.bknd
        )
        return kdf.derive(pwd.encode())

    def get_cipher(self, key):
        if self.algorithm == 'AES':
            return aead.AESGCM(key)
        elif self.algorithm == 'ChaCha20':
            return aead.ChaCha20Poly1305(key)
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")

    def process_chunk(self, chunk, key, nonce, mode='encrypt'):
        cipher = self.get_cipher(key)
        if mode == 'encrypt':
            return cipher.encrypt(nonce, chunk, None)
        else:
            return cipher.decrypt(nonce, chunk, None)

    def enc(self, pltxt: str, pwd: str) -> Tuple[bytes, bytes, bytes]:
        slt = os.urandom(16)
        key = self.gen_k(pwd, slt, 32)
        nonce = os.urandom(12)
        cipher = self.get_cipher(key)
        ciphertxt = cipher.encrypt(nonce, pltxt.encode(), None)
        return ciphertxt, nonce, slt

    def dec(self, ciphertxt: bytes, nonce: bytes, slt: bytes, pwd: str) -> str:
        key = self.gen_k(pwd, slt, 32)
        cipher = self.get_cipher(key)
        pltxt = cipher.decrypt(nonce, ciphertxt, None)
        return pltxt.decode()

    def enc_file(self, fpath: str, pwd: str, chunk_size: int = 64 * 1024) -> str:
        slt = os.urandom(16)
        key = self.gen_k(pwd, slt, 32)
        initial_nonce = os.urandom(12)
        enc_fpath = fpath + '.enc'
        
        with open(fpath, 'rb') as in_file, open(enc_fpath, 'wb') as out_file:
            out_file.write(slt + initial_nonce)
            file_size = os.path.getsize(fpath)
            with tqdm(total=file_size, unit='B', unit_scale=True, desc="Encrypting") as pbar:
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    futures = []
                    nonce = initial_nonce
                    while True:
                        chunk = in_file.read(chunk_size)
                        if not chunk:
                            break
                        future = executor.submit(self.process_chunk, chunk, key, nonce, mode='encrypt')
                        futures.append(future)
                        nonce = (int.from_bytes(nonce, 'big') + 1).to_bytes(12, 'big')
                    
                    for future in concurrent.futures.as_completed(futures):
                        encrypted_chunk = future.result()
                        out_file.write(encrypted_chunk)
                        pbar.update(len(chunk))
        
        return enc_fpath

    def dec_file(self, fpath: str, pwd: str, chunk_size: int = 64 * 1024) -> str:
        with open(fpath, 'rb') as in_file:
            slt = in_file.read(16)
            initial_nonce = in_file.read(12)
            key = self.gen_k(pwd, slt, 32)
            dec_fpath = fpath[:-4]  # Удаляем '.enc'
            
            with open(dec_fpath, 'wb') as out_file:
                file_size = os.path.getsize(fpath) - 28  # Вычитаем размер соли и начального nonce
                with tqdm(total=file_size, unit='B', unit_scale=True, desc="Decrypting") as pbar:
                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        futures = []
                        nonce = initial_nonce
                        while True:
                            chunk = in_file.read(chunk_size + 16)  # 16 bytes for auth tag
                            if not chunk:
                                break
                            future = executor.submit(self.process_chunk, chunk, key, nonce, mode='decrypt')
                            futures.append(future)
                            nonce = (int.from_bytes(nonce, 'big') + 1).to_bytes(12, 'big')
                        
                        for future in concurrent.futures.as_completed(futures):
                            try:
                                decrypted_chunk = future.result()
                                out_file.write(decrypted_chunk)
                                pbar.update(len(chunk) - 16)  # Вычитаем размер auth tag
                            except InvalidTag:
                                logger.error("Decryption failed: Invalid password or corrupted data")
                                os.remove(dec_fpath)  # Удаляем частично расшифрованный файл
                                raise
        
        return dec_fpath

def get_pwd() -> str:
    while True:
        pwd = getpass.getpass("Enter password: ")
        if len(pwd) < 12:
            print("Password must be at least 12 characters long. Please try again.")
            continue
        pwd_conf = getpass.getpass("Confirm password: ")
        if pwd == pwd_conf:
            return pwd
        print("Passwords do not match. Please try again.")

def main():
    tool = AdvEncTool()

    while True:
        print("\nAdvanced Encryption Tool")
        print("1. Encrypt text")
        print("2. Decrypt text")
        print("3. Encrypt file")
        print("4. Decrypt file")
        print("5. Change encryption algorithm")
        print("6. Exit")

        ch = input("Enter your choice (1-6): ")

        if ch == '1':
            pltxt = input("Enter text to encrypt: ")
            pwd = get_pwd()
            ciphertxt, nonce, slt = tool.enc(pltxt, pwd)
            print("Encrypted text (base64):")
            print(base64.b64encode(slt + nonce + ciphertxt).decode())

        elif ch == '2':
            enc_data = input("Enter encrypted text (base64): ")
            pwd = getpass.getpass("Enter password: ")
            try:
                dt = base64.b64decode(enc_data)
                slt, nonce, ciphertxt = dt[:16], dt[16:28], dt[28:]
                pltxt = tool.dec(ciphertxt, nonce, slt, pwd)
                print("Decrypted text:", pltxt)
            except Exception as e:
                logger.error(f"Decryption failed: {str(e)}")

        elif ch == '3':
            fpath = input("Enter file path to encrypt: ")
            pwd = get_pwd()
            try:
                enc_file = tool.enc_file(fpath, pwd)
                print(f"File encrypted successfully. Encrypted file: {enc_file}")
            except Exception as e:
                logger.error(f"Encryption failed: {str(e)}")

        elif ch == '4':
            fpath = input("Enter file path to decrypt: ")
            pwd = getpass.getpass("Enter password: ")
            try:
                dec_file = tool.dec_file(fpath, pwd)
                print(f"File decrypted successfully. Decrypted file: {dec_file}")
            except Exception as e:
                logger.error(f"Decryption failed: {str(e)}")

        elif ch == '5':
            print("Available algorithms: AES, ChaCha20")
            new_algo = input("Enter the algorithm you want to use: ")
            if new_algo in ['AES', 'ChaCha20']:
                tool.algorithm = new_algo
                print(f"Algorithm changed to {new_algo}")
            else:
                print("Invalid algorithm. Keeping the current one.")

        elif ch == '6':
            print("Exiting the program. Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()

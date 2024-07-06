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

class AdvEncTool:
    def __init__(self):
        self.bknd = default_backend()

    def gen_k(self, pwd: str, slt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=slt,
            iterations=100000,
            backend=self.bknd
        )
        return kdf.derive(pwd.encode())

    def enc(self, pltxt: str, pwd: str) -> Tuple[bytes, bytes, bytes, bytes]:
        slt = os.urandom(16)
        key = self.gen_k(pwd, slt)
        iv = os.urandom(16)
        cphr = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.bknd)
        enctr = cphr.encryptor()
        pd_dt = self._pd(pltxt.encode())
        ciphertxt = enctr.update(pd_dt) + enctr.finalize()

        h = HMAC(key, hashes.SHA256(), backend=self.bknd)
        h.update(slt + iv + ciphertxt)
        hmac_val = h.finalize()

        return ciphertxt, iv, slt, hmac_val

    def dec(self, ciphertxt: bytes, iv: bytes, slt: bytes, hmac_val: bytes, pwd: str) -> str:
        key = self.gen_k(pwd, slt)
        h = HMAC(key, hashes.SHA256(), backend=self.bknd)
        h.update(slt + iv + ciphertxt)
        h.verify(hmac_val)

        cphr = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.bknd)
        dectr = cphr.decryptor()
        pd_plt = dectr.update(ciphertxt) + dectr.finalize()
        pltxt = self._unp(pd_plt)
        return pltxt.decode()

    def _pd(self, dt: bytes) -> bytes:
        pd_len = 16 - (len(dt) % 16)
        pd = bytes([pd_len] * pd_len)
        return dt + pd

    def _unp(self, pd_dt: bytes) -> bytes:
        pd_len = pd_dt[-1]
        return pd_dt[:-pd_len]

    def enc_file(self, fpath: str, pwd: str) -> str:
        with open(fpath, 'rb') as f:
            pltxt = f.read()
        ciphertxt, iv, slt, hmac_val = self.enc(pltxt.decode(), pwd)
        enc_fpath = fpath + '.enc'
        with open(enc_fpath, 'wb') as f:
            f.write(slt + iv + hmac_val + ciphertxt)
        return enc_fpath

    def dec_file(self, fpath: str, pwd: str) -> str:
        with open(fpath, 'rb') as f:
            dt = f.read()
        slt, iv, hmac_val, ciphertxt = dt[:16], dt[16:32], dt[32:64], dt[64:]
        pltxt = self.dec(ciphertxt, iv, slt, hmac_val, pwd)
        dec_fpath = fpath[:-4]  # Удаляем '.enc'
        with open(dec_fpath, 'wb') as f:
            f.write(pltxt.encode())
        return dec_fpath

def get_pwd() -> str:
    while True:
        pwd = getpass.getpass("Enter password: ")
        if len(pwd) < 8:
            print("Password must be at least 8 characters long. Please try again.")
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
        print("5. Exit")

        ch = input("Enter your choice (1-5): ")

        if ch == '1':
            pltxt = input("Enter text to encrypt: ")
            pwd = get_pwd()
            ciphertxt, iv, slt, hmac_val = tool.enc(pltxt, pwd)
            print("Encrypted text (base64):")
            print(base64.b64encode(slt + iv + hmac_val + ciphertxt).decode())

        elif ch == '2':
            enc_data = input("Enter encrypted text (base64): ")
            pwd = getpass.getpass("Enter password: ")
            try:
                dt = base64.b64decode(enc_data)
                slt, iv, hmac_val, ciphertxt = dt[:16], dt[16:32], dt[32:64], dt[64:]
                pltxt = tool.dec(ciphertxt, iv, slt, hmac_val, pwd)
                print("Decrypted text:", pltxt)
            except Exception as e:
                print("Decryption failed:", str(e))

        elif ch == '3':
            fpath = input("Enter file path to encrypt: ")
            pwd = get_pwd()
            try:
                enc_file = tool.enc_file(fpath, pwd)
                print(f"File encrypted successfully. Encrypted file: {enc_file}")
            except Exception as e:
                print("Encryption failed:", str(e))

        elif ch == '4':
            fpath = input("Enter file path to decrypt: ")
            pwd = getpass.getpass("Enter password: ")
            try:
                dec_file = tool.dec_file(fpath, pwd)
                print(f"File decrypted successfully. Decrypted file: {dec_file}")
            except Exception as e:
                print("Decryption failed:", str(e))

        elif ch == '5':
            print("Exiting the program. Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()

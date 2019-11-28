#!/usr/bin/python
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import random

IV = get_random_bytes(16)
key = get_random_bytes(16)

def encrypt(text):
    AES_cipher = AES.new(key, AES.MODE_CBC, IV)
    ciphertext = AES_cipher.encrypt(text)
    return ciphertext

def decrypt(ciphertext):
    AES_cipher = AES.new(key, AES.MODE_CBC, IV)
    plaintext = AES_cipher.decrypt(ciphertext)
    return plaintext

ciphertext = encrypt("hallo hallo hall")
print(ciphertext)

plaintext = decrypt(ciphertext)
print(plaintext)

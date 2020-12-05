from Crypto.Cipher import AES
import Crypto.Util.number
from Crypto import Random

from Cryptodome.Util.Padding import pad, unpad

key_size = 256

def AES_data_Encryption(plaintextPath, key):
    plaintext = open(plaintextPath,'rb').read()
    last_blok = len(plaintext)%AES.block_size
    len1 = len(plaintext)
    if (last_blok!=0):
        plaintext+=b'\x03'*(AES.block_size-last_blok%AES.block_size)
    #plaintext = pad(plaintext,AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted = cipher.encrypt(plaintext)
    return encrypted,  cipher.iv, len1

def AES_data_Decryption(ciphertext, key, iv):
   # iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)#[AES.block_size:])
   # plaintext = unpad(plaintext, AES.block_size)
    return plaintext

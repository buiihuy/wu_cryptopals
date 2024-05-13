from Cryptodome.Cipher import AES
import cryptopals
import requests
import base64

def AES_decrypt(key: bytes, cipher: bytes, mode: str) -> bytes:
    cryptor = AES.new(key, AES.MODE_ECB)
    last_block = b'\x00' * 16
    decrypted = b''
    for i in range(0, len(cipher), 16):
        decrypted += cryptopals.bxor(cryptor.decrypt(cipher[i : i + 16]), last_block)
        if mode == 'cbc':
            last_block = cipher[i : i + 16]
    return decrypted

content = base64.b64decode(requests.get('https://cryptopals.com/static/challenge-data/10.txt').text)
print(AES_decrypt(b'YELLOW SUBMARINE', content, 'cbc'))

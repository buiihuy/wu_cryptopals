from Cryptodome.Cipher import AES
from random import randint
import cryptopals

def AES_encrypt(key: bytes, plain: bytes, mode: str) -> bytes:
    cryptor = AES.new(key, AES.MODE_ECB)
    last_block = b'\x00' * 16
    encrypted = b''
    for i in range(0, len(plain), 16):
        last_block = cryptor.encrypt(cryptopals.bxor(plain[i : i + 16], last_block))
        encrypted += last_block
        if mode == 'ecb':
            last_block = b'\x00' * 16
    return encrypted

def generate_key(length: int = 16) -> bytes:
    return bytes([randint(0, 255) for _ in range(length)])

def encryption_oracle(s: bytes) -> bytes:
    mode = 'ecb' if randint(0, 1) == 0 else 'cbc'
    s = generate_key(randint(5, 10)) + s + generate_key(randint(5, 10))
    s = cryptopals.pkcs7(s, 16)
    return AES_encrypt(generate_key(), s, mode), mode

if __name__ == '__main__':
    for _ in range(100):
        cipher, mode = encryption_oracle(b'a'* (16 * 3))
        if cipher[16:32] == cipher[32:48]:
            if mode != 'ecb':
                print('wrong')
            else:
                print('right')
        else:
            if mode != 'cbc':
                print('wrong')
            else:
                print('right')
